"""Regression tests for safe Greenbone cancellation and transient poll failures."""
from contextlib import contextmanager

import pytest

from agent import gmp_local, main


class FakeGMP:
    def __init__(self, *, stop_error=None):
        self.stop_calls = []
        self.stop_error = stop_error

    def stop_task(self, task_id):
        self.stop_calls.append(task_id)
        if self.stop_error:
            raise self.stop_error


def scanner():
    obj = gmp_local.LocalOpenVAS.__new__(gmp_local.LocalOpenVAS)
    obj.socket_path = "/tmp/mock-gvmd.sock"
    obj.host = "127.0.0.1"
    obj.port = 9390
    obj.username = "admin"
    obj.password = "test"
    obj._terminal_task_ids = set()
    return obj


def attach_gmp(monkeypatch, state="running", *, stop_error=None):
    fake = FakeGMP(stop_error=stop_error)
    sessions = []

    @contextmanager
    def session(**kwargs):
        sessions.append(kwargs)
        yield fake

    monkeypatch.setattr(gmp_local, "_session", session)
    monkeypatch.setattr(gmp_local, "_task_status", lambda *_: (state, 100 if state == "done" else 20, object()))
    return fake, sessions


@pytest.mark.parametrize("status", ["done", "stopped", "failed", "internal error", "stop requested"])
def test_no_stop_call_for_terminal_or_already_stopping(monkeypatch, status):
    obj = scanner()
    fake, sessions = attach_gmp(monkeypatch, status)
    assert obj.stop("task-123") is False
    assert fake.stop_calls == []
    assert len(sessions) == 1
    if status != "stop requested":
        assert "task-123" in obj._terminal_task_ids


def test_stop_only_active_task_once(monkeypatch):
    obj = scanner()
    fake, sessions = attach_gmp(monkeypatch, "running")
    assert obj.stop("task-123") is True
    assert fake.stop_calls == ["task-123"]
    assert sessions[0]["timeout"] == 8.0


def test_cached_terminal_does_not_open_session(monkeypatch):
    obj = scanner()
    obj._terminal_task_ids.add("task-123")
    monkeypatch.setattr(gmp_local, "_session", lambda **_: (_ for _ in ()).throw(AssertionError("should not connect")))
    assert obj.stop("task-123") is False


def test_timeout_is_unconfirmed_not_scan_failure(monkeypatch, caplog):
    obj = scanner()
    fake, _ = attach_gmp(monkeypatch, "running", stop_error=TimeoutError("socket timed out"))
    assert obj.stop("task-123") is False
    assert fake.stop_calls == ["task-123"]
    assert "unconfirmed" in caplog.text
    assert "Traceback" not in caplog.text


def test_task_lookup_failure_does_not_issue_blind_stop(monkeypatch):
    obj = scanner()
    fake, _ = attach_gmp(monkeypatch, "running")
    monkeypatch.setattr(gmp_local, "_task_status", lambda *_: ("unknown", 0, None))
    assert obj.stop("task-123") is False
    assert fake.stop_calls == []


def test_invalid_timeout_falls_back_to_eight_seconds(monkeypatch):
    monkeypatch.setenv("GVM_STOP_TIMEOUT_SEC", "badvalue")
    obj = scanner()
    _, sessions = attach_gmp(monkeypatch, "running")
    assert obj.stop("task-123") is True
    assert sessions[0]["timeout"] == 8


def test_transient_poll_error_does_not_cancel_scan(monkeypatch):
    from agent import reachability
    patches, uploaded, stops = [], [], []
    class Api:
        def patch_job(self, job_id, payload):
            patches.append(payload)
            return {"id": job_id}
        def upload_results(self, job_id, payload):
            uploaded.append(payload)
            return {"status": "completed"}
    class Scanner:
        port_profile = "nexus"
        def __init__(self):
            self.polls = 0
        def start_scan(self, *, name, targets, port_range=None):
            return "task-123"
        def get_task_hosts(self, task_id):
            return ["10.0.0.123"]
        def poll(self, task_id, **kwargs):
            self.polls += 1
            if self.polls == 1:
                raise TimeoutError("temporary GMP read timeout")
            return {"status": "completed", "gmp_status": "Done", "progress": 100,
                    "vulnerabilities": [{"ip": "10.0.0.123", "severity": "medium", "plugin_id": "123"}],
                    "evidence": {"report_id": "report-123", "hosts_attempted": 1,
                                 "hosts_assessed": 1, "assessed_hosts": ["10.0.0.123"],
                                 "assessment_complete": True, "task_status": "Done"}}
        def stop(self, task_id):
            stops.append(task_id)
            raise AssertionError("transient poll timeout must not stop the scan")
    obj = Scanner()
    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    monkeypatch.setattr(main, "should_watch_lan", lambda *a, **kw: False)
    monkeypatch.setattr(main, "probe_laptop_capacity", lambda **kw: {
        "chunk_size": 1, "ip_workers": 1, "configured_ceiling": 1,
        "hot": False, "admission_paused": False})
    monkeypatch.setattr(main, "emit_ip_event", lambda *a, **kw: None)
    monkeypatch.setattr(reachability, "partition_targets", lambda targets, **kw: {
        "reachable": list(targets), "unreachable": [], "skipped_hosts": []})
    monkeypatch.setenv("SKIP_UNREACHABLE_TARGETS", "false")
    monkeypatch.setenv("SCAN_DEGRADED_RETRY", "0")
    main._run_job_body({"api": Api(), "openvas": obj, "poll": 0,
        "max_scan_runtime_sec": 0, "progress_report_interval": 0,
        "high_progress_warn_sec": 300, "high_progress_stall_sec": 0},
        {"id": "00000000-0000-0000-0000-000000000001",
         "targets": [{"target": "10.0.0.123"}]})
    assert obj.polls >= 2
    assert stops == []
    assert uploaded


def test_poll_terminal_status_prevents_later_cleanup_stop(monkeypatch):
    obj = scanner()
    obj.alive_test = "Consider Alive"
    obj.policy_snapshots = {}
    fake, sessions = attach_gmp(monkeypatch, "done")
    monkeypatch.setattr(gmp_local, "_report_payload", lambda *a, **kw: (
        [{"ip": "10.0.0.123", "severity": "medium"}],
        {"report_id": "r-123", "assessment_complete": True,
         "report_result_count_filtered": 1, "scan_start": "now"},
    ))
    details = obj.poll("task-123", expected_targets=["10.0.0.123"])
    assert details["status"] == "completed"
    assert details["vulnerabilities"]
    assert obj.stop("task-123") is False
    assert fake.stop_calls == []
    assert len(sessions) == 2  # status + report only; stop was a cache hit
