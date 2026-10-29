"""V1.9.3 - IP starts in parallel, one clock per IP, and caps for checks with long own timeouts.

Field job 3c4f45e0 (2 IPs, build 1.9.1-v51.0):
* IP .9's start began only after IP .8's 45 s start finished (starts ran on
  the polling thread, one after another);
* MAX_SCAN_RUNTIME_SEC=3600 was ONE clock for the whole job, so .9 was cut at
  whatever .8 left over, and any IP still queued would have got nothing;
* .9 sat at 98 % for 30+ min although the 5 static SSL caps were applied:
  OpenVAS uses a check's own script_timeout before plugins_timeout, so a
  check declaring 30-60 min (or -1, never killed) holds the tail.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from lxml import etree

from agent import gmp_local, main, nvt_timeouts, scan_performance as perf
from agent.scan_performance import NvtHangRegistry
from tests.test_speed_v167 import _done, _loop, _slow_then_stopped

LONG_OID = "1.3.6.1.4.1.25623.1.0.999301"
UNBOUNDED_OID = "1.3.6.1.4.1.25623.1.0.999302"
SHORT_OID = "1.3.6.1.4.1.25623.1.0.999303"
NMAP_LIKE_OID = "1.3.6.1.4.1.25623.1.0.999304"
VARIABLE_OID = "1.3.6.1.4.1.25623.1.0.999305"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for key in ("SCAN_IP_DEADLINE_SEC", "MAX_SCAN_RUNTIME_SEC", "MAX_JOB_RUNTIME_SEC", "SCAN_NVT_MAX_SEC",
                "SCAN_SERVICE_PARALLELISM", "FAST_MAX_CHECKS", "SCAN_IP_WORKERS_FIXED", "SCAN_PERFORMANCE",
                "OPENVAS_LOG_WHOLE_ATTACK", "SCAN_CHECK_SCOPE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))
    monkeypatch.setattr(nvt_timeouts, "_INDEX", None)
    monkeypatch.setenv("OPENVAS_PLUGINS_DIR", str(tmp_path / "no-plugins"))
    monkeypatch.setenv("NVT_TIMEOUT_INDEX_FILE", str(tmp_path / "index.json"))


def _nasl(oid: str, timeout: str | None, name: str = "Some check", family: str = "General") -> str:
    body = [
        "# Copyright (C) 2026 Greenbone AG",
        "if(description)",
        "{",
        f'  script_oid("{oid}");',
        '  script_version("2026-10-01T00:00:00+0000");',
        f'  script_name("{name}");',
        "  script_category(ACT_GATHER_INFO);",
        f'  script_family("{family}");',
    ]
    if timeout is not None:
        body.append(f"  script_timeout({timeout});")
    body += ["  exit(0);", "}", "exit(0);", ""]
    return "\n".join(body)


def _feed(root: Path, plugin_set: str = "202610150600") -> Path:
    (root / "2026" / "sub").mkdir(parents=True, exist_ok=True)
    (root / "plugin_feed_info.inc").write_text(f'PLUGIN_SET = "{plugin_set}";\n')
    (root / "2026" / "long.nasl").write_text(_nasl(LONG_OID, "60*60", "SSL/TLS: Slow cipher walk"))
    (root / "2026" / "sub" / "unbounded.nasl").write_text(_nasl(UNBOUNDED_OID, "-1", "Endless web check"))
    (root / "2026" / "short.nasl").write_text(_nasl(SHORT_OID, "600", "Short enough"))
    (root / "2026" / "nmap.nasl").write_text(_nasl(NMAP_LIKE_OID, "7200", "Nmap (NASL wrapper) copy"))
    (root / "2026" / "variable.nasl").write_text(_nasl(VARIABLE_OID, "my_timeout", "Variable timeout"))
    (root / "2026" / "plain.nasl").write_text(_nasl("1.3.6.1.4.1.25623.1.0.999306", None, "No own timeout"))
    (root / "2026" / "helper.inc").write_text("script_timeout(99999);\n")
    return root


# --- 1. IP starts run in parallel ---------------------------------------------------------------
def _with_start_hook(monkeypatch, hook):
    """Wrap the harness scanner's start_scan with ``hook(kwargs, start)``."""
    orig_run = main._run_job_body

    def run(cfg, job):
        scanner = cfg["openvas"]
        start = scanner.start_scan
        scanner.start_scan = lambda **kwargs: hook(kwargs, start)
        return orig_run(cfg, job)

    monkeypatch.setattr(main, "_run_job_body", run)


def test_ip_starts_run_in_parallel_not_one_after_another(monkeypatch):
    """Both starts must be inside start_scan at the same time, or the barrier breaks."""
    barrier = threading.Barrier(2, timeout=10)
    threads: set[str] = set()

    def hook(kwargs, start):
        barrier.wait()
        threads.add(threading.current_thread().name)
        return start(**kwargs)

    _with_start_hook(monkeypatch, hook)
    poll = lambda host, n, stopped: _done(host) if n >= 2 else {
        "status": "running", "gmp_status": "running", "progress": 50, "vulnerabilities": [], "evidence": {}}
    uploaded, events, stops, state = _loop(monkeypatch, ["10.9.0.1", "10.9.0.2"], poll)
    assert not [e for _, e, _ in events if e == "start_error"], "one start waited for the other"
    assert sorted(state["started"]) == ["task-10.9.0.1", "task-10.9.0.2"]
    assert threads and all(name.startswith("aetheris-start") for name in threads)
    assert uploaded[-1]["status"] == "completed" and stops == []


def test_start_failure_frees_the_slot_for_the_next_ip(monkeypatch):
    hosts = ["10.9.1.1", "10.9.1.2", "10.9.1.3"]

    def hook(kwargs, start):
        if kwargs["targets"][0] == hosts[0]:
            raise RuntimeError("gvmd rejected the target")
        return start(**kwargs)

    _with_start_hook(monkeypatch, hook)
    poll = lambda host, n, stopped: _done(host)
    _, events, _, state = _loop(monkeypatch, hosts, poll, env={"SCAN_IP_WORKERS_FIXED": "1"})
    assert [h for h, e, _ in events if e == "start_error"] == [hosts[0]]
    assert state["started"] == [f"task-{hosts[1]}", f"task-{hosts[2]}"]


# --- 2. one clock per IP --------------------------------------------------------------------------
def test_max_scan_runtime_is_per_ip_now():
    import os

    os.environ["MAX_SCAN_RUNTIME_SEC"] = "3600"
    try:
        assert perf.ip_runtime_limit() == (3600, "MAX_SCAN_RUNTIME_SEC (per IP since V1.9.3)")
        os.environ["SCAN_IP_DEADLINE_SEC"] = "1200"
        assert perf.ip_runtime_limit() == (1200, "SCAN_IP_DEADLINE_SEC")
    finally:
        os.environ.pop("MAX_SCAN_RUNTIME_SEC", None)
        os.environ.pop("SCAN_IP_DEADLINE_SEC", None)
    assert perf.ip_runtime_limit() == (0, "off")
    assert perf.job_runtime_limit_sec() == 0  # the whole-job clock is opt-in only


def _serial_job(monkeypatch, env):
    """3 IPs one after another, each finishing on its 6th poll."""
    poll = lambda host, n, stopped: _done(host) if n >= 6 else {
        "status": "running", "gmp_status": "running", "progress": 15 * n, "vulnerabilities": [], "evidence": {}}
    return _loop(monkeypatch, ["10.9.2.1", "10.9.2.2", "10.9.2.3"], poll,
                 env={"SCAN_IP_WORKERS_FIXED": "1", **env}, step=10.0)


def test_a_multi_ip_job_is_not_cut_by_a_limit_each_ip_fits_in(monkeypatch):
    # Calibrate on the mocked clock: how long does one IP take, and the whole job?
    _, events, _, _ = _serial_job(monkeypatch, {})
    durations = [kw["duration_sec"] for _, e, kw in events if e == "completed"]
    assert len(durations) == 3
    per_ip = max(durations)
    job_total = sum(durations)
    limit = int(per_ip * 1.5) + 1
    assert job_total > limit, "calibration: the whole job must exceed the limit one IP fits in"

    # V1.9.3 semantics: MAX_SCAN_RUNTIME_SEC applies to each IP -> nothing is stopped.
    uploaded, events, stops, _ = _serial_job(monkeypatch, {"MAX_SCAN_RUNTIME_SEC": str(limit)})
    assert stops == [] and not [e for _, e, _ in events if e == "time_limit"]
    assert len([e for _, e, _ in events if e == "completed"]) == 3
    assert uploaded[-1]["status"] == "completed"


def test_whole_job_limit_is_its_own_opt_in_setting(monkeypatch):
    _, events, _, _ = _serial_job(monkeypatch, {})
    per_ip = max(kw["duration_sec"] for _, e, kw in events if e == "completed")
    limit = int(per_ip * 1.5) + 1
    orig_run = main._run_job_body

    def run(cfg, job):
        return orig_run({**cfg, "max_job_runtime_sec": limit}, job)

    monkeypatch.setattr(main, "_run_job_body", run)
    uploaded, events, stops, state = _serial_job(monkeypatch, {})
    assert stops, "MAX_JOB_RUNTIME_SEC must still stop a job that runs past it"
    assert "job runtime" in (uploaded[-1].get("partial_reason") or uploaded[-1].get("error") or "")


def test_slow_ip_is_stopped_at_its_own_limit_and_reported_honestly(monkeypatch):
    host = "192.168.1.9"
    uploaded, events, stops, _ = _loop(monkeypatch, [host], _slow_then_stopped,
                                       env={"SCAN_PERFORMANCE": "fast", "MAX_SCAN_RUNTIME_SEC": "900"})
    assert stops == [f"task-{host}"]
    limit_events = [kw for h, ev, kw in events if ev == "time_limit"]
    assert limit_events and limit_events[0]["limit_sec"] == 900
    cov = uploaded[-1]["host_coverage"][host]
    assert cov["time_limited"] is True and any("time limit" in w for w in cov["warnings"])
    assert any(v.get("result_id") == f"r-{host}" for v in uploaded[-1]["vulnerabilities"])


# --- 3. service-level parallelism: one number ------------------------------------------------------
def test_per_ip_check_concurrency_is_one_number(monkeypatch):
    assert perf.per_ip_check_concurrency("fast") == 6  # V1.10.3 port semaphore 6 > FAST_MAX_CHECKS 5
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "8")
    assert perf.per_ip_check_concurrency("fast") == 8  # could not exceed 4 before V1.9.3
    assert perf.per_ip_check_concurrency("standard") == 8
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "99")
    assert perf.per_ip_check_concurrency("fast") == 32


# --- 4. long own timeouts ---------------------------------------------------------------------------
def test_nasl_timeouts_are_read_without_guessing():
    parse = nvt_timeouts.parse_nasl
    assert parse(_nasl(LONG_OID, "60*60").encode())["timeout"] == 3600
    assert parse(_nasl(UNBOUNDED_OID, "-1").encode())["timeout"] == -1
    assert parse(_nasl(SHORT_OID, " 600 ").encode())["timeout"] == 600
    assert parse(_nasl(VARIABLE_OID, "my_timeout").encode()) is None  # never guessed
    assert parse(_nasl(VARIABLE_OID, "__import__('os')").encode()) is None
    assert parse(_nasl("1.3.6.1.4.1.25623.1.0.1", None).encode()) is None


def test_index_caps_only_long_or_unbounded_checks_and_never_scanners(tmp_path):
    root = _feed(tmp_path / "plugins")
    data = nvt_timeouts.build_index(root)
    assert data["files_scanned"] == 6  # .inc helpers are not checks
    assert set(data["nvts"]) == {LONG_OID, UNBOUNDED_OID, SHORT_OID, NMAP_LIKE_OID}
    caps = nvt_timeouts.long_timeout_caps(900, data)
    assert caps == {LONG_OID: 900, UNBOUNDED_OID: 900}
    # A check below the cap keeps its own (shorter) limit: a cap never raises a limit.
    assert SHORT_OID not in caps
    # The port scanner / service detection family is never capped.
    assert NMAP_LIKE_OID not in caps
    assert nvt_timeouts.long_timeout_caps(0, data) == {}
    sample = nvt_timeouts.describe_long_checks(data, 900)
    assert sample[0].startswith("Endless web check (no limit)")


def test_index_is_cached_per_feed_and_rebuilt_when_the_feed_changes(tmp_path):
    root = _feed(tmp_path / "plugins", plugin_set="202610150600")
    idx = nvt_timeouts.TimeoutIndex(root=root, cache=tmp_path / "idx.json")
    data = idx.get(wait=10)
    assert data and LONG_OID in data["nvts"] and (tmp_path / "idx.json").exists()
    assert "declare their own timeout" in idx.status()

    # A new agent process loads the saved index instead of re-reading the feed.
    again = nvt_timeouts.TimeoutIndex(root=root, cache=tmp_path / "idx.json")
    assert again.get()["signature"] == data["signature"] and again.status().startswith("loaded")

    # Feed update: new PLUGIN_SET -> rebuilt, with the new check.
    (root / "plugin_feed_info.inc").write_text('PLUGIN_SET = "202610160600";\n')
    new_oid = "1.3.6.1.4.1.25623.1.0.999399"
    (root / "2026" / "new.nasl").write_text(_nasl(new_oid, "-1", "New endless check"))
    again.invalidate()
    rebuilt = again.get(wait=10)
    assert rebuilt and new_oid in rebuilt["nvts"] and rebuilt["signature"] != data["signature"]


def test_missing_plugins_volume_is_reported_not_raised(tmp_path):
    idx = nvt_timeouts.TimeoutIndex(root=tmp_path / "absent", cache=tmp_path / "idx.json")
    assert idx.get() is None
    assert "mount gvm_vt_data" in idx.status()


# --- 5. task start: caps on every profile, per-check logging, no duplicate config read --------------
class _Gmp:
    def __init__(self):
        self.prefs: list[tuple[str, str, str, str]] = []
        self.scanner_prefs: dict[str, str] = {}
        self.removed_prefs: list[str] = []
        self.config_reads = 0

    def get_scan_configs(self, **kw):
        return etree.fromstring(b"<r/>")

    def clone_scan_config(self, cid):
        return {"id": f"profile-of-{cid}"}

    def modify_scan_config_set_name(self, cid, name):
        pass

    def get_scan_config(self, cid):
        self.config_reads += 1
        return etree.fromstring(b'<get_configs_response><config id="c"><nvt_count>185633</nvt_count>'
                                b"<families><family><name>General</name><nvt_count>10</nvt_count>"
                                b"<max_nvt_count>10</max_nvt_count><growing>1</growing></family></families>"
                                b"</config></get_configs_response>")

    def modify_scan_config_set_nvt_preference(self, cid, name, nvt_oid, value=None):
        self.prefs.append((cid, name, nvt_oid, value))

    def modify_scan_config_set_comment(self, cid, *, comment=None):
        pass

    def modify_scan_config_set_scanner_preference(self, cid, name, value=None):
        if value is None:  # gvmd deletes a preference sent without a value
            self.removed_prefs.append(name)
            return
        self.scanner_prefs[name] = value

    def delete_scan_config(self, cid, ultimate=False):
        pass

    def create_target(self, **kw):
        return {"id": "t1"}

    def create_task(self, **kw):
        self.task = kw
        return {"id": "task-1"}

    def start_task(self, tid):
        return etree.fromstring(b"<r><report_id>r</report_id></r>")

    def get_feeds(self):
        return etree.fromstring(b"<r/>")

    def get_nvts(self, **kw):
        return etree.fromstring(b"<r><nvt/></r>")

    def get_credential(self, cid):
        return etree.fromstring(b"<r/>")


def _start(monkeypatch, tmp_path, policy):
    root = _feed(tmp_path / "plugins")
    monkeypatch.setenv("OPENVAS_PLUGINS_DIR", str(root))
    nvt_timeouts.timeout_index().get(wait=10)  # the background build, finished
    g = _Gmp()

    @contextmanager
    def sess(**kw):
        yield g

    monkeypatch.setattr(gmp_local, "_session", sess)
    monkeypatch.setattr(gmp_local, "_ensure_portscan_config", lambda gmp, base: "cfg")
    monkeypatch.setattr(gmp_local, "_find_scanner_id", lambda gmp: "s")
    monkeypatch.setattr(gmp_local, "_named_port_list_tcp", lambda gmp, name: {80})
    from agent import control_plane

    monkeypatch.setattr(control_plane, "_probe_health", lambda *a, **kw: False)  # hermetic: no TCP
    monkeypatch.setenv("SCAN_CHECK_SCOPE", "all")  # keep the check-scope clone out of this test
    scanner = gmp_local.LocalOpenVAS()
    tid = scanner.start_scan(name="t", targets=["192.0.2.9"], scan_policy=policy, max_checks=4)
    return g, scanner.policy_snapshots[tid]


@pytest.mark.parametrize("profile", ["fast", "turbo", "standard"])
def test_every_profile_gets_the_caps_and_no_log_whole_attack_value(monkeypatch, tmp_path, profile):
    g, snap = _start(monkeypatch, tmp_path, {"template": "basic_network", "performance": profile})
    capped = {oid: value for (_cid, name, oid, value) in g.prefs if name.endswith(":0:entry:timeout")}
    assert capped.get(LONG_OID) == "900" and capped.get(UNBOUNDED_OID) == "900"
    assert SHORT_OID not in capped and NMAP_LIKE_OID not in capped
    assert set(perf.static_caps()) <= set(capped)  # before V1.9.3 only "fast" got these
    # V1.9.5: through a scan config log_whole_attack can only read as "off"
    # (gvmd sends "1"; OpenVAS wants "yes"), so it is removed, never set.
    assert "log_whole_attack" not in g.scanner_prefs
    assert g.removed_prefs == ["log_whole_attack"]
    caps = snap["nvt_timeout_caps"]
    assert caps["sources"]["long_timeout"] == 2 and caps["long_timeout_max_sec"] == 900


def test_log_whole_attack_is_never_sent_even_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENVAS_LOG_WHOLE_ATTACK", "yes")
    g, _ = _start(monkeypatch, tmp_path, {"template": "basic_network", "performance": "fast"})
    assert "log_whole_attack" not in g.scanner_prefs and g.removed_prefs == ["log_whole_attack"]


def test_long_timeout_caps_can_be_turned_off(monkeypatch, tmp_path):
    monkeypatch.setenv("SCAN_NVT_MAX_SEC", "0")
    g, snap = _start(monkeypatch, tmp_path, {"template": "basic_network", "performance": "fast"})
    capped = {oid for (_cid, name, oid, _v) in g.prefs if name.endswith(":0:entry:timeout")}
    assert LONG_OID not in capped and snap["nvt_timeout_caps"]["sources"]["long_timeout"] == 0


def test_task_start_reads_the_big_config_once_not_twice(monkeypatch, tmp_path):
    """The config-count floor reuses the count effective_selection just read (was 30-40 s per IP)."""
    g, snap = _start(monkeypatch, tmp_path, {"template": "basic_network", "performance": "fast"})
    # one read for the Nmap timing preference lookup on the new clone, one for the selection;
    # the feed-quality floor no longer adds a third.
    assert g.config_reads == 2
    assert snap["check_selection"]["nvt_count"] == 185633


def test_config_floor_still_refuses_an_incomplete_config(monkeypatch, tmp_path):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "200000")
    with pytest.raises(RuntimeError, match="config_nvt_count=185633"):
        _start(monkeypatch, tmp_path, {"template": "basic_network", "performance": "fast"})
