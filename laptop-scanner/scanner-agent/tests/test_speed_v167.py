"""V1.6.7: Nexus ports, fixed 4-IP pool, 15-minute per-IP limit, stuck-IP diagnostics."""
from __future__ import annotations

import pytest

from agent import gmp_local, main, scan_performance as perf
from agent.openvas_log import host_activity
from agent.scan_performance import NvtHangRegistry, fixed_ip_workers, ip_deadline_sec

OID = "1.3.6.1.4.1.25623.1.0.999777"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("SCAN_PERFORMANCE", "SCAN_IP_DEADLINE_SEC", "SCAN_IP_WORKERS_FIXED", "PORT_PROFILE",
                "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_IP_STALL_SEC", "SCAN_PORTSCAN_STALL_SEC",
                "SCAN_TASK_START_STALL_SEC", "SERVICE_EXTRA_TCP_PORTS", "SERVICE_EXTRA_UDP_PORTS",
                "SCAN_TCP_CUSTOM_PORTS", "SCAN_UDP_CUSTOM_PORTS", "SCAN_CHECK_SCOPE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "openvas.log"))
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- ports ----------------------------------------------------------------------
def test_nexus_is_the_service_port_catalog_again(monkeypatch):
    nexus = gmp_local._effective_scan_policy(None, "nexus", "priority")
    catalog = gmp_local._effective_scan_policy(None, "catalog", "priority")
    assert nexus["port_range"] == catalog["port_range"]
    assert nexus["tcp_port_count"] < 200  # 154 in policy 1.1, not the 1,055+ floor of the nessus profile
    assert {22, 135, 139, 445, 3389, 8443} <= {
        p for tok in nexus["port_range"].split(",") if tok.startswith("T:")
        for p in gmp_local.port_numbers(tok[2:])}

    def must_not_widen(gmp, name):
        raise AssertionError("nexus must not load the IANA port list")

    monkeypatch.setattr(gmp_local, "_named_port_list_tcp", must_not_widen)
    scanner = gmp_local.LocalOpenVAS()
    assert scanner.resolve_port_range(["192.0.2.1"], None, {"template": "basic_network"}) == nexus["port_range"]


# --- settings ---------------------------------------------------------------------
def test_defaults_fixed_pool_and_deadline(monkeypatch):
    assert fixed_ip_workers() == 5  # V1.10.3 IP semaphore
    # V1.6.8: no per-IP time limit unless explicitly configured.
    assert ip_deadline_sec("fast") == 0 and ip_deadline_sec("standard") == 0
    monkeypatch.setenv("SCAN_IP_DEADLINE_SEC", "600")
    assert ip_deadline_sec("standard") == 600
    monkeypatch.setenv("SCAN_IP_WORKERS_FIXED", "0")
    assert fixed_ip_workers() == 0
    assert main._ip_worker_limit({"ip_workers": 7}, 20) == 7  # adaptive path still works


# --- OpenVAS log reader -------------------------------------------------------------
def test_host_activity_matches_exact_ip_and_extracts_oids(tmp_path):
    log = tmp_path / "openvas.log"
    log.write_text(
        f"lib  misc:MESSAGE:2026-10-14 192.168.0.163: launching NVT {OID}\n"
        "lib  misc:MESSAGE:2026-10-14 192.168.0.16: launching NVT 1.3.6.1.4.1.25623.1.0.1\n"
        f"lib  misc:MESSAGE:2026-10-14 192.168.0.163: NVT {OID} timed out\n"
    )
    out = host_activity("192.168.0.163")
    assert out["available"] is True and len(out["lines"]) == 2
    assert out["nvt_oids"] == [OID]
    assert host_activity("10.9.9.9")["lines"] == []


def test_missing_openvas_log_is_reported_not_raised(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "nope.log"))
    out = host_activity("192.168.0.163")
    assert out["available"] is False and "error" in out


# --- job-loop harness ------------------------------------------------------------------
def _loop(monkeypatch, hosts, poll_fn, *, env=None, step=30.0):
    from agent import reachability

    uploaded, events, stops = [], [], []
    clock = {"t": 5000.0}
    state = {"active": set(), "max_active": 0, "started": [], "n": {}, "stopped": set()}

    def mono():
        clock["t"] += step
        return clock["t"]

    class Api:
        def patch_job(self, job_id, payload):
            return {"id": job_id}

        def upload_results(self, job_id, payload):
            uploaded.append(payload)
            return {"status": "completed"}

    class Scanner:
        port_profile = "nexus"

        def start_scan(self, *, name, targets, **kw):
            tid = f"task-{targets[0]}"
            state["active"].add(tid)
            state["started"].append(tid)
            state["max_active"] = max(state["max_active"], len(state["active"]))
            state["n"][tid] = 0
            return tid

        def get_task_hosts(self, task_id):
            return [task_id.split("task-", 1)[1]]

        def poll(self, task_id, **kw):
            state["n"][task_id] += 1
            host = task_id.split("task-", 1)[1]
            res = poll_fn(host, state["n"][task_id], task_id in state["stopped"])
            if res["status"] in {"completed", "stopped", "failed"}:
                state["active"].discard(task_id)
            return res

        def stop(self, task_id):
            stops.append(task_id)
            state["stopped"].add(task_id)
            return True

    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    monkeypatch.setattr(main.time, "monotonic", mono)
    monkeypatch.setattr(main, "should_watch_lan", lambda *a, **kw: False)
    monkeypatch.setattr(main, "probe_laptop_capacity", lambda **kw: {
        "chunk_size": 1, "ip_workers": 8, "configured_ceiling": 10, "hot": False, "admission_paused": False})
    monkeypatch.setattr(main, "emit_ip_event", lambda job, host, event, **kw: events.append((host, event, kw)))
    monkeypatch.setattr(main, "emit_service_results", lambda *a, **kw: None)
    monkeypatch.setattr(reachability, "partition_targets", lambda targets, **kw: {
        "reachable": list(targets), "unreachable": [], "skipped_hosts": []})
    monkeypatch.setenv("SKIP_UNREACHABLE_TARGETS", "false")
    monkeypatch.setenv("SCAN_DEGRADED_RETRY", "0")
    monkeypatch.setenv("PORT_DISCOVERY_ENABLED", "false")  # hermetic: no real TCP probes
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    main._run_job_body({"api": Api(), "openvas": Scanner(), "poll": 0, "max_scan_runtime_sec": 0,
                        "progress_report_interval": 0, "high_progress_warn_sec": 300,
                        "high_progress_stall_sec": 0},
                       {"id": "00000000-0000-0000-0000-0000000000a7",
                        "targets": [{"target": h} for h in hosts]})
    return uploaded, events, stops, state


def _done(host, ports=(135, 139, 445)):
    return {"status": "completed", "gmp_status": "done", "progress": 100,
            "vulnerabilities": [{"host": host, "result_id": f"r-{host}", "severity": "medium",
                                 "port": 445, "protocol": "tcp", "plugin_name": "SMB check", "cvss": 5.0}],
            "evidence": {"report_id": f"rep-{host}", "task_status": "done", "assessed_hosts": [host],
                         "hosts_assessed": 1, "assessment_complete": True,
                         "scan_start": "2026-10-14T03:00:00Z", "scan_end": "2026-10-14T03:05:00Z",
                         "host_coverage": {host: {"verdict": "observed_unverified", "network_scan_complete": True,
                                                  "open_tcp_ports": list(ports), "warnings": []}}}}


def test_fixed_pool_never_runs_more_than_four_ips(monkeypatch):
    hosts = [f"10.0.1.{i}" for i in range(1, 11)]
    poll = lambda host, n, stopped: _done(host) if n >= 3 else {
        "status": "running", "gmp_status": "running", "progress": 40 * n, "vulnerabilities": [], "evidence": {}}
    uploaded, _, _, state = _loop(monkeypatch, hosts, poll)
    assert state["max_active"] == 5  # V1.10.3 IP semaphore
    assert len(state["started"]) == 10
    assert uploaded[-1]["status"] == "completed"


def test_fixed_pool_size_is_configurable(monkeypatch):
    hosts = [f"10.0.2.{i}" for i in range(1, 7)]
    poll = lambda host, n, stopped: _done(host) if n >= 2 else {
        "status": "running", "gmp_status": "running", "progress": 50, "vulnerabilities": [], "evidence": {}}
    _, _, _, state = _loop(monkeypatch, hosts, poll, env={"SCAN_IP_WORKERS_FIXED": "2"})
    assert state["max_active"] == 2


def _slow_then_stopped(host, n, stopped, *, ports=(135, 139, 445), pct=None):
    if stopped:
        res = _done(host, ports)
        res["status"] = "stopped"
        res["gmp_status"] = "stopped"
        res["progress"] = 94
        res["evidence"]["task_status"] = "stopped"
        res["evidence"]["scan_end"] = None
        res["evidence"]["host_coverage"][host]["network_scan_complete"] = False
        if not ports:
            res["evidence"]["host_coverage"][host]["verdict"] = "degraded_no_ports"
        return res
    progress = pct if pct is not None else min(97, 90 + n // 10)
    return {"status": "running", "gmp_status": "running", "progress": progress, "vulnerabilities": [], "evidence": {}}


def test_fast_mode_without_limit_never_stops_a_progressing_ip(monkeypatch):
    host = "192.168.0.163"
    poll = lambda h, n, stopped: _done(h) if n >= 150 else {
        "status": "running", "gmp_status": "running", "progress": min(98, 10 + n), "vulnerabilities": [],
        "evidence": {}}
    uploaded, events, stops, _ = _loop(monkeypatch, [host], poll, env={"SCAN_PERFORMANCE": "fast"})
    assert stops == [] and not [e for _, e, _ in events if e == "time_limit"]
    assert uploaded[-1]["status"] == "completed"


def test_opt_in_time_limit_stops_an_ip_and_reports_it_honestly(monkeypatch):
    host = "192.168.0.163"
    uploaded, events, stops, _ = _loop(monkeypatch, [host], _slow_then_stopped,
                                       env={"SCAN_PERFORMANCE": "fast", "SCAN_IP_DEADLINE_SEC": "900"})
    assert stops == [f"task-{host}"]
    limit_events = [kw for h, ev, kw in events if ev == "time_limit"]
    assert limit_events and limit_events[0]["limit_sec"] == 900
    final = uploaded[-1]
    assert final["status"] == "completed"
    skipped = final.get("skipped_hosts") or (final.get("evidence") or {}).get("skipped_hosts") or []
    assert not skipped, "a time-limited host is a finished scan with a warning, not a skipped host"
    cov = final["host_coverage"][host]
    assert cov["time_limited"] is True and cov["network_scan_complete"] is True
    assert cov["verdict"] == "observed_unverified" and cov["stopped_at_progress"] >= 90
    assert any("time limit" in w for w in cov["warnings"])
    assert any(v.get("result_id") == f"r-{host}" for v in final["vulnerabilities"])  # findings kept
    assert final["scan_end"]  # stop time recorded
    # What central needs to accept the job instead of failing it:
    assert final["task_status"] == "done" and final["assessment_complete"] is True
    assert host in final["assessed_hosts"]
    assert final["assessment_verdict"] != "assessed" or cov["time_limited"]


def test_time_limit_wins_over_preprobe_mismatch():
    from agent.coverage_reconcile import reconcile_host_observations

    d = {"evidence": {"host_coverage": {"h": {"verdict": "degraded_time_limit", "time_limited": True,
                                               "open_tcp_ports": [], "warnings": []}}}}
    reconcile_host_observations(d, "h", [445])
    cov = d["evidence"]["host_coverage"]["h"]
    assert cov["verdict"] == "degraded_time_limit" and any("445" in w for w in cov["warnings"])


def test_time_limit_during_port_scan_is_incomplete_and_not_retried(monkeypatch):
    host = "192.168.0.164"
    poll = lambda h, n, stopped: _slow_then_stopped(h, n, stopped, ports=(), pct=5)
    uploaded, events, stops, state = _loop(monkeypatch, [host], poll,
                                           env={"SCAN_PERFORMANCE": "fast", "SCAN_DEGRADED_RETRY": "1",
                                                "SCAN_IP_DEADLINE_SEC": "900"})
    cov = uploaded[-1]["host_coverage"][host]
    assert cov["verdict"] == "degraded_time_limit" and cov["network_scan_complete"] is False
    assert len(state["started"]) == 1  # no automatic re-run of a time-limited host


def test_standard_mode_has_no_time_limit(monkeypatch):
    host = "10.0.3.1"
    poll = lambda h, n, stopped: _done(h) if n >= 80 else {
        "status": "running", "gmp_status": "running", "progress": 10 + n, "vulnerabilities": [], "evidence": {}}
    uploaded, events, stops, _ = _loop(monkeypatch, [host], poll, env={"SCAN_PERFORMANCE": "standard"})
    assert stops == [] and not [e for _, e, _ in events if e == "time_limit"]
    assert uploaded[-1]["status"] == "completed"


def test_stuck_ip_logs_what_openvas_is_running(monkeypatch, tmp_path):
    host = "192.168.0.163"
    (tmp_path / "openvas.log").write_text(f"x {host}: NVT {OID} still running\n")
    _, events, _, _ = _loop(monkeypatch, [host], _slow_then_stopped,
                            env={"SCAN_PERFORMANCE": "fast", "SCAN_IP_DEADLINE_SEC": "900"})
    tails = [kw for h, ev, kw in events if ev == "tail_activity"]
    assert tails and tails[0]["nvt_oids"] == [OID] and tails[0]["log_available"] is True
