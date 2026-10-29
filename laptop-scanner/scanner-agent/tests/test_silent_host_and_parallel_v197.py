"""V1.9.7 — field job de53e2fe (Advanced template, 2 IPs, agent 1.9.6).

* Both OpenVAS tasks started within ~1 s and both were stopped at their own 60-min
  limit, so the IPs ran in parallel. 192.168.0.195 answered none of 154 probed ports
  and sat at 0% (OpenVAS's progress stays 0 until the port scan of all 65,535 ports
  ends) for the whole hour, holding a slot.
* Now: such a silent host is stopped after SCAN_SILENT_HOST_SEC as "no response";
  the Activity column says what a 0% IP is doing; a 5-minute log line lists the IPs
  scanning in parallel.
"""
from __future__ import annotations

import logging

from agent import main, port_discovery, target_progress
from tests.test_speed_v167 import _done, _loop

SILENT = "192.168.0.195"
LIVE = "192.168.0.10"


def _plan(states_by_host):
    def plan(chunk):
        host = chunk[0]
        states = states_by_host.get(host, {"open": [445], "closed": [22], "filtered": []})
        return {"observed_port_range": ",".join(f"T:{p}" for p in states["open"]),
                "open_ports": {host: list(states["open"])}, "port_states": {host: states},
                "fallback": not states["open"]}
    return plan


def _run(monkeypatch, poll, states_by_host, env=None):
    monkeypatch.setattr(port_discovery, "discovery_plan", _plan(states_by_host))
    base = {"MAX_SCAN_RUNTIME_SEC": "3600", "SCAN_IP_WORKERS_FIXED": "4"}
    base.update(env or {})
    return _loop(monkeypatch, [LIVE, SILENT], poll, env=base)


SILENT_STATES = {SILENT: {"open": [], "closed": [], "filtered": list(range(1, 155))}}


def _poll_silent_stays_at_zero(done_after=40):
    def poll(host, n, stopped):
        if host == SILENT:
            if stopped:
                return {"status": "stopped", "gmp_status": "stopped", "progress": 0, "vulnerabilities": [],
                        "evidence": {"report_id": "rep-s", "task_status": "stopped", "assessed_hosts": [],
                                     "hosts_assessed": 0, "host_coverage": {}}}
            return {"status": "running", "gmp_status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}
        return _done(host) if n >= done_after else {
            "status": "running", "gmp_status": "running", "progress": min(95, n * 2), "vulnerabilities": [],
            "evidence": {}}
    return poll


# --- the silent-host rule ----------------------------------------------------------------------
def test_silent_preprobe_counts_only_hosts_that_answered_nothing():
    assert main._silent_preprobe({"open": [], "closed": [], "filtered": [1, 2, 3]}) == 3
    assert main._silent_preprobe({"open": [], "closed": [22], "filtered": [1, 2]}) == 0  # a reset = host is up
    assert main._silent_preprobe({"open": [445], "closed": [], "filtered": []}) == 0
    assert main._silent_preprobe(None) == 0


def test_silent_host_is_stopped_as_no_response_and_frees_its_slot(monkeypatch):
    uploaded, events, stops, _ = _run(monkeypatch, _poll_silent_stays_at_zero(), SILENT_STATES,
                                      env={"SCAN_SILENT_HOST_SEC": "900"})
    assert f"task-{SILENT}" in stops and f"task-{LIVE}" not in stops
    no_resp = [kw for host, ev, kw in events if host == SILENT and ev == "no_response"]
    assert no_resp and no_resp[0]["probed_ports"] == 154
    assert 900 <= no_resp[0]["after_sec"] < 3600  # well before the per-IP limit
    assert not [1 for host, ev, _ in events if host == SILENT and ev == "time_limit"]
    cov = uploaded[-1]["host_coverage"][SILENT]
    assert cov["verdict"] == "no_response"
    assert any("No response: none of the 154 TCP ports" in n for n in cov.get("warnings") or [])
    assert uploaded[-1]["host_coverage"][LIVE]["verdict"] == "observed_unverified"


def test_host_that_reset_a_port_is_not_treated_as_silent(monkeypatch):
    states = {SILENT: {"open": [], "closed": [22], "filtered": list(range(1, 154))}}
    uploaded, events, stops, _ = _run(monkeypatch, _poll_silent_stays_at_zero(), states,
                                      env={"SCAN_SILENT_HOST_SEC": "900", "MAX_SCAN_RUNTIME_SEC": "3000"})
    assert not [1 for host, ev, _ in events if host == SILENT and ev == "no_response"]
    assert [1 for host, ev, _ in events if host == SILENT and ev == "time_limit"]  # only the normal limit


def test_silent_host_rule_can_be_turned_off(monkeypatch):
    _, events, _, _ = _run(monkeypatch, _poll_silent_stays_at_zero(), SILENT_STATES,
                           env={"SCAN_SILENT_HOST_SEC": "0", "MAX_SCAN_RUNTIME_SEC": "3000"})
    assert not [1 for host, ev, _ in events if host == SILENT and ev == "no_response"]


def test_a_silent_host_that_starts_progressing_is_left_alone(monkeypatch):
    def poll(host, n, stopped):
        if host == SILENT:
            return _done(host) if n >= 30 else {"status": "running", "gmp_status": "running",
                                                "progress": 0 if n < 10 else 40, "vulnerabilities": [], "evidence": {}}
        return _done(host) if n >= 5 else {"status": "running", "gmp_status": "running", "progress": 50,
                                           "vulnerabilities": [], "evidence": {}}
    uploaded, events, stops, _ = _run(monkeypatch, poll, SILENT_STATES, env={"SCAN_SILENT_HOST_SEC": "1800"})
    assert f"task-{SILENT}" not in stops
    assert uploaded[-1]["host_coverage"][SILENT]["verdict"] == "observed_unverified"


# --- what the Activity column says --------------------------------------------------------------
def test_activity_says_waiting_for_a_slot_and_port_scan_running():
    states = target_progress.build_target_progress(
        ["a", "b", "c"], chunks=[["a"], ["b"], ["c"]], in_flight={0: "t-a", 1: "t-b"}, done_details={},
        poll_results={0: {"progress": 0}, 1: {"progress": 37}}, running_sec={0: 25 * 60, 1: 600}, slots=2)
    assert states["a"]["activity"].startswith("Port scan running (25 min)")
    assert states["b"]["activity"] == "In progress (37%, 10 min)"
    assert states["c"]["activity"] == "Waiting for a free scan slot (2 IPs scan at once)"


def test_activity_without_new_arguments_is_unchanged():
    states = target_progress.build_target_progress(
        ["a", "b"], chunks=[["a"], ["b"]], in_flight={0: "t-a"}, done_details={}, poll_results={0: {"progress": 0}})
    assert states["a"]["activity"] == "In progress (0%)"
    assert states["b"]["activity"] == "Waiting"


def test_no_response_host_gets_its_own_activity_text():
    done = {0: {"status": "completed", "evidence": {"assessment_complete": False, "host_coverage": {
        "a": {"verdict": "no_response", "reason": "No response on any probed port"}}}}}
    states = target_progress.build_target_progress(["a"], chunks=[["a"]], in_flight={}, done_details=done)
    assert states["a"]["status"] == "incomplete"
    assert states["a"]["activity"].startswith("No response: ")


def test_parallel_status_line_lists_the_ips_scanning_together(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="scanner_agent")
    _run(monkeypatch, _poll_silent_stays_at_zero(done_after=30), SILENT_STATES, env={"SCAN_SILENT_HOST_SEC": "900"})
    lines = [r.getMessage() for r in caplog.records if "parallel status" in r.getMessage()]
    assert lines
    # IP starts run on worker threads, so the first line may catch one IP still starting.
    both = [ln for ln in lines if "2 IP(s) scanning now" in ln and SILENT in ln and LIVE in ln]
    assert both, lines
    assert "port scan" in both[0] and "waiting for a free slot (up to 4 at once)" in both[0]
