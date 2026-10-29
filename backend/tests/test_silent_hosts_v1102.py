"""V1.10.2: IPs that answered nothing must not read as clean 'Completed' scans."""

from __future__ import annotations

from pathlib import Path

from app.services.scanner_agent_jobs import (
    _merge_edge_target_progress,
    classify_host_coverage,
    silent_hosts,
    silent_hosts_note,
)

SILENT = ["192.168.0.162", "192.168.0.183", "192.168.0.194", "192.168.0.201", "192.168.0.209",
          "192.168.0.212", "192.168.0.228", "192.168.0.234", "192.168.0.241", "192.168.0.246"]
GATEWAY = "192.168.0.254"


def _field_coverage(cause: str | None = "client_isolation_suspected") -> dict:
    cov = {
        h: {"verdict": "no_exposed_services", "network_scan_complete": True, "host_responded": False,
            "port_state_counts": {"open": 0, "closed": 0, "filtered": 262}, "silent_cause": cause,
            "icmp_echo": "no_reply", "notes": ["Not assessed: ..."]}
        for h in SILENT
    }
    cov[GATEWAY] = {"verdict": "observed_unverified", "network_scan_complete": True,
                    "open_tcp_ports": [22, 80, 443], "warnings": ["w"] * 8, "notes": ["n"] * 5}
    return cov


def test_late_completed_event_keeps_the_not_assessed_explanation():
    tp, _, _ = classify_host_coverage(_field_coverage(), {})
    assert tp[SILENT[0]]["activity"].startswith("No response - not assessed: none of 262 policy TCP ports answered")
    # The agent's per-IP "completed" event (with its task id) arrives after classification.
    late = {h: {"status": "completed", "task_id": "task-9", "event_seq": 40} for h in SILENT + [GATEWAY]}
    merged = _merge_edge_target_progress(tp, late, SILENT + [GATEWAY])
    for h in SILENT:
        assert merged[h]["activity"].startswith("No response - not assessed"), merged[h]["activity"]
        assert merged[h]["coverage"]["host_responded"] is False
        assert merged[h]["event_seq"] == 40
    # V1.10.3: warnings no longer change the label; the count stays in the activity.
    assert merged[GATEWAY]["activity"].startswith("Completed - network scan finished, 3 open TCP")
    assert "check warning(s)" in merged[GATEWAY]["activity"]
    assert merged[GATEWAY]["coverage"]["host_responded"] is True


def test_a_new_task_drops_the_previous_verdict():
    tp, _, _ = classify_host_coverage(_field_coverage(), {})
    tp[SILENT[0]]["task_id"] = "task-1"
    merged = _merge_edge_target_progress(tp, {SILENT[0]: {"status": "scanning", "task_id": "task-2",
                                                          "event_seq": 50, "progress_pct": 10}}, SILENT)
    row = merged[SILENT[0]]
    assert row["status"] == "scanning" and "coverage" not in row and "notes" not in row


def test_causes_are_named_on_the_row():
    for cause, words in (("client_isolation_suspected", "client isolation"),
                         ("host_firewall", "answers ping"),
                         ("no_answer", "no ping reply"),
                         (None, "firewall blocking or host offline")):
        tp, _, _ = classify_host_coverage({SILENT[0]: _field_coverage(cause)[SILENT[0]]}, {})
        assert words in tp[SILENT[0]]["activity"], (cause, tp[SILENT[0]]["activity"])


def test_host_that_refused_connections_is_up_not_silent():
    cov = {"10.0.0.5": {"verdict": "no_exposed_services", "network_scan_complete": True, "host_responded": True,
                        "port_state_counts": {"closed": 200, "filtered": 62}}}
    tp, _, _ = classify_host_coverage(cov, {})
    assert tp["10.0.0.5"]["activity"].startswith("No exposed services - host is up")
    assert silent_hosts(cov) == ([], ["10.0.0.5"])


def test_job_note_explains_why_findings_are_on_one_ip():
    note = silent_hosts_note(_field_coverage())
    assert note.startswith("10 of 11 IPs did not answer on any policy TCP port and were not assessed")
    assert GATEWAY in note and "client (AP) isolation" in note and "wired port" in note
    cov = _field_coverage("host_firewall")
    assert "10 silent IP(s) answered ping" in silent_hosts_note(cov)
    assert silent_hosts_note({GATEWAY: _field_coverage()[GATEWAY]}) is None


def test_job_label_and_notes_wired_in_router():
    src = (Path(__file__).resolve().parents[1] / "app/routers/vuln.py").read_text(encoding="utf-8")
    assert 'IP(S) DID NOT ANSWER"' in src
    assert "notes.insert(0, silent_note)" in src
