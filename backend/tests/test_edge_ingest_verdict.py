"""Central ingest must never convert skipped targets into clean coverage."""

from app.services.scanner_agent_jobs import evaluate_edge_ingest_verdict


def _verdict(**overrides):
    base = {
        "target_list": ["192.168.0.163", "192.168.0.103"],
        "skipped_details": [{"host": "192.168.0.103", "reason": "unreachable"}],
        "skipped_set": {"192.168.0.103"},
        "assessed_list": ["192.168.0.163"],
        "status": "completed",
        "partial": True,
        "partial_reason": "OpenVAS finished but assessed 1 of 2 target(s): target_not_in_report",
        "error": None,
        "external_scan_id": "49700bc1-cd46-4e65-af2a-6dd4feabc213",
        "report_id": "18c107e5-0580-4827-b13c-2e51dc8bbe4a",
        "task_status": "done",
        "hosts_attempted": 2,
        "hosts_assessed": 1,
        "report_result_count": 12,
        "plugin_error_count": 0,
        "scan_start": "2026-08-26T11:54:08Z",
        "scan_end": "2026-08-26T13:00:58Z",
        "assessment_complete": False,
        "assessment_verdict": "target_not_in_report",
        "report_read_error": None,
        "vulnerability_count": 12,
        "evidence_present": True,
    }
    base.update(overrides)
    return evaluate_edge_ingest_verdict(**base)


def test_done_one_alive_one_skipped_completes_with_warning():
    # V1.9.8 (was "failed"): the agent skipped 192.168.0.103 with a stated reason and
    # 192.168.0.163 was assessed, so the job completes - never clean, the IP named.
    v = _verdict()
    assert v["coverage_ok"] is True
    assert v["verified_complete"] is True
    assert v["final_status"] == "completed"
    assert v["err_text"] is None
    assert v["clean_eligible"] is False
    assert v["missing_ip_targets"] == ["192.168.0.103"]
    assert v["not_assessed_hosts"] == ["192.168.0.103"]
    assert v["warnings"] == ["1 of 2 IP(s) not assessed: 192.168.0.103 (unreachable)"]
    assert v["required_count"] == 2


def test_report_with_results_but_zero_parsed_rows_fails_integrity_gate():
    v = _verdict(report_result_count=400, vulnerability_count=0)
    assert v["result_payload_ok"] is False
    assert v["verified_complete"] is False
    assert v["final_status"] == "failed"
    assert "result integrity mismatch" in " ".join(v["reasons"])


def test_missing_skip_for_absent_host_still_fails():
    v = _verdict(
        skipped_details=[],
        skipped_set=set(),
        partial=True,
        assessment_complete=False,
    )
    assert v["coverage_ok"] is False
    assert v["verified_complete"] is False
    assert v["final_status"] == "failed"
    assert "192.168.0.103" in " ".join(v["reasons"])


def test_all_unreachable_without_gmp_task_fails():
    v = _verdict(
        target_list=["192.168.0.103"],
        skipped_details=[{"host": "192.168.0.103", "reason": "unreachable"}],
        skipped_set={"192.168.0.103"},
        assessed_list=[],
        partial=False,
        external_scan_id=None,
        report_id=None,
        task_status=None,
        hosts_attempted=0,
        hosts_assessed=0,
        report_result_count=0,
        assessment_complete=True,
        assessment_verdict="all_targets_unreachable_skipped",
        scan_start=None,
        scan_end=None,
    )
    assert v["final_status"] == "failed"
    assert v["effective_report_id"] is None
    assert v["clean_eligible"] is False


def test_partial_result_loss_fails_integrity_gate():
    v = _verdict(report_result_count=81, vulnerability_count=3)
    assert v["result_payload_ok"] is False
    assert v["verified_complete"] is False
    assert v["final_status"] == "failed"
    assert "81" in " ".join(v["reasons"])
    assert "3" in " ".join(v["reasons"])


def test_runtime_cap_partial_with_evidence_is_incomplete_not_failed():
    """V1.9.0: a scan stopped at the runtime cap at ~98%, on the one reachable
    target, with findings and a report, is 'incomplete' (keeps evidence), not a
    red 'failed'."""
    v = _verdict(
        target_list=["192.168.0.163"],
        skipped_details=[],
        skipped_set=set(),
        assessed_list=["192.168.0.163"],
        status="completed",
        partial=True,
        partial_reason="maximum runtime 3600s exceeded while status=stopped progress=98%",
        task_status="stopped",
        hosts_attempted=1,
        hosts_assessed=1,
        report_result_count=26,
        vulnerability_count=26,
        assessment_complete=False,
        assessment_verdict="partial_coverage",
    )
    assert v["final_status"] == "incomplete"
    assert v["verified_complete"] is False
    assert v["clean_eligible"] is False


def test_runtime_cap_partial_without_evidence_still_fails():
    v = _verdict(
        target_list=["192.168.0.163"],
        skipped_details=[],
        skipped_set=set(),
        assessed_list=[],
        status="completed",
        partial=True,
        partial_reason="maximum runtime 3600s exceeded",
        task_status="stopped",
        hosts_attempted=1,
        hosts_assessed=0,
        report_result_count=0,
        vulnerability_count=0,
        assessment_complete=False,
    )
    assert v["final_status"] == "failed"


def test_missing_target_is_still_failed_even_with_findings():
    # Regression: nothing may rescue a scan where a requested IP never appeared in
    # the report and the agent gave no reason for it (V1.9.8: an IP the agent
    # skipped with a reason is accounted for - see the test above).
    v = _verdict(task_status="stopped", skipped_details=[], skipped_set=set())
    assert v["final_status"] == "failed"
    assert v["missing_ip_targets"] == ["192.168.0.103"]
