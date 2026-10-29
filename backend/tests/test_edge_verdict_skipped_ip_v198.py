"""V1.9.8 — field job fcbb90c0: 10 IPs, 9 assessed, 192.168.1.239's scan failed mid-way.

The agent skipped that IP (reason in skipped_hosts) and kept its 50 partial findings.
The job is now "completed" with a warning naming the IP; with agent < 1.9.8 the kept
rows were not declared (241 declared vs 291 rows) and that real mismatch still fails.
"""
from app.services.scanner_agent_jobs import evaluate_edge_ingest_verdict

TARGETS = [f"192.168.1.{n}" for n in (10, 11, 12, 13, 14, 15, 16, 17, 18, 239)]
BAD = "192.168.1.239"


def _verdict(**overrides):
    base = {
        "target_list": TARGETS,
        "skipped_details": [{"host": BAD, "reason": "scan_failed", "error": "OpenVAS failed"}],
        "skipped_set": {BAD},
        "assessed_list": [t for t in TARGETS if t != BAD],
        "status": "completed",
        "partial": True,
        "partial_reason": "OpenVAS finished but assessed 9 of 10 target(s): incomplete_coverage",
        "error": None,
        "external_scan_id": ",".join(f"task-{i}" for i in range(10)),
        "report_id": "rep-1",
        "task_status": "done",
        "hosts_attempted": 10,
        "hosts_assessed": 9,
        "report_result_count": 291,
        "plugin_error_count": 0,
        "scan_start": "2026-10-16T03:59:21Z",
        "scan_end": "2026-10-16T05:28:09Z",
        "assessment_complete": False,
        "assessment_verdict": "incomplete_coverage",
        "report_read_error": None,
        "vulnerability_count": 291,
        "evidence_present": True,
        "host_coverage": {t: {"verdict": "observed_unverified"} for t in TARGETS if t != BAD},
    }
    base.update(overrides)
    return evaluate_edge_ingest_verdict(**base)


def test_one_failed_ip_does_not_fail_nine_assessed_ips():
    v = _verdict()
    assert v["final_status"] == "completed" and v["verified_complete"] is True
    assert v["err_text"] is None
    assert v["clean_eligible"] is False
    assert v["not_assessed_hosts"] == [BAD]
    assert v["warnings"] == ["1 of 10 IP(s) not assessed: 192.168.1.239 (scan_failed)"]


def test_undeclared_rows_from_an_old_agent_still_fail_on_integrity():
    v = _verdict(report_result_count=241)
    assert v["final_status"] == "failed"
    assert "report declares 241 result(s) but the agent uploaded 291 parsed row(s)" in v["err_text"]


def test_a_missing_ip_the_agent_did_not_explain_still_fails():
    v = _verdict(skipped_details=[], skipped_set=set())
    assert v["final_status"] == "failed"
    assert "no assessment evidence for target(s): 192.168.1.239" in v["err_text"]


def test_every_ip_skipped_still_fails():
    v = _verdict(assessed_list=[], hosts_assessed=0, report_result_count=0, vulnerability_count=0,
                 skipped_details=[{"host": t, "reason": "scan_failed"} for t in TARGETS], skipped_set=set(TARGETS))
    assert v["final_status"] == "failed"


def test_single_ip_job_whose_ip_failed_still_fails():
    v = _verdict(target_list=[BAD], assessed_list=[], hosts_assessed=0, hosts_attempted=1,
                 report_result_count=50, vulnerability_count=50)
    assert v["final_status"] == "failed"
