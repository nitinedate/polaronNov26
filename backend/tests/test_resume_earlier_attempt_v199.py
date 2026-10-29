"""V1.9.9 — field job fcbb90c0: Resume after a first attempt that assessed 9 of 10 IPs.

The agent rescans only 192.168.1.239 and its upload names only that IP. Ingest used to
judge it against all 10 targets ("assessed 1 of 10", nine IPs "missing" -> failed).
The earlier attempt's assessed IPs (kept in orchestration_json) now count."""
import json
from unittest.mock import patch

from app.services.scanner_agent_jobs import ingest_agent_results

TARGETS = [f"192.168.1.{n}" for n in (5, 6, 10, 11, 30, 51, 76, 192, 248, 239)]
RESUMED = "192.168.1.239"
EARLIER = [t for t in TARGETS if t != RESUMED]
JOB_ID = "00000000-0000-0000-0000-0000000000f1"


def _job(resumed=True, earlier=EARLIER):
    orch = {"edge_agent": True, "edge_owner_instance": "agent-1",
            "assessed_hosts": list(earlier),
            "host_coverage": {h: {"verdict": "observed_unverified", "notes": [f"earlier {h}"]} for h in earlier}}
    if resumed:
        orch["edge_resume_requested"] = True
    return {"id": JOB_ID, "scanner_id": "00000000-0000-0000-0000-000000000002", "status": "running",
            "case_id": "00000000-0000-0000-0000-000000000003", "orchestration_json": orch}


def _ingest(job, assessed=(RESUMED,)):
    writes = []
    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), \
         patch("app.services.scanner_agent_jobs.fetchall",
               return_value=[{"target": t, "excluded": False} for t in TARGETS]), \
         patch("app.services.scanner_agent_jobs.ingest_engine_results", return_value=1), \
         patch("app.services.scanner_agent_jobs.execute", side_effect=lambda db, sql, params=None: writes.append(params)), \
         patch("app.services.vuln_brd.record_scan_result"), \
         patch("app.services.scanner_agent_jobs.timeline"):
        result = ingest_agent_results(
            object(), scanner_id=job["scanner_id"], job_id=JOB_ID, agent_instance_id="agent-1",
            vulnerabilities=[{"severity": "medium", "host": RESUMED}], external_scan_id="task-239",
            report_id="report-239", task_status="Done", partial=True,
            partial_reason="OpenVAS finished but assessed 1 of 10 target(s): incomplete_coverage",
            hosts_attempted=1, hosts_assessed=1, assessed_hosts=list(assessed), report_result_count=1,
            scan_start="2026-10-16T06:40:00Z", scan_end="2026-10-16T07:12:06Z", assessment_complete=False,
            host_coverage={RESUMED: {"verdict": "observed_unverified"}})
    stored = json.loads(next(p["orch"] for p in writes if p and "orch" in p))
    status_writes = [p.get("st") for p in writes if p and "st" in p]
    return result, stored, status_writes


def test_resume_counts_the_earlier_attempts_ips_and_completes():
    result, stored, statuses = _ingest(_job())
    assert "failed" not in statuses and "completed" in statuses
    assert sorted(stored["assessed_hosts"]) == sorted(TARGETS)
    assert stored["host_coverage"]["192.168.1.76"]["notes"] == ["earlier 192.168.1.76"]
    assert stored["host_coverage"][RESUMED]["verdict"] == "observed_unverified"


def test_without_resume_the_same_upload_still_fails():
    _, stored, statuses = _ingest(_job(resumed=False))
    assert "failed" in statuses
    assert sorted(stored["assessed_hosts"]) == [RESUMED]


def test_earlier_ips_outside_this_jobs_targets_do_not_count():
    _, stored, statuses = _ingest(_job(earlier=EARLIER[:8] + ["10.9.9.9"]))
    assert "10.9.9.9" not in stored["assessed_hosts"]
    assert "failed" in statuses  # one real target (192.168.1.248) still has no evidence from any attempt
