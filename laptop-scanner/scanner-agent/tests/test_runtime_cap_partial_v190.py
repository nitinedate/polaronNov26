"""V1.9.0 - MAX_SCAN_RUNTIME_SEC cap keeps partial evidence instead of binning it.

Before, hitting the runtime cap uploaded status="failed" and discarded a scan
that had already collected findings and a port map (the 98%/status=stopped case).
Now, when usable evidence exists, the job is kept as completed + partial
(completed-with-warnings, not clean-eligible); only a cap with nothing usable
fails outright.
"""
from __future__ import annotations

import inspect

from agent import main


def test_runtime_cap_branch_keeps_partial_when_evidence_exists():
    source = inspect.getsource(main)
    # The cap handler must branch on whether usable evidence was collected.
    assert "has_usable_evidence" in source
    # When evidence exists it uploads a completed+partial result, not failed.
    assert 'status="completed"' in source and "completed_with_warnings" in source
    # The old unconditional hard-fail string must be gone from the cap path.
    assert 'OpenVAS exceeded maximum runtime {max_scan_runtime_sec}s "\n                    f"while status=' not in source


def test_usable_evidence_predicate_counts_findings_ports_and_hosts():
    """The decision uses findings OR open ports OR assessed hosts."""
    src = inspect.getsource(main)
    # Locate the predicate line and confirm all three signals feed it.
    assert "has_usable_evidence = bool(cap_vulns) or cap_open_ports > 0 or int(cap_evidence.get(\"hosts_assessed\") or 0) > 0" in src


def test_partial_reason_marks_not_clean_eligible():
    src = inspect.getsource(main)
    assert "partial coverage kept, not clean-eligible" in src


def _simulate_cap_decision(vulns, open_ports, hosts_assessed):
    """Mirror the cap predicate exactly, to lock its truth table."""
    cap_open_ports = open_ports
    cap_vulns = vulns
    cap_evidence = {"hosts_assessed": hosts_assessed}
    has_usable_evidence = bool(cap_vulns) or cap_open_ports > 0 or int(cap_evidence.get("hosts_assessed") or 0) > 0
    return "completed" if has_usable_evidence else "failed"


def test_decision_truth_table():
    # 98% with findings and ports -> keep as completed/partial.
    assert _simulate_cap_decision(vulns=[{"id": 1}], open_ports=6, hosts_assessed=1) == "completed"
    # Ports but no findings (the screenshot case: 49 info, 6 open ports) -> keep.
    assert _simulate_cap_decision(vulns=[], open_ports=6, hosts_assessed=1) == "completed"
    # Hosts assessed but nothing else surfaced yet -> keep.
    assert _simulate_cap_decision(vulns=[], open_ports=0, hosts_assessed=1) == "completed"
    # Genuinely hung from the start: no evidence at all -> fail.
    assert _simulate_cap_decision(vulns=[], open_ports=0, hosts_assessed=0) == "failed"
