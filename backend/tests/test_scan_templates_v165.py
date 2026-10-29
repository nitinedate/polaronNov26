"""V1.6.5 central: network-complete hosts, Nessus templates, policy validation."""
from __future__ import annotations

import filecmp
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services.scan_orchestrator import scan_job_progress
from app.services.scanner_agent_jobs import classify_host_coverage

FIELD = "192.168.0.163"


def _field_cov(**over):
    cov = {
        "verdict": "observed_unverified",
        "network_scan_complete": True,
        "open_tcp_ports": [135, 139, 445],
        "nvts_evidenced": 10,
        "results_evidenced": 11,
        "warnings": ["SMB check A on 445/tcp: NVT timed out after 320 seconds.",
                     "SMB check B on 445/tcp: NVT timed out after 320 seconds."],
        "coverage_complete": False,
        "reason": "Network scan finished: 3 open TCP / 0 UDP port(s)",
    }
    cov.update(over)
    return cov


def test_field_host_is_completed_with_warnings_not_incomplete():
    tp, degraded, done = classify_host_coverage({FIELD: _field_cov()}, {})
    assert degraded == [] and done == [FIELD]
    row = tp[FIELD]
    assert row["status"] == "completed"
    # V1.10.3: warnings no longer change the label; the count stays in the activity.
    assert row["activity"].startswith("Completed - network scan finished, 3 open TCP")
    assert "check warning(s)" in row["activity"]
    assert "unauthenticated checks" in row["activity"]  # V1.8.0 wording
    assert row["coverage"]["open_tcp_port_list"] == [135, 139, 445]
    assert len(row["warnings"]) == 2


def test_old_agent_without_network_flag_stays_incomplete():
    tp, degraded, done = classify_host_coverage({FIELD: _field_cov(network_scan_complete=None)}, {})
    assert degraded == [FIELD] and done == []
    assert tp[FIELD]["status"] == "incomplete"


def test_degraded_verdicts_stay_incomplete_with_reason():
    for verdict in ("degraded_no_ports", "degraded_port_scan_failed", "degraded_discovery_mismatch"):
        tp, degraded, _ = classify_host_coverage(
            {FIELD: _field_cov(verdict=verdict, network_scan_complete=False, reason="why")}, {})
        assert degraded == [FIELD]
        assert tp[FIELD]["activity"] == "Incomplete — why"


def test_existing_target_progress_fields_are_preserved():
    tp, _, _ = classify_host_coverage({FIELD: _field_cov()}, {FIELD: {"progress_pct": 100, "engines": {"x": 1}}})
    assert tp[FIELD]["progress_pct"] == 100 and tp[FIELD]["engines"] == {"x": 1}


def test_job_label_says_complete_with_warnings():
    job = {"status": "completed", "orchestration_json": {
        "edge_agent": True, "degraded_hosts": [], "network_complete_hosts": [FIELD],
        "completed_with_warnings": True}}
    label = scan_job_progress(None, job)["progress_label"]
    assert label.startswith("Complete") and "warnings" not in label  # V1.10.3
    job["orchestration_json"]["degraded_hosts"] = [FIELD]
    assert "1 host(s) incomplete" in scan_job_progress(None, job)["progress_label"]


def test_policy_settings_are_validated_and_template_intent_stored(monkeypatch):
    from app.routers import vuln

    stored = vuln._validated_policy_settings({"udp_profile": "off"}, "basic_network")
    assert stored == {"udp_profile": "off", "template": "basic_network"}
    with pytest.raises(HTTPException) as err:
        vuln._validated_policy_settings({"scan_config": "Everything"})
    assert err.value.status_code == 400
    with pytest.raises(HTTPException):
        vuln._validated_policy_settings({}, "no_such_template")


def test_template_endpoint_lists_nessus_equivalents(monkeypatch):
    from app.routers import vuln

    monkeypatch.setattr(vuln, "_require_vuln_module", lambda: None)
    rows = vuln.list_policy_templates(current=None)
    keys = {r["key"] for r in rows}
    assert {"host_discovery", "basic_network", "advanced", "credentialed_patch_audit",
            "web_app_tests", "internal_pci", "threat_ms17_010"} <= keys
    audit = next(r for r in rows if r["key"] == "credentialed_patch_audit")
    assert audit["requires_credentials"] == ["smb", "ssh"]
    basic = next(r for r in rows if r["key"] == "basic_network")
    assert basic["settings"]["port_profile"] == "nexus" and basic["settings"]["optimize_test"] == "yes"


def test_credential_gap_blocks_patch_audit_without_reference():
    from app.services.scanner_service_policy import credential_gap, validate_request

    assert credential_gap(validate_request({"template": "credentialed_patch_audit"}))
    assert credential_gap(validate_request({"template": "basic_network"})) is None


def test_central_policy_module_matches_the_agent_copy():
    """Agent and central must interpret settings and attribution identically."""
    root = Path(__file__).resolve().parents[2]
    agent = root / "laptop-scanner" / "scanner-agent" / "agent"
    central = root / "backend" / "app" / "services"
    if not agent.is_dir():
        pytest.skip("laptop-scanner tree not present in this checkout")
    assert filecmp.cmp(agent / "service_policy.py", central / "scanner_service_policy.py", shallow=False)
    assert filecmp.cmp(agent / "scan_templates.json", central / "scan_templates.json", shallow=False)
    assert filecmp.cmp(agent / "service_catalog.json", central / "service_catalog.json", shallow=False)
    assert filecmp.cmp(agent / "service_port_policy.json", central / "service_port_policy.json", shallow=False)
