"""V1.6.9 central: new template purposes and relabelled threat checks."""
from app.services.scanner_agent_jobs import classify_host_coverage


def test_ping_only_alive_host_is_completed():
    tp, degraded, _ = classify_host_coverage({"h": {"verdict": "discovery_alive", "scan_purpose": "ping_discovery"}}, {})
    assert degraded == [] and tp["h"]["status"] == "completed"
    assert tp["h"]["activity"].startswith("Alive - answered the ping")


def test_credential_validation_reports_login_results():
    cov = {"verdict": "observed_unverified", "network_scan_complete": True, "open_tcp_ports": [445],
           "scan_purpose": "credential_validation", "auth_status": {"smb": "success", "ssh": "failure"}}
    tp, _, _ = classify_host_coverage({"h": cov}, {})
    assert tp["h"]["activity"].startswith("Credential check - SMB login succeeded, SSH login failed")
    cov["auth_status"] = {}
    tp, _, _ = classify_host_coverage({"h": cov}, {})
    assert "no login result reported" in tp["h"]["activity"]


def test_template_list_marks_threat_checks_as_not_nessus(monkeypatch):
    from app.routers import vuln

    monkeypatch.setattr(vuln, "_require_vuln_module", lambda: None)
    rows = {r["key"]: r for r in vuln.list_policy_templates(current=None)}
    for key in ("ping_discovery", "credential_validation", "advanced_dynamic", "policy_compliance"):
        assert rows[key]["nessus_template"]
    assert rows["threat_ms17_010"]["nessus_template"] is None
    assert rows["threat_ms17_010"]["name"].startswith("Threat check:")
    assert rows["advanced_dynamic"]["settings"]["nvt_filter"] == {"min_severity": 7.0}
    assert rows["credential_validation"]["requires_credentials"] == ["smb", "ssh"]
