"""The audit must tell operators what was requested vs evidenced."""
from agent import service_audit as audit


def _sample():
    return {
        "status": "completed",
        "gmp_status": "done",
        "evidence": {"task_status": "done", "host_coverage": {"192.0.2.9": {"open_tcp_ports": [22, 443]}}},
        "vulnerabilities": [
            {"host": "192.0.2.9", "source_result_id": "ssh-critical", "port": 22, "protocol": "tcp",
             "service": "ssh", "plugin_name": "OpenSSH security update", "cvss": 9.8,
             "severity": "critical", "plugin_id": "1.3.6.1.4.1.25623.1.0.1"},
            {"host": "192.0.2.9", "source_result_id": "tls-info", "port": 443, "protocol": "tcp",
             "service": "https", "plugin_name": "TLS information", "cvss": 0,
             "severity": "info", "plugin_id": "1.3.6.1.4.1.25623.1.0.2"},
            {"host": "192.0.2.10", "source_result_id": "different-host", "port": 22,
             "protocol": "tcp", "service": "ssh", "cvss": 10, "severity": "critical"},
        ],
    }


def test_audit_only_native_result_severity_and_full_fifty_two():
    rows = audit.service_audit_rows("192.0.2.9", _sample())
    assert len(rows) == 52
    ssh = next(r for r in rows if r["service"] == "SSH: OpenSSH / Dropbear")
    assert ssh["status"] == "finding"
    assert ssh["max_severity"] == "Critical"
    assert ssh["native_result_count"] == 1
    assert ssh["severity_counts"]["Critical"] == 1
    smb = next(r for r in rows if r["service_id"] == "SVC-01")
    assert smb["status"] == "not-tested"
    assert smb["max_severity"] == "Not verified"
    assert not any("different-host" in r["source_result_ids"] for r in rows)


def test_open_port_does_not_imply_pass_or_severity():
    rows = audit.service_audit_rows("192.0.2.9", {
        "status": "completed", "evidence": {"host_coverage": {"192.0.2.9": {"open_tcp_ports": [445]}}},
        "vulnerabilities": [],
    })
    smb = next(r for r in rows if r["service_id"] == "SVC-01")
    assert smb["port_hint_count"] == 1
    assert smb["native_result_count"] == 0
    assert smb["status"] == "not-tested"
    assert smb["max_severity"] == "Not verified"


def test_emits_one_result_per_service_and_native_findings(monkeypatch):
    events = []
    monkeypatch.setattr(audit, "emit_ip_event", lambda job_id, host, event, **fields: events.append((event, fields)))
    monkeypatch.delenv("SERVICE_AUDIT_ENABLED", raising=False)
    monkeypatch.delenv("SERVICE_AUDIT_INCLUDE_UNTESTED", raising=False)
    monkeypatch.delenv("SERVICE_AUDIT_LOG_FINDINGS", raising=False)
    audit.emit_service_plan("job-1", "192.0.2.9", "task-1")
    assert len([x for x in events if x[0] == "service_planned"]) == 52
    audit.emit_service_results("job-1", "192.0.2.9", _sample(), "task-1")
    results = [x[1] for x in events if x[0] == "service_result"]
    assert len(results) == 52
    assert any(r["severity_counts"]["Critical"] > 0 for r in results)
    assert any(r["status"] == "not-tested" for r in results)
    findings = [x[1] for x in events if x[0] == "service_finding"]
    assert any(x["result_id"] == "ssh-critical" for x in findings)
    assert all(x["result_id"] != "different-host" for x in findings)
    assert events[-1][0] == "service_audit_summary"


def test_disable_service_audit(monkeypatch):
    monkeypatch.setenv("SERVICE_AUDIT_ENABLED", "false")
    monkeypatch.setattr(audit, "emit_ip_event", lambda *args, **kwargs: 1 / 0)
    audit.emit_service_plan("job-1", "192.0.2.9", "task-1")
    audit.emit_service_results("job-1", "192.0.2.9", _sample())


def test_unscored_is_not_critical():
    assert audit._severity({}) == "Unscored"
    assert audit._severity({"cvss": 0}) == "Info"
    assert audit._severity({"severity": "High", "cvss": 7.2}) == "High"
    assert audit._severity({"cvss": "invalid"}) == "Unscored"


def test_custom_score_bands_override_stale_native_label():
    assert audit._severity({"severity": "high", "cvss": 8.0}) == "Critical"
    assert audit._severity({"severity": "medium", "cvss": 6.0}) == "High"
    assert audit._severity({"severity": "high", "cvss": 5.9}) == "Medium"
    assert audit._severity({"severity": "medium", "cvss": 3.9}) == "Low"
    assert audit._severity({"severity": "info", "cvss": 0.0}) == "Info"
