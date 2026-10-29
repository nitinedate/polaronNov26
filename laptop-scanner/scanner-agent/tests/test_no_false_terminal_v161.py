"""Regression: a quiet 95% GMP task cannot be converted into successful completion."""

from agent.main import _env_stall_sec, seal_tail_harvest
from agent.service_policy import effective_policy, service_catalog, port_numbers


def test_full_profile_includes_all_fifty_two_catalog_port_hints(monkeypatch):
    monkeypatch.delenv("SCAN_TCP_CUSTOM_PORTS", raising=False)
    monkeypatch.delenv("SCAN_UDP_CUSTOM_PORTS", raising=False)
    policy = effective_policy({"port_profile": "full", "udp_profile": "priority"})
    included_tcp = {n for token in policy["port_range"].split(",") if token.startswith("T:") for n in port_numbers(token[2:])}
    included_udp = {n for token in policy["port_range"].split(",") if token.startswith("U:") for n in port_numbers(token[2:])}
    catalog = service_catalog()["services"]
    assert len(catalog) == 52
    assert policy["tcp_port_count"] == 65535
    assert all(set(service["tcp_hints"]) <= included_tcp for service in catalog)
    assert all(set(service["udp_hints"]) <= included_udp for service in catalog)
    # Port-range inclusion only proves the requested scope; it does not
    # establish that a vulnerability NVT completed for each family.


def test_stale_positive_tail_timeout_never_promotes_running(monkeypatch):
    monkeypatch.setenv("HIGH_PROGRESS_STALL_SEC", "45")
    assert _env_stall_sec() == 45  # diagnostic threshold only
    details = {
        "status": "running", "progress": 97,
        "vulnerabilities": [{"host": "192.0.2.11", "port": 445, "severity": "medium"}],
        "evidence": {"task_status": "running", "report_id": "report-1", "assessment_complete": False},
    }
    assert seal_tail_harvest(details, "192.0.2.11", reason="stuck 45 seconds") is False
    assert details["status"] == "running"
    assert details["evidence"]["assessment_complete"] is False
