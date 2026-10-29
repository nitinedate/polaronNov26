"""V1.6.6: scan policies accept a validated speed setting."""
import pytest
from fastapi import HTTPException


def test_policy_speed_is_validated():
    from app.routers import vuln

    assert vuln._validated_policy_settings({"performance": "fast"}, "basic_network") == {
        "performance": "fast", "template": "basic_network"}
    assert vuln._validated_policy_settings({"performance": "standard"})["performance"] == "standard"
    with pytest.raises(HTTPException) as err:
        vuln._validated_policy_settings({"performance": "turbo"})
    assert err.value.status_code == 400


def test_speed_survives_into_the_agent_request_and_snapshot_fields():
    from app.services.scanner_service_policy import SNAPSHOT_FIELDS, effective_policy, validate_request

    assert validate_request({"template": "advanced", "performance": "fast"})["performance"] == "fast"
    assert effective_policy({"performance": "fast"})["performance"] == "fast"
    assert {"performance", "performance_status", "nvt_timeout_caps"} <= SNAPSHOT_FIELDS


def test_time_limited_host_is_finished_with_explicit_wording():
    from app.services.scanner_agent_jobs import classify_host_coverage

    cov = {"verdict": "observed_unverified", "network_scan_complete": True, "time_limited": True,
           "time_limit_sec": 900, "stopped_at_progress": 94, "open_tcp_ports": [135, 139, 445],
           "warnings": ["Per-IP time limit (15 min) reached at 94%: ..."]}
    tp, degraded, done = classify_host_coverage({"192.168.0.163": cov}, {})
    row = tp["192.168.0.163"]
    assert degraded == [] and done == ["192.168.0.163"]
    assert row["activity"].startswith("Completed at time limit - stopped after 15 min at 94%")
    assert row["coverage"]["time_limited"] is True


def test_time_limit_before_port_scan_is_incomplete():
    from app.services.scanner_agent_jobs import classify_host_coverage

    cov = {"verdict": "degraded_time_limit", "network_scan_complete": False, "time_limited": True,
           "reason": "Per-IP time limit (900s) reached at 5% before port scanning finished"}
    tp, degraded, _ = classify_host_coverage({"h": cov}, {})
    assert degraded == ["h"] and tp["h"]["status"] == "incomplete"


def test_policy_check_scope_is_validated():
    from app.routers import vuln

    assert vuln._validated_policy_settings({"check_scope": "vulnerability"})["check_scope"] == "vulnerability"
    with pytest.raises(HTTPException):
        vuln._validated_policy_settings({"check_scope": "info_only"})
