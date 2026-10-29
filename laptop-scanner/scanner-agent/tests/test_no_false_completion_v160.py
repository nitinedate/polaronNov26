"""V1.6.0 checks: no deadline-based false success or lane evidence promotion."""
from agent.service_lanes import merge_service_lane_polls


def _part(status, port=None):
    return {"status": status, "progress": 100, "vulnerabilities": [], "evidence": {
        "host_coverage": {"192.0.2.5": {
            "host": "192.0.2.5",
            "verdict": "observed_unverified" if port else "degraded_no_ports",
            "reason": "observed" if port else "port scanner did not verify scope",
            "open_tcp_ports": [port] if port else [], "coverage_complete": False,
            "service_checks_verified": False,
        }}
    }}


def test_failed_lane_cannot_look_completed():
    result = merge_service_lane_polls([_part("completed", 443), _part("failed")])
    assert result["status"] == "failed"
    assert result["evidence"]["assessment_complete"] is False
    assert result["evidence"]["host_coverage"]["192.0.2.5"]["coverage_complete"] is False
    assert result["evidence"]["host_coverage"]["192.0.2.5"]["verdict"] == "observed_unverified"


def test_stopped_lane_cannot_look_completed():
    result = merge_service_lane_polls([_part("completed", 443), _part("stopped")])
    assert result["status"] == "stopped"


def test_all_lanes_complete_is_engine_complete_only():
    result = merge_service_lane_polls([_part("completed", 443), _part("completed")])
    assert result["status"] == "completed"
    assert result["evidence"]["host_coverage"]["192.0.2.5"]["coverage_complete"] is False


def test_running_lane_is_still_running():
    assert merge_service_lane_polls([_part("completed", 443), _part("running")])["status"] == "running"
