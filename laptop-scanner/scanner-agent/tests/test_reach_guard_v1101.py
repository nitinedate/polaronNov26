"""V1.10.1 — job 6bee3375: all 25 IPs "No TCP port answered", although an earlier job
found open ports and findings on the same IPs. When no target answers and none is on
the laptop's own network, nothing was assessed: the job fails with that reason."""
from __future__ import annotations

from agent import main
from agent.reach_guard import unreachable_network_error

SILENT = {"verdict": "no_exposed_services", "host_responded": False, "network_scan_complete": True}
TARGETS = ["192.168.1.128", "192.168.1.169", "192.168.1.31"]
OTHER_LAN = {"gateway": "192.168.0.1", "subnet": "192.168.0.0/24", "source": "host"}
SAME_LAN = {"gateway": "192.168.1.1", "subnet": "192.168.1.0/24", "source": "host"}


def _ev(cov=None):
    return {"host_coverage": cov if cov is not None else {h: dict(SILENT) for h in TARGETS}}


def test_all_silent_targets_off_the_laptops_network_are_not_an_assessment():
    msg = unreachable_network_error(_ev(), OTHER_LAN)
    assert msg.startswith("Nothing was assessed: none of the 3 IPs answered")
    assert "192.168.0.0/24, gateway 192.168.0.1" in msg


def test_silent_targets_on_the_laptops_own_network_stay_a_result():
    assert unreachable_network_error(_ev(), SAME_LAN) is None


def test_one_host_that_answered_keeps_the_job_a_result():
    cov = {h: dict(SILENT) for h in TARGETS}
    cov["192.168.1.31"] = {"verdict": "no_exposed_services", "host_responded": True}
    assert unreachable_network_error(_ev(cov), OTHER_LAN) is None
    cov["192.168.1.31"] = {"verdict": "observed_unverified", "open_tcp_ports": [445]}
    assert unreachable_network_error(_ev(cov), OTHER_LAN) is None


def test_unknown_lan_self_scan_or_single_ip_is_left_alone():
    assert unreachable_network_error(_ev(), {}) is None
    cov = {h: dict(SILENT) for h in TARGETS}
    cov["192.168.1.31"]["self_scan"] = {"scanned_via": "192.168.65.254"}
    assert unreachable_network_error(_ev(cov), OTHER_LAN) is None
    assert unreachable_network_error(_ev({"192.168.1.128": dict(SILENT)}), OTHER_LAN) is None


def test_completed_payload_becomes_failed_with_the_reason(monkeypatch):
    monkeypatch.setattr("agent.lan_fingerprint.capture_lan_fingerprint", lambda: dict(OTHER_LAN))
    details = {"vulnerabilities": [], "evidence": dict(_ev(), task_status="Done", assessed_hosts=TARGETS)}
    payload = main._result_payload(details=details, task_id="t", status="completed", partial=True,
                                   partial_reason="x")
    assert payload["status"] == "failed" and payload["partial"] is False
    assert payload["error"].startswith("Nothing was assessed")
    monkeypatch.setattr("agent.lan_fingerprint.capture_lan_fingerprint", lambda: dict(SAME_LAN))
    payload = main._result_payload(details=details, task_id="t", status="completed")
    assert payload["status"] == "completed" and payload["error"] is None


def test_docker_nat_fingerprint_is_not_taken_for_the_laptops_lan():
    nat = {"gateway": "172.17.0.1", "subnet": "172.17.0.0/24", "source": "proc"}
    assert unreachable_network_error(_ev(), nat) is None
