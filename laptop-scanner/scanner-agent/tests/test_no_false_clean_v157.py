"""Regression checks for the 2026-10-13 zero-ports / false-coverage incident."""

from lxml import etree
from agent.coverage_reconcile import reconcile_host_observations
from agent.gmp_local import LocalOpenVAS, _coverage_includes_parsed_results
from agent.network_diagnostics import _ports, probe_target
from agent.scan_coverage import coverage_from_report


def test_env_yes_cannot_optimize_nexus_tests(monkeypatch):
    """V1.6.5: Nessus parity. Nessus ships optimize_test=yes; OpenVAS yes still runs
    every NVT whose required ports/services were detected. An explicit
    GVM_OPTIMIZE_TEST=no restores the pre-1.6.5 forced behaviour."""
    monkeypatch.setenv("PORT_PROFILE", "nexus")
    monkeypatch.setenv("GVM_OPTIMIZE_TEST", "yes")
    assert LocalOpenVAS().optimize_test == "yes"
    monkeypatch.setenv("GVM_OPTIMIZE_TEST", "no")
    assert LocalOpenVAS().optimize_test == "no"


def test_env_yes_allowed_for_explicit_fast_profile(monkeypatch):
    monkeypatch.setenv("PORT_PROFILE", "fast")
    monkeypatch.setenv("GVM_OPTIMIZE_TEST", "yes")
    assert LocalOpenVAS().optimize_test == "yes"


def test_one_finding_is_not_full_catalog_completion():
    evidence = {"host_coverage": {"192.0.2.4": {"verdict": "degraded_no_ports", "open_tcp_ports": [], "nvts_launched": 0}}}
    _coverage_includes_parsed_results(evidence, [{"host": "192.0.2.4", "port": 443, "protocol": "tcp", "severity": "critical"}])
    cov = evidence["host_coverage"]["192.0.2.4"]
    assert cov["verdict"] == "observed_unverified"
    assert cov["coverage_complete"] is False
    assert cov["open_tcp_ports"] == [443]


def test_mismatch_requires_incomplete_state():
    result = {"evidence": {"host_coverage": {"192.0.2.5": {"verdict": "degraded_no_ports", "open_tcp_ports": []}}}}
    reconcile_host_observations(result, "192.0.2.5", [3389, 445])
    cov = result["evidence"]["host_coverage"]["192.0.2.5"]
    assert cov["verdict"] == "degraded_discovery_mismatch"
    assert cov["greenbone_tcp_ports"] == []
    assert cov["preprobe_tcp_ports"] == [445, 3389]
    assert cov["coverage_complete"] is False


def test_no_mismatch_with_native_port_proof():
    result = {"evidence": {"host_coverage": {"192.0.2.5": {"verdict": "observed_unverified", "open_tcp_ports": [445]}}}}
    reconcile_host_observations(result, "192.0.2.5", [445])
    assert result["evidence"]["host_coverage"]["192.0.2.5"]["verdict"] == "observed_unverified"


def test_no_ports_no_false_clean():
    coverage = coverage_from_report(etree.fromstring('<report><results/></report>'), host='192.0.2.10')
    assert coverage["coverage_complete"] is False
    assert coverage["verdict"] == "degraded_no_ports"


def test_diagnostic_ports_strictly_bounded():
    assert _ports("22,443,443") == [22, 443]
    import pytest
    with pytest.raises(ValueError):
        _ports("1-65535")
    with pytest.raises(ValueError):
        _ports("0,80")


def test_diagnostic_classifies_refused_without_vulnerability_claim(monkeypatch):
    import socket
    def refused(*args, **kwargs):
        raise ConnectionRefusedError("Connection refused")
    monkeypatch.setattr(socket, "create_connection", refused)
    result = probe_target("192.0.2.1", [443])
    assert result["counts"]["refused"] == 1
    assert result["open_ports"] == []
    assert result["vulnerability_checks_verified"] is False


def test_diagnostic_reports_actual_local_listener():
    import socket
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = probe_target("127.0.0.1", [port], timeout=0.5)
    assert result["open_ports"] == [port]
    assert result["vulnerability_checks_verified"] is False


def test_build_stamp_identifies_new_fix():
    from agent import AGENT_BUILD
    assert AGENT_BUILD == '1.10.3-v63.0'
