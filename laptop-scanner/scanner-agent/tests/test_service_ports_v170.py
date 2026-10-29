"""V1.7.0: service port policy, open/closed/filtered probe, no 'not tested' for closed services."""
from __future__ import annotations

import socket

import pytest

from agent import gmp_local, port_discovery, scan_performance as perf
from agent.coverage_reconcile import reconcile_host_observations
from agent.scan_performance import NvtHangRegistry
from agent.service_policy import analyze_services, policy_ports, service_port_policy, validate_request
from tests.test_speed_v167 import _loop

HOST = "172.20.10.2"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_TCP_CUSTOM_PORTS", "SCAN_UDP_CUSTOM_PORTS",
                "SERVICE_EXTRA_TCP_PORTS", "SERVICE_EXTRA_UDP_PORTS", "SCAN_PERFORMANCE", "SCAN_CHECK_SCOPE",
                "SCAN_IP_DEADLINE_SEC", "PORT_DISCOVERY_RANGE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "openvas.log"))
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- the policy ----------------------------------------------------------------------
def test_policy_is_the_nexus_scope_minus_ports_that_cannot_have_findings(monkeypatch):
    doc = service_port_policy()
    # V1.8.0 (policy 1.1): 28 services added for Nexpose Full-audit parity.
    assert len(doc["services"]) == 95
    assert all(s["low_plus_examples"] for s in doc["services"])
    tcp, udp = policy_ports()
    assert len(tcp) == 154 and len(udp) == 33
    assert 20 not in tcp and not {67, 68, 138, 4789, 5004} & set(udp)
    assert {"20/tcp", "67-68/udp", "138/udp", "4789/udp", "5004/udp"} <= {s["port"] for s in doc["not_checked"]}
    monkeypatch.setenv("UDP_PORT_RANGE", "U:67-69,U:4789,U:5004")  # Compose default; ignored for nexus
    p = gmp_local._effective_scan_policy(None, "nexus", "priority")
    assert p["tcp_port_count"] == 154 and p["udp_port_count"] == 33
    assert p["service_port_policy_version"] == "aetheris-service-ports-1.1"


def test_services_can_be_switched_off_and_extras_added(monkeypatch):
    p = gmp_local._effective_scan_policy({"disabled_services": ["vnc", "telnet"]}, "nexus", "priority")
    full = len(policy_ports()[0])
    assert p["tcp_port_count"] == full - 11  # 10 VNC ports + 23
    monkeypatch.setenv("SERVICE_EXTRA_TCP_PORTS", "8899")  # not a policy port
    assert gmp_local._effective_scan_policy(None, "nexus", "priority")["tcp_port_count"] == full + 1
    with pytest.raises(ValueError):
        validate_request({"disabled_services": ["not-a-service"]})


# --- the probe -----------------------------------------------------------------------------
def test_probe_keeps_open_closed_and_filtered_apart(monkeypatch):
    def fake_connect(addr, timeout=None):
        port = addr[1]
        if port == 445:
            class S:
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return S()
        if port == 135:
            raise ConnectionRefusedError()
        raise socket.timeout()

    monkeypatch.setattr(port_discovery.socket, "create_connection", fake_connect)
    states = port_discovery.probe_tcp_port_states([HOST], port_range="T:135,T:445,T:3389")
    assert states[HOST] == {"open": [445], "closed": [135], "filtered": [3389]}
    assert port_discovery.probe_open_tcp_ports([HOST], port_range="T:135,T:445,T:3389") == {HOST: [445]}


def test_probe_uses_policy_ports_for_nexus(monkeypatch):
    monkeypatch.setenv("PORT_PROFILE", "nexus")
    monkeypatch.setenv("PORT_DISCOVERY_RANGE", "T:22")  # must not narrow the policy probe
    assert len(port_discovery.parse_tcp_ports(port_discovery.candidate_range())) == len(policy_ports()[0])


# --- verdicts --------------------------------------------------------------------------------
def _degraded():
    return {"evidence": {"host_coverage": {HOST: {
        "verdict": "degraded_no_ports", "open_tcp_ports": [], "port_scanner_errors": [], "warnings": [],
        "network_scan_complete": False}}}}


def test_all_filtered_is_no_exposed_services_with_an_honest_reason():
    tcp, _ = policy_ports()
    d = reconcile_host_observations(_degraded(), HOST, [], {"open": [], "closed": [], "filtered": tcp})
    cov = d["evidence"]["host_coverage"][HOST]
    assert cov["verdict"] == "no_exposed_services" and cov["network_scan_complete"] is True
    assert cov["host_responded"] is False and "firewall" in cov["reason"]
    assert cov["port_state_counts"] == {"open": 0, "closed": 0, "filtered": len(tcp)}


def test_refused_ports_prove_the_host_is_up():
    d = reconcile_host_observations(_degraded(), HOST, [], {"open": [], "closed": [135, 445], "filtered": [22]})
    cov = d["evidence"]["host_coverage"][HOST]
    assert cov["verdict"] == "no_exposed_services" and cov["host_responded"] is True
    assert "2 of 3 policy TCP ports refused" in cov["reason"]


def test_no_verdict_change_without_evidence_or_with_scanner_errors():
    d = reconcile_host_observations(_degraded(), HOST, [], None)
    assert d["evidence"]["host_coverage"][HOST]["verdict"] == "degraded_no_ports"
    bad = _degraded()
    bad["evidence"]["host_coverage"][HOST]["port_scanner_errors"] = [{"nvt_name": "Nmap"}]
    d = reconcile_host_observations(bad, HOST, [], {"open": [], "closed": [445], "filtered": []})
    assert d["evidence"]["host_coverage"][HOST]["verdict"] == "degraded_no_ports"
    d = reconcile_host_observations(_degraded(), HOST, [445], {"open": [445], "closed": [], "filtered": []})
    assert d["evidence"]["host_coverage"][HOST]["verdict"] == "degraded_discovery_mismatch"


# --- service states: the screenshot case ------------------------------------------------------------
def _screenshot_case():
    tcp, udp = policy_ports()
    info_rows = [{"host": HOST, "result_id": f"i{n}", "plugin_name": name, "port": None, "severity": "info", "cvss": 0}
                 for n, name in enumerate(["OS Detection Consolidation and Reporting", "Host Summary", "CPE Inventory",
                                           "Hostname Determination Reporting", "Traceroute", "Host Details"])]
    d = reconcile_host_observations(_degraded(), HOST, [], {"open": [], "closed": [], "filtered": tcp})
    cov = d["evidence"]["host_coverage"][HOST]
    rng = ",".join([f"T:{p}" for p in tcp] + [f"U:{p}" for p in udp])
    return analyze_services(info_rows, host=HOST, coverage=cov, scanned_port_range=rng)


def test_screenshot_case_no_longer_says_51_not_tested():
    res = _screenshot_case()
    counts = res["counts"]
    assert counts["not-tested"] == 0
    assert counts["filtered"] >= 40  # every family with TCP ports: probed, nothing answered
    assert counts["unsupported"] == 1  # DHCP
    smb = next(s for s in res["services"] if s["service_id"] == "SVC-01")
    assert smb["status"] == "filtered" and "139, 445 did not answer" in smb["reason"]
    assert res["policy_summary"]["filtered"] > 40 and res["policy_summary"]["finding"] == 0


def test_policy_view_reports_open_ports_and_low_plus_findings():
    cov = {"open_tcp_ports": [445], "network_scan_complete": True,
           "port_states": {"tcp": {"445": "open", "139": "closed", "3389": "filtered"}}}
    rows = [{"host": HOST, "result_id": "m1", "plugin_name": "SMB signing not required", "port": 445,
             "protocol": "tcp", "severity": "medium", "cvss": 5.3},
            {"host": HOST, "result_id": "i1", "plugin_name": "SMB/CIFS Server Detection", "port": 445,
             "protocol": "tcp", "severity": "info", "cvss": 0}]
    res = analyze_services(rows, host=HOST, coverage=cov, scanned_port_range="T:139,T:445,T:3389")
    view = {s["key"]: s for s in res["policy_services"]}
    assert view["smb"]["state"] == "finding" and view["smb"]["severity_counts"]["Medium"] == 1
    assert view["smb"]["finding_result_ids"] == ["m1"]  # info rows never count as findings
    assert {p["port"]: p["state"] for p in view["smb"]["ports"]} == {"139/tcp": "closed", "445/tcp": "open"}
    assert view["rdp"]["state"] == "filtered"
    assert view["ssh"]["state"] == "not-in-policy"  # 22 not in this scan's range


# --- end to end through the job loop --------------------------------------------------------------------
def test_job_loop_turns_a_firewalled_host_into_no_exposed_services(monkeypatch):
    tcp, _ = policy_ports()
    monkeypatch.setattr(port_discovery, "probe_tcp_port_states",
                        lambda hosts, **kw: {h: {"open": [], "closed": [], "filtered": list(tcp)} for h in hosts})

    def poll(host, n, stopped):
        return {"status": "completed", "gmp_status": "done", "progress": 100, "vulnerabilities": [],
                "evidence": {"report_id": "r", "task_status": "done", "assessed_hosts": [host], "hosts_assessed": 1,
                             "assessment_complete": True, "scan_start": "s", "scan_end": "e",
                             "host_coverage": {host: {"verdict": "degraded_no_ports", "open_tcp_ports": [],
                                                      "port_scanner_errors": [], "warnings": []}}}}

    monkeypatch.setenv("PORT_PROFILE", "nexus")
    uploaded, events, _, _ = _loop(monkeypatch, [HOST], poll, env={"PORT_DISCOVERY_ENABLED": "true"})
    cov = uploaded[-1]["host_coverage"][HOST]
    assert cov["verdict"] == "no_exposed_services"
    disc = [kw for h, e, kw in events if e == "port_discovery"]
    assert disc and disc[0]["filtered_port_count"] == len(policy_ports()[0]) and disc[0]["closed_port_count"] == 0
