"""V1.10.3: OS identification is not a port scanner; 5-IP and 6-port semaphores."""
import threading
import time

import pytest

from agent import port_discovery, scan_performance
from agent.coverage_reconcile import reconcile_host_observations
from agent.scan_coverage import coverage_from_report, is_port_scanner_error

OS_IDENT = {"host": "192.168.0.163", "nvt_oid": "1.3.6.1.4.1.25623.1.0.108021",
            "nvt_name": "Nmap OS Identification (NASL wrapper)", "description": "NVT timed out after 90 seconds."}


def test_only_real_port_scanners_count():
    assert not is_port_scanner_error(OS_IDENT["nvt_oid"], OS_IDENT["nvt_name"], OS_IDENT["description"])
    assert not is_port_scanner_error("", "Service Detection (wrapped) with nmap", "NVT timed out after 900 seconds.")
    assert not is_port_scanner_error("1.3.6.1.4.1.25623.1.0.100186", "Nagios / Nagios Core Detection (HTTP)",
                                     "NVT timed out after 90 seconds.")
    assert is_port_scanner_error("1.3.6.1.4.1.25623.1.0.14259", "Nmap (NASL wrapper)", "NVT timed out")
    assert is_port_scanner_error("", "Ping Host", "")
    assert is_port_scanner_error("", "OpenVAS TCP scanner", "")


def test_field_report_b6b7f60c_is_a_finished_network_scan():
    etree = pytest.importorskip("lxml.etree")
    xml = ("<report><results>"
           "<result><host>192.168.0.163</host><port>445/tcp</port><nvt oid='1.3.6.1.4.1.25623.1.0.11011'/></result>"
           "<result><host>192.168.0.163</host><port>8090/tcp</port><nvt oid='1.3.6.1.4.1.25623.1.0.117761'/></result>"
           "</results></report>")
    cov = coverage_from_report(etree.fromstring(xml), host="192.168.0.163", errors=[dict(OS_IDENT)])
    assert cov["port_scanner_errors"] == []
    assert cov["other_errors"] == 1
    assert cov["verdict"] == "observed_unverified"


def test_real_port_scanner_timeout_is_still_incomplete():
    etree = pytest.importorskip("lxml.etree")
    err = dict(OS_IDENT, nvt_oid="1.3.6.1.4.1.25623.1.0.14259", nvt_name="Nmap (NASL wrapper)")
    cov = coverage_from_report(etree.fromstring("<report><results/></report>"), host="192.168.0.163", errors=[err])
    assert cov["verdict"] == "degraded_port_scan_failed"


def test_preprobe_agreement_reconciles_a_port_scanner_warning():
    def details(native):
        return {"evidence": {"host_coverage": {"h": {
            "verdict": "degraded_port_scan_failed", "open_tcp_ports": native, "network_scan_complete": False,
            "port_scanner_errors": [{"nvt_name": "Nmap (NASL wrapper)"}]}}}}
    ok = reconcile_host_observations(details([139, 445, 8090]), "h", [139, 445, 8090],
                                     {"open": [139, 445, 8090], "filtered": [21, 22]})
    cov = ok["evidence"]["host_coverage"]["h"]
    assert cov["verdict"] == "observed_unverified" and cov["network_scan_complete"] is True
    missed = reconcile_host_observations(details([445]), "h", [22, 445], {"open": [22, 445]})
    assert missed["evidence"]["host_coverage"]["h"]["verdict"] == "degraded_port_scan_failed"


def test_semaphore_defaults_and_stale_env(monkeypatch):
    for key in ("SCAN_IP_SEMAPHORE", "SCAN_IP_WORKERS_FIXED", "SCAN_PORT_SEMAPHORE",
                "SCAN_SERVICE_PARALLELISM", "SCAN_PERFORMANCE"):
        monkeypatch.delenv(key, raising=False)
    assert scan_performance.fixed_ip_workers() == 5
    assert scan_performance.port_semaphore() == 6
    assert scan_performance.per_ip_check_concurrency("standard") == 6
    # A laptop .env still holding the old values does not override the new semaphores.
    monkeypatch.setenv("SCAN_IP_WORKERS_FIXED", "4")
    monkeypatch.setenv("SCAN_SERVICE_PARALLELISM", "4")
    monkeypatch.setenv("SCAN_IP_SEMAPHORE", "5")
    monkeypatch.setenv("SCAN_PORT_SEMAPHORE", "6")
    assert scan_performance.fixed_ip_workers() == 5
    assert scan_performance.per_ip_check_concurrency("standard") == 6


def test_preprobe_keeps_six_connects_per_ip(monkeypatch):
    monkeypatch.delenv("SCAN_PORT_SEMAPHORE", raising=False)
    monkeypatch.delenv("SCAN_SERVICE_PARALLELISM", raising=False)
    lock, inflight, peak = threading.Lock(), {}, {}

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_connect(addr, timeout=None):
        host, port = addr
        with lock:
            inflight[host] = inflight.get(host, 0) + 1
            peak[host] = max(peak.get(host, 0), inflight[host])
        time.sleep(0.03)
        with lock:
            inflight[host] -= 1
        if port % 2:
            raise ConnectionRefusedError()
        return _Conn()

    monkeypatch.setattr(port_discovery.socket, "create_connection", fake_connect)
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    result = port_discovery.probe_tcp_port_states(hosts, port_range="T:1-60")
    assert all(peak[h] <= 6 for h in hosts)
    assert max(peak.values()) == 6
    assert len(result["10.0.0.1"]["open"]) == 30 and len(result["10.0.0.1"]["closed"]) == 30


def test_port_semaphore_caps_turbo_and_fast(monkeypatch):
    """Field .env: SCAN_PERFORMANCE=turbo ran 10-40 checks per IP; the semaphore makes it 6."""
    monkeypatch.setenv("SCAN_PERFORMANCE", "turbo")
    monkeypatch.setenv("SCAN_PORT_SEMAPHORE", "6")
    monkeypatch.setenv("TURBO_MAX_CHECKS", "40")
    for profile in ("turbo", "fast", "standard"):
        assert scan_performance.per_ip_check_concurrency(profile) == 6
    assert scan_performance.profile_settings("turbo")["max_checks"] == 6
    assert scan_performance.profile_settings("fast")["max_checks"] == 6
