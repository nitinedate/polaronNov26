"""V1.10.3: central re-check of 'coverage incomplete' caused by Nmap OS Identification."""
from app.services.scanner_coverage_rules import (effective_degraded_hosts, effective_network_complete_hosts,
                                                 normalize_host_coverage)

FIELD = {"verdict": "degraded_port_scan_failed", "open_tcp_ports": [445, 8090], "network_scan_complete": False,
         "port_scanner_errors": [{"nvt_oid": "1.3.6.1.4.1.25623.1.0.108021",
                                  "nvt_name": "Nmap OS Identification (NASL wrapper)",
                                  "description": "NVT timed out after 90 seconds."}]}


def test_os_identification_timeout_is_a_warning():
    cov = normalize_host_coverage(dict(FIELD))
    assert cov["verdict"] == "observed_unverified"
    assert cov["network_scan_complete"] is True
    assert any("Nmap OS Identification" in w for w in cov["warnings"])


def test_real_failures_stay_incomplete():
    real = dict(FIELD, port_scanner_errors=[{"nvt_oid": "1.3.6.1.4.1.25623.1.0.14259",
                                              "nvt_name": "Nmap (NASL wrapper)"}])
    assert normalize_host_coverage(real)["verdict"] == "degraded_port_scan_failed"
    assert normalize_host_coverage(dict(FIELD, open_tcp_ports=[]))["verdict"] == "degraded_port_scan_failed"


def test_stored_job_reads_complete():
    orch = {"degraded_hosts": ["192.168.0.163"], "network_complete_hosts": [],
            "host_coverage": {"192.168.0.163": dict(FIELD)}}
    assert effective_degraded_hosts(orch) == []
    assert effective_network_complete_hosts(orch) == ["192.168.0.163"]
