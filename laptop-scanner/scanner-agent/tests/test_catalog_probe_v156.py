"""Three log rows are not a catalog vulnerability scan."""
from agent.gmp_local import _coverage_includes_parsed_results


def test_hostname_traceroute_and_os_rows_do_not_count_as_service_coverage():
    evidence = {
        "plugin_error_count": 0,
        "task_status": "done",
        "host_coverage": {
            "192.168.0.164": {
                "verdict": "degraded_no_ports",
                "open_tcp_ports": [],
                "open_udp_ports": [],
                "nvts_launched": 0,
            }
        },
    }
    vulns = [
        {"host": "192.168.0.164", "severity": "log", "plugin_name": name}
        for name in (
            "Hostname Determination Reporting",
            "OS Detection Consolidation and Reporting",
            "Traceroute",
        )
    ]
    _coverage_includes_parsed_results(evidence, vulns)
    coverage = evidence["host_coverage"]["192.168.0.164"]
    assert coverage["verdict"] == "degraded_no_ports"
    assert "no open listeners" in coverage["reason"]
    assert coverage["open_tcp_ports"] == []


def test_an_open_port_still_records_the_listener():
    evidence = {
        "plugin_error_count": 0,
        "task_status": "done",
        "host_coverage": {
            "192.168.0.1": {
                "verdict": "degraded_no_ports",
                "open_tcp_ports": [],
                "nvts_launched": 0,
            }
        },
    }
    _coverage_includes_parsed_results(
        evidence,
        [{"host": "192.168.0.1", "port": 22, "protocol": "tcp", "severity": "medium", "plugin_name": "SSH"}],
    )
    coverage = evidence["host_coverage"]["192.168.0.1"]
    assert coverage["open_tcp_ports"] == [22]
    assert coverage["verdict"] == "observed_unverified"
    assert coverage["coverage_complete"] is False
