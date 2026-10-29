"""V1.6.5 service attribution: every native result lands somewhere, nothing is invented."""
from agent.service_policy import STATUSES, analyze_services, attribute_row

H = "192.0.2.20"


def _row(rid, title, port=None, proto="tcp", cvss=0.0, sev=None):
    return {"host": H, "source_result_id": rid, "plugin_name": title, "port": port,
            "protocol": proto if port else None, "cvss": cvss,
            "severity": sev or ("medium" if cvss >= 4 else "low" if cvss > 0 else "info")}


def _svc(result, key):
    return next(s for s in result["services"] if s["service_id"] == key)


def test_word_boundaries_stop_substring_misattribution():
    assert "SVC-42" not in attribute_row(_row("a", "lighttpd Detection"))[0]   # not Apache HTTPD
    assert "SVC-07" not in attribute_row(_row("b", "TFTP Server Detection"))[0]  # not FTP
    assert "SVC-07" not in attribute_row(_row("c", "SFTP Supported Algorithms"))[0]
    assert "SVC-17" in attribute_row(_row("d", "TFTP Server Detection"))[0]
    assert "SVC-46" not in attribute_row(_row("e", "Unlike-named banner check"))[0]  # 'ike' inside a word


def test_openvas_dce_rpc_wording_maps_to_rpc():
    keys, method = attribute_row(_row("r", "DCE/RPC and MSRPC Services Enumeration Reporting", 135, cvss=5.0))
    assert keys == {"SVC-02"}
    assert "title_or_protocol" in method


def test_tls_on_rdp_port_is_both_tls_and_rdp():
    keys, _ = attribute_row(_row("t", "SSL/TLS: Report Weak Cipher Suites", 3389, cvss=5.9))
    assert {"SVC-10", "SVC-05"} <= keys


def test_port_owner_only_for_results_actually_on_that_port():
    keys, method = attribute_row(_row("w", "Microsoft Windows Remote Code Execution (KB000)", 445, cvss=8.1))
    assert keys == {"SVC-01"} and method == "port_owner"
    # Product families sharing a port are never routed by port number.
    keys, _ = attribute_row(_row("j", "Unknown banner", 8080))
    assert keys == {"SVC-09"}  # protocol owner HTTP, not Tomcat/Jenkins/JBoss


def test_general_rows_go_to_host_level_and_unknown_ports_to_other():
    rows = [
        _row("low", "TCP Timestamps Information Disclosure", None, cvss=2.6),
        _row("os", "OS Detection Consolidation and Reporting"),
        _row("odd", "Unknown service on high port", 5040),
    ]
    res = analyze_services(rows, host=H, coverage={"open_tcp_ports": [5040]})
    assert res["host_level"]["finding_result_ids"] == ["low"]
    assert res["host_level"]["severity_counts"]["Low"] == 1
    assert res["other_ports"]["source_result_ids"] == ["odd"]
    assert res["other_ports"]["ports"] == ["5040/tcp"]


def test_not_observed_needs_completed_network_scan_and_known_range():
    cov = {"open_tcp_ports": [135, 139, 445], "network_scan_complete": True}
    known = analyze_services([], host=H, coverage=cov, scanned_port_range="T:1-1024,T:3389,U:161")
    assert _svc(known, "SVC-05")["status"] == "not-observed"       # 3389 scanned, closed
    assert _svc(known, "SVC-15")["status"] == "not-observed"       # UDP 161 scanned
    assert "filtered" in _svc(known, "SVC-15")["reason"]
    assert _svc(known, "SVC-32")["status"] == "not-in-scope"       # 6443 not scanned
    assert _svc(known, "SVC-01")["status"] == "not-tested"         # 445 open, no result
    unknown = analyze_services([], host=H, coverage=cov, scanned_port_range=None)
    assert _svc(unknown, "SVC-05")["status"] == "not-tested"
    unfinished = analyze_services([], host=H, coverage={"open_tcp_ports": [445]},
                                  scanned_port_range="T:1-65535")
    assert _svc(unfinished, "SVC-05")["status"] == "not-tested"


def test_wmi_explains_credential_requirement_when_135_open():
    res = analyze_services([], host=H, coverage={"open_tcp_ports": [135], "network_scan_complete": True},
                           scanned_port_range="T:135")
    wmi = _svc(res, "SVC-03")
    assert wmi["status"] == "not-tested"
    assert "credentials" in wmi["reason"]


def test_counts_cover_every_status_and_sum_to_52():
    res = analyze_services([], host=H, coverage={"network_scan_complete": True}, scanned_port_range="T:1-65535")
    assert set(res["counts"]) == set(STATUSES)
    assert sum(res["counts"].values()) == 52
    assert res["coverage_complete"] is False
    assert all(s["status"] != "passed" for s in res["services"])


def test_other_hosts_rows_are_ignored():
    rows = [_row("x", "SMB/CIFS Server Detection", 445)]
    rows[0]["host"] = "192.0.2.99"
    res = analyze_services(rows, host=H, coverage={})
    assert _svc(res, "SVC-01")["source_result_ids"] == []
    assert res["host_level"]["source_result_ids"] == []
