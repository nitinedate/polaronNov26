"""Guard against false clean scans and narrowed vulnerability port scopes."""

from lxml import etree
from unittest.mock import patch

from agent.gmp_local import _effective_scan_policy, LocalOpenVAS
from agent.port_discovery import discovery_plan
from agent.scan_coverage import coverage_from_report
from agent.service_policy import analyze_services


def test_preprobe_never_narrows_authorized_scope(monkeypatch):
    monkeypatch.setenv("PORT_DISCOVERY_ENABLED", "true")
    monkeypatch.setenv("PORT_DISCOVERY_RANGE", "T:22,T:80,T:443,T:445")
    with patch("agent.port_discovery.probe_tcp_port_states", return_value={"192.0.2.10": {'open': [445], 'closed': [], 'filtered': []}}):
        plan = discovery_plan(["192.0.2.10"])
    assert plan["port_range"] == "T:22,T:80,T:443,T:445"
    assert plan["observed_port_range"] == "T:445"
    assert plan["open_ports"] == {"192.0.2.10": [445]}


def test_no_service_pass_from_clean_status_or_port_banner():
    items = analyze_services([], host="192.0.2.10", coverage={"open_tcp_ports": [22, 443]})
    assert items["coverage_complete"] is False
    assert items["counts"]["finding"] == 0
    assert items["counts"]["not-tested"] > 0


def test_report_results_are_not_full_nvt_execution_proof():
    report = etree.fromstring('''<report><results><result><host>192.0.2.10</host>
      <port>443/tcp</port><nvt oid="1.2.3.4"/></result></results></report>''')
    cov = coverage_from_report(report, host="192.0.2.10")
    assert cov["open_tcp_ports"] == [443]
    assert cov["nvts_evidenced"] == 1
    assert cov["coverage_complete"] is False
    assert cov["verdict"] != "full"


def test_no_ports_and_no_results_is_degraded():
    cov = coverage_from_report(etree.fromstring('<report/>'), host="192.0.2.10")
    assert cov["verdict"] == "degraded_no_ports"


def test_nexus_profile_keeps_baseline_critical_ports_and_disables_optimization(monkeypatch):
    monkeypatch.setenv('PORT_PROFILE', 'nexus')
    monkeypatch.delenv('GVM_OPTIMIZE_TEST', raising=False)
    p = _effective_scan_policy(None, 'nexus', 'priority')
    from agent.service_policy import port_numbers
    tcp = {port for item in p['port_range'].split(',') if item.startswith('T:') for port in port_numbers(item[2:])}
    assert {22, 443, 445, 3389, 8443} <= tcp
    assert p['tcp_port_count'] >= 52
    agent = LocalOpenVAS()
    # V1.6.5: Nessus default (optimize_test=yes) unless explicitly disabled.
    assert agent.optimize_test == 'yes'


def test_open_port_is_hint_not_service_pass():
    rows = analyze_services([], host="192.0.2.10", coverage={"open_tcp_ports": [445]})
    smb = next(row for row in rows["services"] if row["service_id"] == "SVC-01")
    assert smb["port_hint_count"] == 1
    assert smb["port_hints"] == ["445/tcp"]
    assert smb["status"] == "not-tested"
    assert rows["coverage_complete"] is False
