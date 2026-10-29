"""V1.6.5 regression: field job d26e3145 / report 034bf5f5 on 192.168.0.163.

Field log (agent 1.6.4+v47.6):
  metadata ok details=False filter=first=1 rows=1
  result integrity full=11 filtered=11 materialized=11 parsed=11
      severity={'info': 8, 'medium': 2, 'low': 1}
  scan INCOMPLETE (degraded_no_ports) - no open ports enumerated and only 11 NVT(s) ran
  ... yet SERVICE_FINDING rows exist on 139/tcp and 445/tcp, pre-probe saw 135/139/445,
  completed plugin_errors=2, unmapped_native_results=8.

The three SMB rows are the real ones from the log. The titles of the eight
unmapped rows were never logged by 1.6.4, so the remaining rows below are
representative fixtures with the same severity histogram and port shape.
"""
from __future__ import annotations

from lxml import etree

from agent.gmp_local import _report_payload

HOST = "192.168.0.163"
REPORT = "034bf5f5-ff36-4f9f-ac7f-3935036b3b99"

# (result_id, oid, name, port, cvss)
ROWS = [
    ("31bdb35d-ae89-4b1b-99b5-71cc40906629", "1.3.6.1.4.1.25623.1.0.11011", "SMB/CIFS Server Detection", "445/tcp", "0.0"),
    ("cb7b696a-1648-4441-a522-70c6198db950", "1.3.6.1.4.1.25623.1.0.11011", "SMB/CIFS Server Detection", "139/tcp", "0.0"),
    ("dcdb2e0f-23f3-4621-b429-c5b298162f8e", "1.3.6.1.4.1.25623.1.0.807830", "SMB Remote Version Detection", "445/tcp", "0.0"),
    ("fx-rpc-medium", "1.3.6.1.4.1.25623.1.0.10736", "DCE/RPC and MSRPC Services Enumeration Reporting", "135/tcp", "5.0"),
    ("fx-smb-medium", "1.3.6.1.4.1.25623.1.0.999001", "SMB fixture medium finding", "445/tcp", "5.3"),
    ("fx-tcp-low", "1.3.6.1.4.1.25623.1.0.80091", "TCP Timestamps Information Disclosure", "general/tcp", "2.6"),
    ("fx-os", "1.3.6.1.4.1.25623.1.0.105937", "OS Detection Consolidation and Reporting", "general/tcp", "0.0"),
    ("fx-trace", "1.3.6.1.4.1.25623.1.0.51662", "Traceroute", "general/tcp", "0.0"),
    ("fx-hostname", "1.3.6.1.4.1.25623.1.0.108449", "Hostname Determination Reporting", "general/tcp", "0.0"),
    ("fx-cpe", "1.3.6.1.4.1.25623.1.0.810002", "CPE Inventory", "general/CPE-T", "0.0"),
    ("fx-summary", "1.3.6.1.4.1.25623.1.0.810003", "Host Summary", "general/tcp", "0.0"),
]

ERRORS = """
<errors><count>2</count>
  <error><host>192.168.0.163</host><port>445/tcp</port>
    <description>NVT timed out after 320 seconds.</description>
    <nvt oid="1.3.6.1.4.1.25623.1.0.999101"><name>SMB fixture slow check A</name></nvt></error>
  <error><host>192.168.0.163</host><port>445/tcp</port>
    <description>NVT timed out after 320 seconds.</description>
    <nvt oid="1.3.6.1.4.1.25623.1.0.999102"><name>SMB fixture slow check B</name></nvt></error>
</errors>
"""


def _results_xml() -> str:
    return "".join(
        f"""<result id="{rid}"><host>{HOST}</host><port>{port}</port>
              <nvt oid="{oid}"><name>{name}</name><family>General</family>
                <cvss_base>{cvss}</cvss_base><tags>summary={name}</tags></nvt>
              <severity>{cvss}</severity><threat>Log</threat>
              <qod><value>80</value></qod></result>"""
        for rid, oid, name, port, cvss in ROWS
    )


def _meta_xml() -> bytes:
    # details=False: counts only. No <results>, no host <detail>, no <error> rows.
    return f"""<get_reports_response><report id="{REPORT}"><report id="{REPORT}">
        <task id="c9fb3a80-5e47-4ade-b107-f6f9ce39c687"/>
        <scan_run_status>Done</scan_run_status>
        <scan_start>2026-10-14T01:51:25Z</scan_start><scan_end>2026-10-14T02:06:15Z</scan_end>
        <hosts><count>1</count></hosts>
        <host><ip>{HOST}</ip></host>
        <result_count><full>11</full><filtered>11</filtered></result_count>
        <errors><count>2</count></errors>
    </report></report></get_reports_response>""".encode()


def _detail_xml(host_ports_detail: bool = True) -> bytes:
    detail = (
        "<detail><name>ports</name><value>135,139,445</value></detail>"
        "<detail><name>tcp_ports</name><value>135,139,445</value></detail>"
        if host_ports_detail else ""
    )
    return f"""<get_reports_response><report id="{REPORT}"><report id="{REPORT}">
        <task id="c9fb3a80-5e47-4ade-b107-f6f9ce39c687"/>
        <scan_run_status>Done</scan_run_status>
        <scan_start>2026-10-14T01:51:25Z</scan_start><scan_end>2026-10-14T02:06:15Z</scan_end>
        <hosts><count>1</count></hosts>
        <host><ip>{HOST}</ip>
          <detail><name>best_os_cpe</name><value>cpe:/o:microsoft:windows</value></detail>
          {detail}
        </host>
        <result_count><full>11</full><filtered>11</filtered></result_count>
        {ERRORS}
        <results>{_results_xml()}</results>
    </report></report></get_reports_response>""".encode()


class FieldGmp:
    def __init__(self, host_ports_detail: bool = True):
        self.host_ports_detail = host_ports_detail
        self.calls: list[tuple[bool, str]] = []

    def get_task(self, task_id):
        return etree.fromstring(
            f"<get_tasks_response><task><status>Done</status><progress>-1</progress>"
            f"<current_report><report id='{REPORT}'/></current_report></task></get_tasks_response>".encode()
        )

    def get_report(self, **kwargs):
        details = bool(kwargs.get("details"))
        filt = str(kwargs.get("filter_string") or "")
        self.calls.append((details, filt))
        if not details:
            return etree.fromstring(_meta_xml())
        return etree.fromstring(_detail_xml(self.host_ports_detail))


def _run(gmp: FieldGmp):
    return _report_payload(
        gmp, "c9fb3a80-5e47-4ade-b107-f6f9ce39c687",
        expected_targets=[HOST], alive_test="Consider Alive", task_status="done", progress=100.0,
    )


def test_field_job_is_not_reported_as_no_open_ports():
    vulns, evidence = _run(FieldGmp())
    assert len(vulns) == 11
    cov = evidence["host_coverage"][HOST]
    assert cov["verdict"] != "degraded_no_ports"
    assert set(cov["open_tcp_ports"]) >= {135, 139, 445}
    assert "no open ports" not in cov["reason"]


def test_nvt_timeouts_are_warnings_not_port_scanner_failure():
    _, evidence = _run(FieldGmp())
    cov = evidence["host_coverage"][HOST]
    assert cov["port_scanner_errors"] == []
    assert cov["network_scan_complete"] is True
    assert cov["plugin_error_count"] == 2
    assert any("timed out" in w for w in cov["warnings"])
    # Still never a clean/verified claim: unauthenticated, warnings present.
    assert cov["coverage_complete"] is False
    assert evidence["clean_eligible"] is False


def test_error_details_come_from_the_detailed_page():
    _, evidence = _run(FieldGmp())
    names = {e["nvt_name"] for e in evidence["plugin_error_details"]}
    assert names == {"SMB fixture slow check A", "SMB fixture slow check B"}


def test_nvt_count_is_distinct_oids_not_result_rows():
    _, evidence = _run(FieldGmp())
    cov = evidence["host_coverage"][HOST]
    # 11 rows but SMB/CIFS Server Detection appears on two ports: 10 distinct NVTs.
    assert cov["nvts_evidenced"] == 10
    assert cov["results_evidenced"] == 11


def test_ports_from_results_alone_still_count_without_host_detail():
    _, evidence = _run(FieldGmp(host_ports_detail=False))
    cov = evidence["host_coverage"][HOST]
    assert set(cov["open_tcp_ports"]) == {135, 139, 445}
    assert cov["verdict"] == "observed_unverified"


def test_every_medium_and_low_is_attributed_to_a_service_or_host_bucket():
    _, evidence = _run(FieldGmp())
    svc = evidence["service_coverage"][HOST]
    by_id = {s["service_id"]: s for s in svc["services"]}
    assert "fx-rpc-medium" in by_id["SVC-02"]["finding_result_ids"]   # DCE/RPC on 135
    assert "fx-smb-medium" in by_id["SVC-01"]["finding_result_ids"]   # SMB on 445
    assert by_id["SVC-01"]["status"] == "finding"
    assert by_id["SVC-02"]["status"] == "finding"
    host_level = svc["host_level"]
    assert "fx-tcp-low" in host_level["finding_result_ids"]
    assert host_level["severity_counts"]["Low"] == 1
    mapped = {rid for s in svc["services"] for rid in s["source_result_ids"]}
    mapped |= set(host_level["source_result_ids"])
    assert {r[0] for r in ROWS} <= mapped, "no native result may be silently unattributed"


def test_merged_job_keeps_declared_error_count_and_network_complete_host():
    from agent.main import _merge_chunk_details

    _, evidence = _run(FieldGmp())
    vulns, _ = _run(FieldGmp())
    evidence["plugin_error_details"] = []  # e.g. detail page unreadable
    merged = _merge_chunk_details(
        [([HOST], {"status": "completed", "progress": 100, "vulnerabilities": vulns, "evidence": evidence})],
        all_targets=[HOST],
    )
    assert merged["evidence"]["plugin_error_count"] == 2
    assert merged["evidence"]["network_complete_hosts"] == [HOST]
    assert merged["evidence"]["degraded_hosts"] == []


def test_preprobe_port_missing_from_greenbone_becomes_a_warning():
    from agent.coverage_reconcile import reconcile_host_observations

    details = {"evidence": {"host_coverage": {HOST: {
        "verdict": "observed_unverified", "open_tcp_ports": [139, 445],
        "network_scan_complete": True, "warnings": []}}}}
    reconcile_host_observations(details, HOST, [135, 139, 445])
    cov = details["evidence"]["host_coverage"][HOST]
    assert cov["preprobe_only_ports"] == [135]
    assert any("135" in w for w in cov["warnings"])
    assert cov["network_scan_complete"] is True  # partial gap is a warning, not a failure

    details = {"evidence": {"host_coverage": {HOST: {
        "verdict": "degraded_no_ports", "open_tcp_ports": [], "network_scan_complete": False}}}}
    reconcile_host_observations(details, HOST, [445])
    assert details["evidence"]["host_coverage"][HOST]["verdict"] == "degraded_discovery_mismatch"


def test_report_diagnose_reclassifies_the_field_report(capsys):
    from agent.report_diagnose import _print_text, diagnose_report

    out = diagnose_report(FieldGmp(), REPORT)
    assert out["detail_page_available"] is True
    assert len(out["results"]) == 11
    assert {e["nvt_name"] for e in out["errors"]} == {"SMB fixture slow check A", "SMB fixture slow check B"}
    assert out["coverage"][HOST]["verdict"] == "observed_unverified"
    assert out["host_details"][HOST]["ports"] == "135,139,445"
    _print_text(out)
    text = capsys.readouterr().out
    assert "NVT timed out after 320 seconds" in text and "network_scan_complete=True" in text
