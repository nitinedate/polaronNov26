"""V1.10.6: Merge gap reports by scan job (several jobs of one case, or of several cases)."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from fastapi import HTTPException

import app.services.gap_assessment_report as gap
import app.services.gap_merge_jobs as gmj

CASE = "53d96f29-0000-0000-0000-000000000001"
OTHER_CASE = "77777777-0000-0000-0000-000000000002"
J1 = "d2068523-1111-1111-1111-111111111111"
J2 = "3df13145-2222-2222-2222-222222222222"
J3 = "fcbb90c0-3333-3333-3333-333333333333"


# --- candidates -------------------------------------------------------------------------------
def test_window_rules():
    assert gmj.merge_window(None, None) == (None, None)
    assert gmj.merge_window("2026-10-15", "") == (date(2026, 10, 15), None)
    with pytest.raises(gmj.MergeDateError) as bad:
        gmj.merge_window("2026-10-16", "2026-10-01")
    assert bad.value.code == "invalid_date_range"
    with pytest.raises(gmj.MergeDateError):
        gmj.merge_window("16/10/2026", None)


def _job_row(jid, case_id=CASE, started=datetime(2026, 10, 16, 6, 39, tzinfo=timezone.utc), status="completed"):
    return {"job_id": jid, "case_id": case_id, "status": status, "started_at": started,
            "completed_at": started, "created_at": started, "scan_ist_date": started.date(),
            "case_title": "RRP-Oct-2026_1", "case_number": None, "target_count": 25,
            "gap_site_json": {"client_name": "RRP Electronics", "branch_locations": "Mahape", "author": "Bhagyesh Sawant"}}


def test_candidates_list_jobs_of_one_case_newest_first_with_counts(monkeypatch):
    sql_seen = []

    def fake_fetchone(db, sql, params=None):
        sql_seen.append(("one", sql, dict(params or {})))
        return {"c": 3}

    def fake_fetchall(db, sql, params=None):
        sql_seen.append(("all", sql, dict(params or {})))
        if "FROM vuln_findings" in sql:
            return [{"scan_job_id": J1, "severity": "high", "c": 7}, {"scan_job_id": J1, "severity": "medium", "c": 33},
                    {"scan_job_id": J2, "severity": "info", "c": 4}]
        return [_job_row(J1), _job_row(J2), _job_row(J3, started=datetime(2026, 10, 15, 6, 0, tzinfo=timezone.utc))]

    monkeypatch.setattr(gmj, "fetchone", fake_fetchone)
    monkeypatch.setattr(gmj, "fetchall", fake_fetchall)
    monkeypatch.setattr(gmj, "ist_today", lambda: date(2026, 10, 16))
    out = gmj.list_merge_job_candidates(object())
    assert [i["job_id"] for i in out["items"]] == [J1, J2, J3]
    assert {i["case_id"] for i in out["items"]} == {CASE}  # one case, three mergeable jobs
    assert out["items"][0]["severity_counts"]["high"] == 7 and out["items"][2]["severity_counts"]["high"] == 0
    assert out["items"][0]["day_label"] == "today" and out["items"][2]["day_label"] == "yesterday"
    assert out["items"][0]["gap_details"]["client_name"] == "RRP Electronics"
    assert out["limit"] == 20 and out["filtered"] is False
    list_sql = sql_seen[1][1]
    assert "j.status IN ('completed', 'incomplete')" in list_sql and "c.gap_site_json <> '{}'::jsonb" in list_sql
    assert "ORDER BY COALESCE(j.completed_at, j.started_at, j.created_at) DESC" in list_sql
    assert sql_seen[1][2]["lim"] == 20 and ":from_d" not in list_sql


def test_candidates_date_filter_uses_scan_day(monkeypatch):
    seen = {}
    monkeypatch.setattr(gmj, "fetchone", lambda db, sql, params=None: seen.setdefault("count", (sql, params)) and {"c": 0})
    monkeypatch.setattr(gmj, "fetchall", lambda db, sql, params=None: [])
    out = gmj.list_merge_job_candidates(object(), from_date="2026-10-15", to_date="2026-10-16")
    sql, params = seen["count"]
    assert "COALESCE(j.started_at, j.created_at)" in sql and params == {"from_d": "2026-10-15", "to_d": "2026-10-16"}
    assert out["filtered"] is True and out["limit"] == 200 and out["items"] == []


# --- merged context by job -------------------------------------------------------------------
def _stub_merge(monkeypatch, refs):
    calls = {"inventory": [], "assessment": [], "coverage": []}
    monkeypatch.setattr(gap, "fetchall", lambda db, sql, params=None: refs)
    monkeypatch.setattr(gap, "fetchone", lambda db, sql, params=None: {"endpoint_count": 31})
    monkeypatch.setattr(gap, "load_case_row", lambda db, cid: {"id": cid, "title": "RRP-Oct-2026_1"})
    monkeypatch.setattr(gap, "load_gap_site", lambda db, cid: {"client_name": "RRP Electronics", "num_endpoints": "",
                                                               "key_contacts": [], "has_saved_intake": True})

    def inventory(db, cid, scan_job_id=None):
        calls["inventory"].append((cid, scan_job_id))
        host = {J1: "192.168.1.71", J2: "192.168.1.164"}.get(scan_job_id, "10.0.0.1")
        finding = {"name": "SMB signing not required", "risk": "Medium", "description": "d", "remediation": "r",
                   "port": 445, "protocol": "tcp", "hosts": [host]}
        return {"findings": [finding], "informational_findings": [],
                "finding_summary": {"Medium": 1, "total": 1, "actionable": 1}}

    def assessment(db, cid, scan_job_id=None):
        calls["assessment"].append((cid, scan_job_id))
        return {"verified": True, "clean_eligible": True, "target_count": 25, "hosts_attempted": 6, "hosts_assessed": 6}

    def coverage(db, *, case_id, scan_job_id=None):
        calls["coverage"].append((case_id, scan_job_id))
        return []

    monkeypatch.setattr(gap, "load_gap_finding_inventory", inventory)
    monkeypatch.setattr(gap, "load_case_scan_assessment", assessment)
    monkeypatch.setattr(gap, "load_service_coverage", coverage)
    return calls


def test_two_jobs_of_one_case_merge_into_one_report(monkeypatch):
    refs = [{"id": J2, "case_id": CASE, "status": "completed"}, {"id": J1, "case_id": CASE, "status": "completed"}]
    calls = _stub_merge(monkeypatch, refs)
    ctx = gap.build_merged_gap_report_context(object(), use_llm=False, job_ids=[J1, J2, J1])
    assert ctx["scan_job_ids"] == [J1, J2] and ctx["case_ids"] == [CASE]
    assert calls["inventory"] == [(CASE, J1), (CASE, J2)]
    assert calls["assessment"] == [(CASE, J1), (CASE, J2)] and calls["coverage"] == [(CASE, J1), (CASE, J2)]
    # identical finding on two jobs -> one finding with both IPs
    assert len(ctx["findings"]) == 1 and ctx["findings"][0]["hosts"] == ["192.168.1.164", "192.168.1.71"]
    assert ctx["finding_summary"]["Medium"] == 2
    assert ctx["site"]["num_endpoints"] == "31"  # distinct targets across both jobs, not 25 + 25
    assert "jobs" in ctx["assessment"]["message"]
    assert [j["job_id"] for j in ctx["merged_jobs"]] == [J1, J2]


def test_jobs_from_two_cases_and_validation(monkeypatch):
    refs = [{"id": J1, "case_id": CASE, "status": "completed"}, {"id": J3, "case_id": OTHER_CASE, "status": "incomplete"}]
    _stub_merge(monkeypatch, refs)
    ctx = gap.build_merged_gap_report_context(object(), use_llm=False, job_ids=[J1, J3])
    assert ctx["case_ids"] == [CASE, OTHER_CASE]
    with pytest.raises(ValueError, match="at least two scan jobs"):
        gap.build_merged_gap_report_context(object(), use_llm=False, job_ids=[J1, J1])
    _stub_merge(monkeypatch, [{"id": J1, "case_id": CASE, "status": "completed"}])
    with pytest.raises(ValueError, match="Scan job not found: 3df13145"):
        gap.build_merged_gap_report_context(object(), use_llm=False, job_ids=[J1, J2])


def test_case_merge_still_works(monkeypatch):
    calls = _stub_merge(monkeypatch, [])
    monkeypatch.setattr(gap, "_derive_case_endpoint_count", lambda db, cid: 9)
    ctx = gap.build_merged_gap_report_context(object(), [CASE, OTHER_CASE], use_llm=False)
    assert ctx["scan_job_ids"] == [] and calls["inventory"] == [(CASE, None), (OTHER_CASE, None)]
    assert "cases" in ctx["assessment"]["message"]


def test_export_names_the_merged_jobs(monkeypatch):
    _stub_merge(monkeypatch, [{"id": J1, "case_id": CASE}, {"id": J2, "case_id": CASE}])
    monkeypatch.setattr(gap, "render_gap_docx", lambda ctx: b"DOCX")
    _, _, name = gap.export_merged_gap_report(object(), fmt="docx", use_llm=False, job_ids=[J1, J2])
    assert name == "gap-assessment-RRP-Electronics-merged-2-jobs.docx"


# --- router ------------------------------------------------------------------------------------
def test_merge_solution_rows_appends_hosts_and_keeps_different_findings():
    from app.services.vuln_report_export import merge_solution_rows

    job_a = [
        {
            "Risk": "High",
            "Host": "192.168.1.1",
            "Protocol": "tcp",
            "Port": 22,
            "Name": "Open SSH",
            "Synopsis": "Open SSH",
            "Description": "SSH exposed",
            "Solution": "Restrict SSH",
        }
    ]
    job_b = [
        {
            "Risk": "High",
            "Host": "10.0.0.5",
            "Protocol": "TCP",
            "Port": 22,
            "Name": "Open SSH",
            "Synopsis": "Open SSH",
            "Description": "SSH exposed",
            "Solution": "Restrict SSH",
        },
        {
            "Risk": "Medium",
            "Host": "10.0.0.5",
            "Protocol": "tcp",
            "Port": 443,
            "Name": "Weak TLS",
            "Synopsis": "Weak TLS",
            "Description": "TLS 1.0 enabled",
            "Solution": "Disable TLS 1.0",
        },
    ]
    merged = merge_solution_rows([job_a, job_b])
    by_name = {row["Name"]: row for row in merged}
    assert set(by_name) == {"Open SSH", "Weak TLS"}
    assert by_name["Open SSH"]["Host"] == "10.0.0.5, 192.168.1.1"
    assert by_name["Weak TLS"]["Host"] == "10.0.0.5"
    assert [row["Name"] for row in merged] == ["Open SSH", "Weak TLS"]


def test_merged_solution_xlsx_combines_job_workbooks(monkeypatch):
    from io import BytesIO

    from openpyxl import load_workbook

    import app.services.vuln_report_export as vre

    monkeypatch.setattr(
        gap,
        "load_merge_job_refs",
        lambda db, job_ids: [{"id": J1, "case_id": CASE}, {"id": J2, "case_id": CASE}],
    )

    def rows(db, *, case_id, scan_job_id=None):
        host = "192.168.1.71" if scan_job_id == J1 else "192.168.1.164"
        shared = {
            "severity": "medium",
            "cvss": 5.0,
            "synopsis": "SMB signing not required",
            "description": "Signing is not required",
            "remediation": "Require signing",
            "port": 445,
            "protocol": "tcp",
            "cve": None,
            "host": host,
        }
        if scan_job_id == J2:
            return [
                shared,
                {
                    **shared,
                    "synopsis": "Weak TLS",
                    "description": "TLS 1.0",
                    "remediation": "Disable TLS 1.0",
                    "port": 443,
                    "host": host,
                },
            ]
        return [shared]

    monkeypatch.setattr(vre, "_open_finding_rows", rows)
    data, media, name = vre.export_merged_solution_xlsx(object(), job_ids=[J1, J2])
    assert media.startswith("application/vnd.openxmlformats")
    assert name == "Solution Set-merged-2-jobs.xlsx"
    ws = load_workbook(BytesIO(data)).active
    assert [c.value for c in ws[1][:8]] == list(vre.XLSX_COLUMNS)
    body = {(ws.cell(row=i, column=5).value, ws.cell(row=i, column=2).value) for i in range(2, 4)}
    assert body == {
        ("SMB signing not required", "192.168.1.164, 192.168.1.71"),
        ("Weak TLS", "192.168.1.164"),
    }
    assert ws.column_dimensions["B"].width > vre.XLSX_COL_WIDTHS["B"]


def test_router_merged_xlsx_accepts_job_ids(monkeypatch):
    from app.routers import vuln_orchestrator as vo

    monkeypatch.setattr(vo, "_require_vuln_module", lambda: None)
    seen = {}

    def fake_export(db, case_ids=None, *, job_ids=None):
        seen.update(case_ids=case_ids, job_ids=job_ids)
        return b"PK", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Solution Set-merged-2-jobs.xlsx"

    monkeypatch.setattr(vo, "export_merged_solution_xlsx", fake_export)
    resp = vo.export_merged_gap_report_xlsx(case_ids=None, job_ids=f"{J1},{J2.upper()}", db=object(), current=None)
    assert resp.body == b"PK" and seen == {"case_ids": None, "job_ids": [J1, J2]}
    assert "Solution Set-merged-2-jobs.xlsx" in resp.headers["content-disposition"]
    vo.export_merged_gap_report_xlsx(case_ids=f"{CASE},{OTHER_CASE}", job_ids=None, db=object(), current=None)
    assert seen["case_ids"] == [CASE, OTHER_CASE] and seen["job_ids"] is None
    for bad in ({"case_ids": None, "job_ids": None}, {"case_ids": None, "job_ids": "nope,also-nope"}):
        with pytest.raises(HTTPException) as exc:
            vo.export_merged_gap_report_xlsx(**bad, db=object(), current=None)
        assert exc.value.status_code == 400


def test_router_merged_pdf_accepts_job_ids(monkeypatch):
    from app.routers import vuln_orchestrator as vo

    monkeypatch.setattr(vo, "_require_vuln_module", lambda: None)
    seen = {}

    def fake_export(db, case_ids=None, *, fmt, use_llm, job_ids=None):
        seen.update(case_ids=case_ids, job_ids=job_ids)
        return b"%PDF", "application/pdf", "gap-merged.pdf"

    monkeypatch.setattr(vo, "export_merged_gap_report", fake_export)
    resp = vo.export_merged_gap_report_pdf(case_ids=None, job_ids=f"{J1},{J2.upper()}", llm=None, db=object(), current=None)
    assert resp.body == b"%PDF" and seen == {"case_ids": None, "job_ids": [J1, J2]}
    vo.export_merged_gap_report_pdf(case_ids=f"{CASE},{OTHER_CASE}", job_ids=None, llm=None, db=object(), current=None)
    assert seen["case_ids"] == [CASE, OTHER_CASE] and seen["job_ids"] is None
    for bad in ({"case_ids": None, "job_ids": None}, {"case_ids": None, "job_ids": "nope,also-nope"}):
        with pytest.raises(HTTPException) as exc:
            vo.export_merged_gap_report_pdf(**bad, llm=None, db=object(), current=None)
        assert exc.value.status_code == 400


def test_router_job_candidates_reports_bad_dates(monkeypatch):
    from app.routers import vuln_orchestrator as vo

    monkeypatch.setattr(vo, "_require_vuln_module", lambda: None)
    monkeypatch.setattr(gap, "ensure_gap_site_column", lambda db: None)
    with pytest.raises(HTTPException) as exc:
        vo.list_gap_merge_jobs(from_date="2026-10-16", to_date="2026-10-01", limit=None, db=object(), current=None)
    assert exc.value.status_code == 400 and exc.value.detail["error"]["code"] == "invalid_date_range"
