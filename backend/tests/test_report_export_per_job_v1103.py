"""V1.10.3: Reports & export per scan job (Excel/CSV, coverage CSV, summary, gap PDF/DOCX)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.services.gap_assessment_report as gap
import app.services.scan_assessment_evidence as sae
import app.services.vuln_report_export as vre

CASE = "00000000-0000-0000-0000-00000000c0de"
JOB = "11111111-2222-3333-4444-555555555555"


class _Recorder:
    def __init__(self, rows=None, one=None):
        self.calls: list[tuple[str, dict]] = []
        self.rows = rows if rows is not None else []
        self.one = one

    def fetchall(self, db, sql, params=None):
        self.calls.append((sql, dict(params or {})))
        return list(self.rows)

    def fetchone(self, db, sql, params=None):
        self.calls.append((sql, dict(params or {})))
        return self.one


def test_job_kw_only_passes_a_selected_job():
    assert vre.job_kw(None) == {} and vre.job_kw("") == {} and vre.job_kw("  ") == {}
    assert vre.job_kw(JOB) == {"scan_job_id": JOB}


def test_solution_rows_are_filtered_by_job_only_when_selected(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(vre, "fetchall", rec.fetchall)
    vre._open_finding_rows(object(), case_id=CASE)
    vre._open_finding_rows(object(), case_id=CASE, scan_job_id=JOB)
    (case_sql, case_params), (job_sql, job_params) = rec.calls
    assert "scan_job_id" not in case_sql and "jid" not in case_params
    assert "f.scan_job_id = CAST(:jid AS uuid)" in job_sql and job_params["jid"] == JOB


def test_excel_and_csv_pass_the_job_through(monkeypatch):
    seen = []

    def rows(db, *, case_id, scan_job_id=None):
        seen.append(scan_job_id)
        return [{"severity": "high", "cvss": 7.5, "synopsis": "SMB signing not required", "description": "",
                 "remediation": "", "port": 445, "protocol": "tcp", "cve": None, "host": "192.168.1.71"}]

    monkeypatch.setattr(vre, "_open_finding_rows", rows)
    assert vre.export_case_xlsx(object(), case_id=CASE, scan_job_id=JOB)[:2] == b"PK"
    csv_text = vre.export_case_csv(object(), case_id=CASE, scan_job_id=JOB)
    assert "192.168.1.71" in csv_text
    vre.export_case_csv(object(), case_id=CASE)
    assert seen == [JOB, JOB, None]


def test_summary_counts_and_correlations_are_per_job(monkeypatch):
    rec = _Recorder(rows=[{"severity": "high", "scan_engine": "openvas", "c": 7}], one={"total": 2, "multi": 1})
    monkeypatch.setattr(vre, "fetchall", rec.fetchall)
    monkeypatch.setattr(vre, "fetchone", rec.fetchone)
    out = vre.export_case_summary(object(), case_id=CASE, scan_job_id=JOB)
    assert out["scan_job_id"] == JOB and out["findings_by_severity"] == {"high": 7}
    assert out["findings_by_engine"] == {"openvas": 7} and out["correlation_groups"] == 2
    sev_sql, eng_sql, corr_sql = rec.calls[0][0], rec.calls[1][0], rec.calls[2][0]
    assert "scan_job_id = CAST(:jid AS uuid)" in sev_sql and "scan_job_id = CAST(:jid AS uuid)" in eng_sql
    assert "EXISTS" in corr_sql and "f.scan_job_id = CAST(:jid AS uuid)" in corr_sql
    cov_sql, cov_params = rec.calls[3]
    assert "FROM vuln_scan_jobs" in cov_sql and "id = CAST(:jid AS uuid)" in cov_sql and cov_params["jid"] == JOB


def test_case_summary_unchanged_without_job(monkeypatch):
    rec = _Recorder(rows=[], one={"total": 0, "multi": 0})
    monkeypatch.setattr(vre, "fetchall", rec.fetchall)
    monkeypatch.setattr(vre, "fetchone", rec.fetchone)
    out = vre.export_case_summary(object(), case_id=CASE)
    assert out["scan_job_id"] is None
    assert all(":jid" not in sql for sql, _ in rec.calls)


def test_gap_findings_and_assessment_are_per_job(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(gap, "fetchall", rec.fetchall)
    gap._load_open_finding_rows(object(), CASE, JOB)
    assert "f.scan_job_id = CAST(:jid AS uuid)" in rec.calls[0][0]

    calls = []
    monkeypatch.setattr(sae, "fetchone", lambda db, sql, params=None: calls.append((sql, params)) or None)
    out = sae.load_case_scan_assessment(object(), CASE, JOB)
    assert out["state"] == "not_performed"
    assert "j.id = CAST(:jid AS uuid)" in calls[0][0] and calls[0][1]["jid"] == JOB


def _stub_gap(monkeypatch, job_row):
    captured: dict = {}
    monkeypatch.setattr(gap, "load_case_row", lambda db, cid: {"id": cid, "title": "RRP-Oct-2026_1"})
    monkeypatch.setattr(gap, "load_scan_job_row", lambda db, cid, jid: job_row)
    monkeypatch.setattr(gap, "load_gap_site", lambda db, cid: {"client_name": "RRP", "num_endpoints": "",
                                                               "key_contacts": [], "has_saved_intake": True})
    monkeypatch.setattr(gap, "_derive_case_endpoint_count", lambda db, cid: 99)

    def job_count(db, cid, jid):
        captured["endpoint_job"] = jid
        return 25

    monkeypatch.setattr(gap, "_derive_job_endpoint_count", job_count)

    def inventory(db, cid, scan_job_id=None):
        captured["inventory_job"] = scan_job_id
        return {"findings": [], "informational_findings": [], "finding_summary": {}}

    def assessment(db, cid, scan_job_id=None):
        captured["assessment_job"] = scan_job_id
        return {}

    def coverage(db, *, case_id, scan_job_id=None):
        captured["coverage_job"] = scan_job_id
        return []

    monkeypatch.setattr(gap, "load_gap_finding_inventory", inventory)
    monkeypatch.setattr(gap, "load_case_scan_assessment", assessment)
    monkeypatch.setattr(gap, "load_service_coverage", coverage)
    return captured


def test_gap_context_uses_only_the_selected_job(monkeypatch):
    captured = _stub_gap(monkeypatch, {"id": JOB, "status": "completed"})
    ctx = gap.build_gap_report_context(object(), CASE, use_llm=False, scan_job_id=JOB)
    assert ctx["scan_job_id"] == JOB and ctx["scan_job"]["status"] == "completed"
    assert ctx["site"]["num_endpoints"] == "25"  # the job's 25 targets, not the case's 99 assets
    assert captured == {"endpoint_job": JOB, "inventory_job": JOB, "assessment_job": JOB, "coverage_job": JOB}


def test_gap_context_without_job_is_case_wide(monkeypatch):
    captured = _stub_gap(monkeypatch, None)
    ctx = gap.build_gap_report_context(object(), CASE, use_llm=False)
    assert ctx["scan_job_id"] is None and ctx["site"]["num_endpoints"] == "99"
    assert captured == {"inventory_job": None, "assessment_job": None, "coverage_job": None}


def test_gap_context_rejects_a_job_from_another_case(monkeypatch):
    _stub_gap(monkeypatch, None)
    with pytest.raises(ValueError, match="Scan job not found"):
        gap.build_gap_report_context(object(), CASE, use_llm=False, scan_job_id=JOB)


def test_gap_export_filename_names_the_job(monkeypatch):
    _stub_gap(monkeypatch, {"id": JOB, "status": "completed"})
    monkeypatch.setattr(gap, "render_gap_docx", lambda ctx: b"DOCX")
    data, media, name = gap.export_gap_report(object(), CASE, fmt="docx", use_llm=False, scan_job_id=JOB)
    assert data == b"DOCX" and name == f"gap-assessment-RRP-job-{JOB[:8]}.docx"


# --- router -------------------------------------------------------------------------------------
def test_router_validates_the_job(monkeypatch):
    from app.routers import vuln_orchestrator as vo

    assert vo._job_or_none(object(), CASE, None) is None
    assert vo._job_or_none(object(), CASE, "all") is None
    with pytest.raises(HTTPException) as bad:
        vo._job_or_none(object(), CASE, "not-a-uuid")
    assert bad.value.status_code == 400
    monkeypatch.setattr(vo, "fetchone", lambda db, sql, params=None: None)
    with pytest.raises(HTTPException) as missing:
        vo._job_or_none(object(), CASE, JOB)
    assert missing.value.status_code == 404
    monkeypatch.setattr(vo, "fetchone", lambda db, sql, params=None: {"id": JOB})
    assert vo._job_or_none(object(), CASE, JOB.upper()) == JOB


def test_router_excel_and_gap_pdf_use_the_job(monkeypatch):
    from app.routers import vuln_orchestrator as vo

    monkeypatch.setattr(vo, "_require_vuln_module", lambda: None)
    monkeypatch.setattr(vo, "fetchone", lambda db, sql, params=None: {"id": JOB})
    seen = {}
    monkeypatch.setattr(vo, "export_case_xlsx", lambda db, *, case_id, scan_job_id=None: seen.setdefault("x", scan_job_id) or b"PK")
    resp = vo.export_vuln_report_xlsx(CASE, scan_job_id=JOB, db=object(), current=None)
    assert seen["x"] == JOB and f"Solution Set-{CASE[:8]}-job-{JOB[:8]}.xlsx" in resp.headers["content-disposition"]

    def fake_gap(db, case_id, *, fmt, use_llm, scan_job_id=None):
        seen["gap"] = (fmt, scan_job_id)
        return b"%PDF", "application/pdf", "gap.pdf"

    monkeypatch.setattr(vo, "export_gap_report", fake_gap)
    vo.export_gap_report_pdf(CASE, llm=None, scan_job_id=JOB, db=object(), current=None)
    assert seen["gap"] == ("pdf", JOB)
    resp = vo.export_vuln_report_xlsx(CASE, scan_job_id=None, db=object(), current=None)
    assert f'Solution Set-{CASE[:8]}.xlsx"' in resp.headers["content-disposition"]
