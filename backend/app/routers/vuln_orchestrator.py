"""Multi-scanner orchestration and solution-set report APIs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.scan_orchestrator import DEFAULT_PIPELINE
from app.services.gap_assessment_report import export_gap_report, export_merged_gap_report
from app.services.gap_report_bundle import export_case_gap_bundle
from app.services.vuln_nessus_parity import compare_nessus_csv
from app.services.vuln_report_export import (
    export_case_csv,
    export_case_summary,
    export_case_xlsx,
    export_merged_solution_xlsx,
    export_service_coverage_csv,
    load_service_coverage,
    import_solution_csv,
)

router = APIRouter(tags=["vuln-orchestrator"])


def _require_vuln_module() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(status_code=404, detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}})


# V1.10.3: every report/export below takes an optional ``scan_job_id``. Without
# it the whole case is exported (previous behaviour); with it only that job's
# findings, coverage and scan assessment are used.
JOB_QUERY = Query(None, description="Optional scan job UUID of this case; omit to export the whole case.")


def _job_or_none(db: Session, case_id: str, scan_job_id: str | None) -> str | None:
    """Validate that the job belongs to the case. Returns the canonical id or None."""
    raw = str(scan_job_id or "").strip()
    if not raw or raw.lower() in {"all", "none", "null"}:
        return None
    try:
        jid = str(uuid.UUID(raw))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {
            "code": "invalid_scan_job_id", "message": "scan_job_id must be a UUID"}}) from exc
    row = fetchone(
        db,
        "SELECT id FROM vuln_scan_jobs WHERE id = CAST(:jid AS uuid) AND case_id = CAST(:cid AS uuid)",
        {"jid": jid, "cid": case_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail={"error": {
            "code": "scan_job_not_found", "message": "Scan job not found in this case"}})
    return jid


def _job_suffix(jid: str | None) -> str:
    return f"-job-{jid[:8]}" if jid else ""


@router.get("/api/vuln/orchestrator/pipeline")
def get_default_pipeline(current: CurrentUser = Depends(require_firm_permission("scan:read"))):
    _require_vuln_module()
    return {"pipeline": DEFAULT_PIPELINE, "orchestration_enabled": get_settings().vuln_orchestration_enabled}


@router.get("/api/cases/{case_id}/vuln-report.csv")
def export_vuln_report_csv(
    case_id: str,
    scan_job_id: str | None = JOB_QUERY,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    csv_text = export_case_csv(db, case_id=case_id, scan_job_id=jid)
    return PlainTextResponse(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="vuln-report-{case_id[:8]}{_job_suffix(jid)}.csv"'},
    )


@router.get("/api/cases/{case_id}/vuln-report.xlsx")
def export_vuln_report_xlsx(
    case_id: str,
    scan_job_id: str | None = JOB_QUERY,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    data = export_case_xlsx(db, case_id=case_id, scan_job_id=jid)
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="Solution Set-{case_id[:8]}{_job_suffix(jid)}.xlsx"'},
    )


@router.get("/api/cases/{case_id}/vuln-report/summary")
def vuln_report_summary(
    case_id: str,
    scan_job_id: str | None = JOB_QUERY,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    return export_case_summary(db, case_id=case_id, scan_job_id=jid)


@router.get("/api/cases/{case_id}/service-coverage.csv")
def service_coverage_csv(case_id: str, scan_job_id: str | None = JOB_QUERY, db: Session = Depends(firm_db),
                         current: CurrentUser = Depends(require_firm_permission("vuln:read"))):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    return PlainTextResponse(
        export_service_coverage_csv(db, case_id=case_id, scan_job_id=jid), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="service-coverage-{case_id[:8]}{_job_suffix(jid)}.csv"'})


@router.get("/api/cases/{case_id}/service-coverage")
def service_coverage_json(case_id: str, scan_job_id: str | None = JOB_QUERY, db: Session = Depends(firm_db),
                         current: CurrentUser = Depends(require_firm_permission("vuln:read"))):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    return {"case_id": case_id, "scan_job_id": jid,
            "jobs": load_service_coverage(db, case_id=case_id, scan_job_id=jid)}


class CsvImportBody(BaseModel):
    csv_text: str


@router.post("/api/cases/{case_id}/vuln-report/import")
def import_vuln_report_csv(
    case_id: str,
    body: CsvImportBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    return import_solution_csv(db, case_id=case_id, csv_text=body.csv_text)


class NessusParityBody(BaseModel):
    csv_text: str


@router.post("/api/cases/{case_id}/nessus-parity/compare")
def compare_nessus_parity_text(
    case_id: str,
    body: NessusParityBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    try:
        return compare_nessus_csv(db, case_id=case_id, csv_text=body.csv_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "nessus_csv_invalid", "message": str(exc)}}) from exc


@router.post("/api/cases/{case_id}/nessus-parity/compare-file")
async def compare_nessus_parity_file(
    case_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    try:
        return compare_nessus_csv(db, case_id=case_id, csv_text=text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "nessus_csv_invalid", "message": str(exc)}}) from exc


@router.post("/api/cases/{case_id}/vuln-report/import-file")
async def import_vuln_report_file(
    case_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return import_solution_csv(db, case_id=case_id, csv_text=text)


@router.get("/api/vuln/gap-merge/jobs")
def list_gap_merge_jobs(
    from_date: str | None = Query(None, description="Optional YYYY-MM-DD (Asia/Kolkata), scan start day."),
    to_date: str | None = Query(None, description="Optional YYYY-MM-DD (Asia/Kolkata), scan start day."),
    limit: int | None = Query(None, ge=1, le=200, description="Default 20 without dates, 200 with dates."),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    """V1.10.6: finished scan jobs that can be merged into one gap report."""
    _require_vuln_module()
    from app.services.gap_assessment_report import ensure_gap_site_column
    from app.services.gap_merge_jobs import MergeDateError, list_merge_job_candidates

    ensure_gap_site_column(db)
    try:
        return list_merge_job_candidates(db, from_date=from_date, to_date=to_date, limit=limit)
    except MergeDateError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": exc.code, "message": str(exc)}}) from exc


def _uuid_list(raw: str | None, label: str) -> list[str]:
    out: list[str] = []
    for part in str(raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(str(uuid.UUID(part)))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": {
                "code": "merge_invalid", "message": f"{label} must be UUIDs"}}) from exc
    return out


@router.get("/api/cases/gap-report/merged.pdf")
def export_merged_gap_report_pdf(
    case_ids: str | None = Query(
        None,
        description="Comma-separated case UUIDs (2+). Same findings append IPs; different findings stay separate.",
    ),
    job_ids: str | None = Query(
        None,
        description="V1.10.6: comma-separated scan job UUIDs (2+), from one case or several. Used instead of case_ids.",
    ),
    llm: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jobs = _uuid_list(job_ids, "job_ids")
    ids = [p.strip() for p in (case_ids or "").split(",") if p.strip()]
    if not jobs and not ids:
        raise HTTPException(status_code=400, detail={"error": {
            "code": "merge_invalid", "message": "Pass job_ids (or case_ids) with at least two entries"}})
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        if jobs:
            data, media_type, filename = export_merged_gap_report(db, fmt="pdf", use_llm=use_llm, job_ids=jobs)
        else:
            data, media_type, filename = export_merged_gap_report(db, ids, fmt="pdf", use_llm=use_llm)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "merge_invalid", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/gap-report/merged.xlsx")
def export_merged_gap_report_xlsx(
    case_ids: str | None = Query(
        None,
        description="Comma-separated case UUIDs (2+). Same findings append IPs; different findings stay separate.",
    ),
    job_ids: str | None = Query(
        None,
        description="Comma-separated scan job UUIDs (2+), from one case or several. Used instead of case_ids.",
    ),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    """Combined Solution Set for the same jobs or cases as the merged gap PDF."""
    _require_vuln_module()
    jobs = _uuid_list(job_ids, "job_ids")
    ids = [p.strip() for p in (case_ids or "").split(",") if p.strip()]
    if not jobs and not ids:
        raise HTTPException(status_code=400, detail={"error": {
            "code": "merge_invalid", "message": "Pass job_ids (or case_ids) with at least two entries"}})
    try:
        if jobs:
            data, media_type, filename = export_merged_solution_xlsx(db, job_ids=jobs)
        else:
            data, media_type, filename = export_merged_solution_xlsx(db, ids)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "merge_invalid", "message": str(exc)}},
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/{case_id}/gap-report.pdf")
def export_gap_report_pdf(
    case_id: str,
    llm: str | None = None,
    scan_job_id: str | None = JOB_QUERY,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        data, media_type, filename = export_gap_report(db, case_id, fmt="pdf", use_llm=use_llm, scan_job_id=jid)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}}) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/{case_id}/gap-report.docx")
def export_gap_report_docx(
    case_id: str,
    llm: str | None = None,
    scan_job_id: str | None = JOB_QUERY,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    jid = _job_or_none(db, case_id, scan_job_id)
    use_llm = str(llm or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        data, media_type, filename = export_gap_report(db, case_id, fmt="docx", use_llm=use_llm, scan_job_id=jid)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}}) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/cases/{case_id}/gap-report-bundle.zip")
def export_gap_report_bundle(
    case_id: str,
    fmt: str = Query("pdf", description="pdf or docx for every gap report in the bundle."),
    llm: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    """V1.27.0: "All jobs in this case" export.

    One ZIP holding each scan job's gap report (``fmt``) and Solution Set, plus — when
    the case has 2+ jobs — the merged report and combined Solution Set. A case with no
    scan jobs yields the whole-case report + Solution Set (previous behaviour, zipped).
    """
    _require_vuln_module()
    # Absent/blank llm -> None so the server's gap_report_llm_enabled setting decides,
    # matching the single-report endpoints; an explicit truthy value forces LLM on.
    use_llm = True if str(llm or "").strip().lower() in {"1", "true", "yes", "on"} else None
    want = "docx" if str(fmt or "").strip().lower() == "docx" else "pdf"
    try:
        data, media_type, filename = export_case_gap_bundle(db, case_id, fmt=want, use_llm=use_llm)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": str(exc)}}) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/vuln/scan-jobs/{job_id}/engine-runs")
def list_engine_runs(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT engine, role, status, findings_count, error, started_at, completed_at, metadata_json
           FROM vuln_scan_engine_runs WHERE scan_job_id = CAST(:jid AS uuid) ORDER BY created_at""",
        {"jid": job_id},
    )
    return {"items": [dict(r) for r in rows]}
