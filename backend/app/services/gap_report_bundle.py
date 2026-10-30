"""V1.27.0: one ZIP with every scan job's Gap Assessment Report + Solution Set,
plus the merged report and combined Solution Set for the whole case.

Why this exists
---------------
When the examiner picks **All jobs in this case** and clicks Download PDF/DOCX, the
old behaviour produced a single blended report over every finding in the case. The
field ask was different: give me *each job's own* report and Solution Set AND a
single combined (merged) report + Solution Set for the case.

Delivering many files from one click is unreliable in a browser — a second
programmatic download is commonly blocked — so everything is packed into one ZIP.

Nothing new is computed here. Each piece is produced by the existing, tested
exporters:

* ``export_gap_report``        -> one job's gap report (PDF/DOCX)
* ``export_case_xlsx``         -> one job's Solution Set (xlsx)
* ``export_merged_gap_report`` -> the merged gap report for 2+ jobs (PDF/DOCX)
* ``export_merged_solution_xlsx`` -> the combined Solution Set for 2+ jobs (xlsx)

Behaviour by job count
-----------------------
* 0 jobs  -> the whole-case report + whole-case Solution Set (today's output, zipped).
* 1 job   -> that job's report + Solution Set (one job cannot be "merged").
* 2+ jobs -> every job's report + Solution Set under ``per-job/``, and the merged
             report + combined Solution Set at the ZIP root.
"""

from __future__ import annotations

import io
import zipfile
from typing import Any

from app.db.sql_helpers import fetchall
from app.services.gap_assessment_report import export_gap_report, export_merged_gap_report
from app.services.vuln_report_export import export_case_xlsx, export_merged_solution_xlsx

XLSX_MEDIA = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def list_case_job_ids(db, case_id: str) -> list[dict[str, Any]]:
    """Every scan job of the case, oldest first (so reports read in scan order).

    No status filter: "All jobs in this case" means all of them. The examiner can
    always export a single job if they want to leave an in-progress scan out.
    """
    rows = fetchall(
        db,
        """SELECT id, status, created_at
             FROM vuln_scan_jobs
            WHERE case_id = CAST(:cid AS uuid)
            ORDER BY created_at ASC""",
        {"cid": case_id},
    )
    return [dict(r) for r in rows]


def _unique(used: set[str], name: str) -> str:
    """A ZIP entry name that has not been used yet (guards duplicate client slugs)."""
    if name not in used:
        used.add(name)
        return name
    head, _, ext = name.rpartition(".")
    i = 2
    while f"{head}-{i}.{ext}" in used:
        i += 1
    final = f"{head}-{i}.{ext}"
    used.add(final)
    return final


def export_case_gap_bundle(
    db,
    case_id: str,
    *,
    fmt: str = "pdf",
    use_llm: bool | None = None,
) -> tuple[bytes, str, str]:
    """Build the per-case ZIP. Returns ``(zip_bytes, media_type, filename)``.

    ``fmt`` is ``"pdf"`` or ``"docx"`` and applies to every gap report in the ZIP;
    the Solution Sets are always xlsx. ``use_llm=None`` defers to the server setting,
    exactly like the single-report endpoints.
    """
    fmt = "docx" if str(fmt or "").strip().lower() == "docx" else "pdf"
    jobs = list_case_job_ids(db, case_id)
    job_ids = [str(j["id"]) for j in jobs]

    buf = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not job_ids:
            # No scan jobs recorded: the "whole case" report is the only one there is.
            rep, _mt, rname = export_gap_report(db, case_id, fmt=fmt, use_llm=use_llm)
            zf.writestr(_unique(used, rname), rep)
            xls = export_case_xlsx(db, case_id=case_id)
            zf.writestr(_unique(used, f"Solution Set-{case_id[:8]}.xlsx"), xls)
        else:
            # Each job's own report + Solution Set, grouped under per-job/.
            for jid in job_ids:
                rep, _mt, rname = export_gap_report(
                    db, case_id, fmt=fmt, use_llm=use_llm, scan_job_id=jid
                )
                zf.writestr(_unique(used, f"per-job/{rname}"), rep)
                xls = export_case_xlsx(db, case_id=case_id, scan_job_id=jid)
                zf.writestr(
                    _unique(used, f"per-job/Solution Set-{case_id[:8]}-job-{jid[:8]}.xlsx"),
                    xls,
                )
            # The combined deliverables sit at the ZIP root so they are seen first.
            if len(job_ids) >= 2:
                mrep, _mt, mrname = export_merged_gap_report(
                    db, fmt=fmt, use_llm=use_llm, job_ids=job_ids
                )
                zf.writestr(_unique(used, mrname), mrep)
                mxls, _mt2, mxname = export_merged_solution_xlsx(db, job_ids=job_ids)
                zf.writestr(_unique(used, mxname), mxls)

    filename = f"gap-assessment-case-{case_id[:8]}-{max(len(job_ids), 1)}-jobs.zip"
    return buf.getvalue(), "application/zip", filename
