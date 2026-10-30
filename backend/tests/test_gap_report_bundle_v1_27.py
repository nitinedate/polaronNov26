"""V1.27.0: "All jobs in this case" export bundles per-job + merged reports in one ZIP.

DB-free: the four exporters and the job-list query are monkeypatched, so the test only
checks what ``export_case_gap_bundle`` assembles, not report rendering (covered elsewhere).
"""
from __future__ import annotations

import io
import zipfile

import app.services.gap_report_bundle as bundle

CASE = "00000000-0000-0000-0000-0000000000aa"
J1 = "11111111-1111-1111-1111-111111111111"
J2 = "22222222-2222-2222-2222-222222222222"
J3 = "33333333-3333-3333-3333-333333333333"


def _patch_exporters(monkeypatch) -> None:
    def gap(db, cid, *, fmt="pdf", site_override=None, use_llm=None, scan_job_id=None):
        ext = "docx" if fmt == "docx" else "pdf"
        slug = f"-job-{scan_job_id[:8]}" if scan_job_id else ""
        return (b"%REPORT", "application/octet-stream", f"gap-assessment-client{slug}.{ext}")

    def case_xlsx(db, *, case_id, scan_job_id=None):
        return b"PK\x03\x04case-xlsx"

    def merged_gap(db, case_ids=None, *, fmt="pdf", use_llm=None, job_ids=None):
        ext = "docx" if fmt == "docx" else "pdf"
        return (b"%MERGED", "application/octet-stream", f"gap-assessment-client-merged-{len(job_ids)}-jobs.{ext}")

    def merged_xlsx(db, case_ids=None, *, job_ids=None):
        return (b"PK\x03\x04merged-xlsx", bundle.XLSX_MEDIA, f"Solution Set-merged-{len(job_ids)}-jobs.xlsx")

    monkeypatch.setattr(bundle, "export_gap_report", gap)
    monkeypatch.setattr(bundle, "export_case_xlsx", case_xlsx)
    monkeypatch.setattr(bundle, "export_merged_gap_report", merged_gap)
    monkeypatch.setattr(bundle, "export_merged_solution_xlsx", merged_xlsx)


def _jobs(monkeypatch, rows) -> None:
    monkeypatch.setattr(bundle, "fetchall", lambda db, sql, params=None: list(rows))


def _names(data: bytes) -> list[str]:
    return zipfile.ZipFile(io.BytesIO(data)).namelist()


def test_two_jobs_bundle_has_each_job_plus_merged(monkeypatch):
    _jobs(monkeypatch, [{"id": J1, "status": "completed", "created_at": 1},
                        {"id": J2, "status": "completed", "created_at": 2}])
    _patch_exporters(monkeypatch)
    data, media, fname = bundle.export_case_gap_bundle(object(), CASE, fmt="pdf")
    assert media == "application/zip" and fname == f"gap-assessment-case-{CASE[:8]}-2-jobs.zip"
    names = _names(data)
    # Each job: one report + one Solution Set, grouped under per-job/.
    assert sum(n.startswith("per-job/") and n.endswith(".pdf") for n in names) == 2
    assert sum(n.startswith("per-job/") and n.endswith(".xlsx") for n in names) == 2
    # The combined pair sits at the ZIP root (not under per-job/).
    assert any(n == "gap-assessment-client-merged-2-jobs.pdf" for n in names)
    assert any(n == "Solution Set-merged-2-jobs.xlsx" for n in names)


def test_three_jobs_merge_uses_all_job_ids(monkeypatch):
    _jobs(monkeypatch, [{"id": J1, "status": "completed", "created_at": 1},
                        {"id": J2, "status": "running", "created_at": 2},
                        {"id": J3, "status": "completed", "created_at": 3}])
    _patch_exporters(monkeypatch)
    data, _, fname = bundle.export_case_gap_bundle(object(), CASE, fmt="pdf")
    assert fname.endswith("-3-jobs.zip")
    names = _names(data)
    assert sum(n.startswith("per-job/") and n.endswith(".pdf") for n in names) == 3
    assert any("merged-3-jobs.pdf" in n for n in names)
    assert any("merged-3-jobs.xlsx" in n for n in names)


def test_single_job_has_no_merge(monkeypatch):
    _jobs(monkeypatch, [{"id": J1, "status": "completed", "created_at": 1}])
    _patch_exporters(monkeypatch)
    data, _, fname = bundle.export_case_gap_bundle(object(), CASE, fmt="pdf")
    assert fname.endswith("-1-jobs.zip")
    names = _names(data)
    assert sum(n.endswith(".pdf") for n in names) == 1
    assert sum(n.endswith(".xlsx") for n in names) == 1
    assert not any("merged" in n for n in names)


def test_no_jobs_falls_back_to_whole_case(monkeypatch):
    _jobs(monkeypatch, [])
    _patch_exporters(monkeypatch)
    data, _, fname = bundle.export_case_gap_bundle(object(), CASE, fmt="pdf")
    assert fname.endswith("-1-jobs.zip")
    names = _names(data)
    # Whole-case report + Solution Set at the root; no per-job/ folder, no merge.
    assert any(n.endswith(".pdf") for n in names) and any(n.endswith(".xlsx") for n in names)
    assert not any(n.startswith("per-job/") for n in names)
    assert not any("merged" in n for n in names)


def test_docx_bundle_uses_docx_for_every_report(monkeypatch):
    _jobs(monkeypatch, [{"id": J1, "status": "completed", "created_at": 1},
                        {"id": J2, "status": "completed", "created_at": 2}])
    _patch_exporters(monkeypatch)
    data, _, _ = bundle.export_case_gap_bundle(object(), CASE, fmt="docx")
    names = _names(data)
    assert sum(n.startswith("per-job/") and n.endswith(".docx") for n in names) == 2
    assert any(n == "gap-assessment-client-merged-2-jobs.docx" for n in names)
    # Solution Sets stay xlsx regardless of report format.
    assert sum(n.endswith(".xlsx") for n in names) == 3


def test_duplicate_report_filenames_do_not_collide(monkeypatch):
    # Both jobs render to the same client slug with no job suffix: names must stay unique.
    _jobs(monkeypatch, [{"id": J1, "status": "completed", "created_at": 1},
                        {"id": J2, "status": "completed", "created_at": 2}])
    monkeypatch.setattr(
        bundle, "export_gap_report",
        lambda db, cid, *, fmt="pdf", site_override=None, use_llm=None, scan_job_id=None:
            (b"%R", "application/octet-stream", "gap-assessment-client.pdf"),
    )
    monkeypatch.setattr(bundle, "export_case_xlsx", lambda db, *, case_id, scan_job_id=None: b"PKx")
    monkeypatch.setattr(
        bundle, "export_merged_gap_report",
        lambda db, case_ids=None, *, fmt="pdf", use_llm=None, job_ids=None:
            (b"%M", "application/octet-stream", "gap-assessment-client-merged-2-jobs.pdf"),
    )
    monkeypatch.setattr(
        bundle, "export_merged_solution_xlsx",
        lambda db, case_ids=None, *, job_ids=None:
            (b"PKm", bundle.XLSX_MEDIA, "Solution Set-merged-2-jobs.xlsx"),
    )
    data, _, _ = bundle.export_case_gap_bundle(object(), CASE, fmt="pdf")
    names = _names(data)
    assert len(names) == len(set(names)), f"duplicate entries: {names}"
