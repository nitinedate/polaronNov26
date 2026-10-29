"""Evidence accessibility is independent of processing completion.

Read only small, job-scoped coverage summaries on polling; never scan artifacts.
Missing records cannot establish deletion, overwriting or absence on a device.
"""
from __future__ import annotations
import html
import json
import re
from app.db.sql_helpers import fetchall, fetchone

NOTICE = "Processing 100% means scheduled work has finished. It does not mean full device or evidence coverage."
RULES = {
    "missing_key": ("Encrypted app data could not be decrypted with an available authorized key.", "Supply the matching authorized key and reprocess the affected source."),
    "private_app_data": ("Private app data is unavailable in this acquisition.", "Obtain an authorized acquisition containing the relevant private app data and reprocess."),
    "overwritten": ("The source record explicitly identifies overwritten evidence.", "Seek independent backups or corroborating sources; overwritten bytes may be unrecoverable."),
    "inaccessible": ("The source record identifies inaccessible evidence.", "Review access, corruption and acquisition errors; reacquire where possible."),
    "acquisition_gap": ("No readable records were recovered for this source. Absence on the device is not established.", "Check acquisition scope, private app access and encryption keys. Corroborate with other sources."),
    "unsupported": ("Acquired files were processed but their format was unsupported.", "Use a supported parser or perform a documented manual examination."),
    "processing_exception": ("Some acquired evidence was skipped, failed or could not be examined.", "Review the processing exceptions and retry or document the examiner's disposition."),
}


def obj(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            pass
    return {}


def build_source_coverage(disk_source=None, coverage_rows=(), validation=None, *, processing_complete=False):
    ds, validation = obj(disk_source), obj(validation)
    limitations = []
    def add(code, source, count=None):
        reason, action = RULES[code]
        item = {"code": code, "source": str(source), "reason": reason, "action": action}
        if count is not None:
            item["count"] = int(count)
        if item not in limitations:
            limitations.append(item)
    gate = obj(ds.get("whatsapp_evidence_gate"))
    decryption = obj(gate.get("decryption"))
    blocked = decryption.get("blocked_files") or 0
    if gate.get("state") in {"key_required", "blocked"} or blocked:
        add("missing_key" if (gate.get("state") == "key_required" or gate.get("authorized_key_candidates") == 0) else "inaccessible", "WhatsApp encrypted data", blocked or None)
    # Only explicit structured facts establish private-data/overwriting limitations.
    # Never expose raw key candidates, paths, exception text or credentials here.
    for record in ds.get("source_limitations") or []:
        if isinstance(record, dict) and record.get("code") in RULES and record.get("resolved") is not True:
            add(record["code"], record.get("source") or "Acquisition")
    for row in coverage_rows:
        source = str(row.get("coverage_key") or "Acquisition")
        detail = obj(row.get("details"))
        status = row.get("status")
        if status in {"acquisition_gap", "inaccessible", "missing_key", "private_app_data", "overwritten"}:
            add(status, source)
        unsupported = int(detail.get("unsupported") or 0)
        if unsupported:
            add("unsupported", source, unsupported)
        if int(row.get("errors") or 0):
            add("processing_exception", source, row["errors"])
        for code in ("private_app_data", "overwritten", "inaccessible", "missing_key"):
            if detail.get(code) is True:
                add(code, source)
    for code, count in obj(validation.get("exceptions")).items():
        if int(count or 0) and code not in {"parse_pending"}:
            add("processing_exception", code.replace("_", " "), count)
    if validation.get("extraction_skipped"):
        add("processing_exception", "Extraction", validation["extraction_skipped"])
    if validation.get("ocr_disabled"):
        add("processing_exception", "OCR disabled")
    return {"version": 1, "processing_complete": bool(processing_complete),
            "status": "incomplete" if limitations else "unknown", "coverage_complete": False,
            "notice": NOTICE, "limitations": limitations,
            "scope_note": "Coverage is limited to the supplied acquisition. Unavailable private app data, missing keys and deleted or overwritten content cannot be ruled out by a successful run."}


def collect_source_coverage(db, job_id, *, row=None, validation=None, processing_complete=False):
    if row is None or "disk_source" not in row:
        row = fetchone(db, "SELECT disk_source,pipeline_progress FROM jobs WHERE id=:jid", {"jid": job_id}) or {}
    if validation is None:
        stages = obj(row.get("pipeline_progress")).get("serial_pipeline", {}).get("stages", [])
        validation = next((obj(s.get("details")) for s in stages if s.get("id") == "validation"), {})
    table = fetchone(db, "SELECT to_regclass('mobile_coverage') AS name")
    rows = fetchall(db, "SELECT coverage_key,status,errors,details FROM mobile_coverage WHERE job_id=:jid ORDER BY coverage_key", {"jid": job_id}) if table and table.get("name") else []
    return build_source_coverage(row.get("disk_source"), rows or [], validation, processing_complete=processing_complete)


def render_source_coverage(coverage):
    """Pipeline and examiner text. Report pages do not include this block."""
    def safe(value):
        return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ")
    parts = ["### Source limitations and evidence coverage", "", coverage["notice"], "",
             "Evidence coverage: " + coverage["status"] + ". " + coverage["scope_note"], ""]
    if coverage["limitations"]:
        parts += ["| Source | Limitation | Follow-up |", "| --- | --- | --- |"]
        for item in coverage["limitations"]:
            count = f" ({item['count']})" if "count" in item else ""
            parts.append(f"| {safe(item['source'])} | {safe(item['reason'] + count)} | {safe(item['action'])} |")
    else:
        parts.append("No recorded accessibility exceptions; full source coverage remains unverified.")
    return "\n".join(parts) + "\n"


_COVERAGE_HEADING = re.compile(r"source limitations and evidence coverage", re.I)
_COVERAGE_TABLE = re.compile(r"^\|\s*Source\s*\|\s*Limitation\s*\|\s*Follow-up\s*\|", re.I)
_MARKDOWN_HEADING = re.compile(r"^#{1,6}\s+\S")


def strip_source_coverage_from_report(markdown: str) -> str:
    """Drop the coverage notice and its Source / Limitation / Follow-up table from report text."""
    lines = str(markdown or "").split("\n")
    kept: list[str] = []
    skipping = False
    skipping_table = False
    for line in lines:
        stripped = line.strip()
        if _COVERAGE_HEADING.search(stripped):
            skipping = True
            skipping_table = False
            continue
        if skipping:
            if _MARKDOWN_HEADING.match(stripped) and not _COVERAGE_HEADING.search(stripped):
                skipping = False
            else:
                continue
        if _COVERAGE_TABLE.match(stripped):
            skipping_table = True
            continue
        if skipping_table:
            if stripped.startswith("|"):
                continue
            skipping_table = False
        kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip("\n") + ("\n" if kept else "")
