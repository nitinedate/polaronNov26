"""Readable, paged view of parsed forensic records for the artifact preview.

Stage 5 ("Native forensic parsing") already stores structured records in
``artifact_parse_results.normalized`` for registry hives, EVTX, Prefetch, LNK,
Jump Lists, SetupAPI, $I recycle records, PST inventories, etc.  The preview
never displayed them: binary forensic files fell through to "opaque binary —
download it".  This module turns the stored records into a table:

* no evidence bytes are read when a stored parse exists (one indexed lookup on
  ``ix_artifact_parse_results_artifact_created`` + one JSONB slice in SQL);
* when nothing is stored, the same registered parser is run once on demand and
  its output is stored, so the next open is a database read;
* every row keeps its record ordinal, so values stay traceable to the parse.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import PurePosixPath
from typing import Any


from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("artifact_parsed_view")

DEFAULT_PAGE = 100
MAX_PAGE = 500
MAX_COLUMNS = 10
CELL_MAX = 400
ONDEMAND_MAX_BYTES = int(os.environ.get("ARTIFACT_ONDEMAND_PARSE_MAX_BYTES", str(256 * 1024 * 1024)))

# Parser outputs that are only placeholders, not forensic records.
_WEAK_PARSERS = frozenset({"file_meta", "binary_fallback", "preview"})

_REGISTRY_NAMES = frozenset({
    "sam", "system", "software", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve",
    "syscache.hve", "bcd", "components", "drivers", "elam",
})

# Preferred column order. Keys are matched case-insensitively.
_PRIORITY: dict[str, tuple[str, ...]] = {
    "registry": ("record_type", "key_path", "key", "value_name", "name", "value", "data",
                 "last_written", "last_write_time", "timestamp", "device", "serial"),
    "evtx": ("timestamp", "time_created", "event_id", "level", "provider", "channel", "computer",
             "user", "account", "target_user", "logon_type", "source_ip", "message"),
    "prefetch": ("executable", "exe_name", "run_count", "last_run", "last_run_times", "volume",
                 "prefetch_hash", "files_loaded"),
    "lnk": ("target_path", "local_path", "working_dir", "arguments", "created", "modified",
            "accessed", "volume_serial", "machine_id", "drive_type"),
    "jumplist": ("app_id", "app_name", "target_path", "local_path", "entry", "last_access",
                 "accessed", "created", "modified", "machine_id"),
    "setupapi": ("timestamp", "device", "device_id", "description", "serial", "event", "section"),
    "recycle_bin": ("original_path", "deleted_at", "deleted_time", "size_bytes", "file_size"),
    "pst": ("record_type", "subject", "sender", "from", "to", "date", "folder", "message_count"),
    "default": ("timestamp", "time", "date", "record_type", "event_id", "name", "path", "url",
                "title", "subject", "user", "account", "value", "message", "text"),
}
_DROP_KEYS = frozenset({"raw", "raw_bytes", "bytes", "hex", "data_b64", "base64", "blob"})


def _norm_ext(row: dict[str, Any]) -> str:
    ext = str(row.get("extension") or "").lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if not ext:
        ext = PurePosixPath(str(row.get("file_path") or "").replace("\\", "/")).suffix.lower()
    return ext


def structured_parser_for(row: dict[str, Any], head: bytes | None = None) -> str | None:
    """Return the parser family whose records are the primary view, else None."""
    path = str(row.get("file_path") or "").replace("\\", "/")
    name = (str(row.get("file_name") or "") or PurePosixPath(path).name).lower()
    low = path.lower()
    ext = _norm_ext(row)
    if head is not None and head[:4] == b"regf":
        return "registry"
    if name in _REGISTRY_NAMES or ext == ".hve" or (name.endswith(".dat") and name.startswith(("ntuser", "usrclass"))):
        return "registry"
    if ext == ".evtx" or (head is not None and head[:8] == b"ElfFile\x00"):
        return "evtx"
    if ext == ".pf":
        return "prefetch"
    if ext == ".lnk":
        return "lnk"
    if "automaticdestinations" in name or "customdestinations" in name:
        return "jumplist"
    if name.startswith("setupapi") and name.endswith(".log"):
        return "setupapi"
    if name.startswith("$i") and ("$recycle.bin" in low or "/recycler/" in low):
        return "recycle_bin"
    if ext in {".pst", ".ost"}:
        return "pst"
    if name in {"$mft", "$logfile", "$usnjrnl", "$j"}:
        return "mft"
    return None


def latest_parse_meta(db, artifact_id: str) -> dict[str, Any] | None:
    """Most recent non-placeholder parse result (uses the artifact/created index)."""
    try:
        rows = fetchall(
            db,
            """SELECT id, parser_name, parser_version, record_count, error, created_at,
                      jsonb_typeof(normalized) AS jtype,
                      CASE WHEN jsonb_typeof(normalized) = 'array'
                           THEN jsonb_array_length(normalized) ELSE 1 END AS n
               FROM artifact_parse_results
               WHERE job_artifact_id = :id
               ORDER BY created_at DESC
               LIMIT 5""",
            {"id": artifact_id},
        )
    except Exception:
        log.debug("parse meta lookup failed artifact=%s", artifact_id, exc_info=True)
        return None
    best = None
    for r in rows or []:
        r = dict(r)
        name = str(r.get("parser_name") or "")
        if r.get("jtype") not in ("array", "object"):
            continue
        if name in _WEAK_PARSERS or str(r.get("parser_version") or "") == "preview" or name.startswith("."):
            best = best or r
            continue
        if int(r.get("n") or 0) <= 0:
            continue
        return r
    return best


def is_strong_parse(meta: dict[str, Any] | None) -> bool:
    if not meta:
        return False
    name = str(meta.get("parser_name") or "")
    return (
        name not in _WEAK_PARSERS
        and not name.startswith(".")
        and str(meta.get("parser_version") or "") != "preview"
        and int(meta.get("n") or 0) > 0
    )


def page_records(db, meta: dict[str, Any], *, offset: int = 0, limit: int = DEFAULT_PAGE) -> list[dict[str, Any]]:
    """One page of records, sliced inside PostgreSQL (no full JSON transfer)."""
    offset = max(int(offset or 0), 0)
    limit = max(1, min(int(limit or DEFAULT_PAGE), MAX_PAGE))
    if meta.get("jtype") == "object":
        row = fetchone(db, "SELECT normalized FROM artifact_parse_results WHERE id=:id", {"id": meta["id"]})
        value = (row or {}).get("normalized")
        if isinstance(value, str):
            value = json.loads(value)
        return [value] if (offset == 0 and isinstance(value, dict)) else []
    rows = fetchall(
        db,
        """SELECT e.value AS rec, e.ord
           FROM artifact_parse_results r
           CROSS JOIN LATERAL jsonb_array_elements(r.normalized) WITH ORDINALITY AS e(value, ord)
           WHERE r.id = :rid
           ORDER BY e.ord
           OFFSET :off LIMIT :lim""",
        {"rid": meta["id"], "off": offset, "lim": limit},
    )
    out: list[dict[str, Any]] = []
    for r in rows or []:
        rec = r.get("rec")
        if isinstance(rec, str):
            try:
                rec = json.loads(rec)
            except json.JSONDecodeError:
                rec = {"text": rec}
        if not isinstance(rec, dict):
            rec = {"value": rec}
        out.append(rec)
    return out


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            value = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            value = str(value)
    text_v = str(value).replace("\x00", "")
    if len(text_v) > CELL_MAX:
        text_v = text_v[: CELL_MAX - 1] + "…"
    return text_v


def records_table(records: list[dict[str, Any]], parser_family: str = "default") -> dict[str, Any]:
    """Columns ordered by forensic priority, then by frequency across the page."""
    freq: dict[str, int] = {}
    original: dict[str, str] = {}
    for rec in records:
        for key, value in rec.items():
            lk = str(key).lower()
            if lk in _DROP_KEYS or value in (None, "", [], {}):
                continue
            freq[lk] = freq.get(lk, 0) + 1
            original.setdefault(lk, str(key))
    priority = _PRIORITY.get(parser_family) or _PRIORITY["default"]
    ordered = [k for k in priority if k in freq]
    rest = sorted((k for k in freq if k not in ordered), key=lambda k: (-freq[k], k))
    # Long free text last: it dominates the table width.
    rest = [k for k in rest if k not in ("text", "preview", "text_preview")] + [
        k for k in rest if k in ("text", "preview", "text_preview")
    ]
    columns = (ordered + rest)[:MAX_COLUMNS]
    rows = []
    for rec in records:
        lower = {str(k).lower(): v for k, v in rec.items()}
        rows.append([_cell(lower.get(c)) for c in columns])
    return {"columns": [original.get(c, c) for c in columns], "rows": rows}


def records_text(records: list[dict[str, Any]], *, limit: int = 60) -> str:
    """Plain-text rendering (search, copy, accessibility fallback)."""
    blocks = []
    for i, rec in enumerate(records[:limit], 1):
        lines = [f"#{i}"]
        for key, value in rec.items():
            if str(key).lower() in _DROP_KEYS or value in (None, "", [], {}):
                continue
            lines.append(f"  {key}: {_cell(value)}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def parsed_records_payload(
    db,
    meta: dict[str, Any],
    *,
    family: str,
    offset: int = 0,
    limit: int = DEFAULT_PAGE,
    source: str = "stored_parse",
) -> dict[str, Any]:
    records = page_records(db, meta, offset=offset, limit=limit)
    table = records_table(records, family)
    total = int(meta.get("n") or len(records))
    return {
        "parser": meta.get("parser_name"),
        "parser_version": meta.get("parser_version"),
        "family": family,
        "record_count": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(records) < total,
        "columns": table["columns"],
        "rows": table["rows"],
        "source": source,
        "parsed_at": str(meta.get("created_at") or ""),
        "_records": records,
    }


def apply_parsed_records(preview: dict[str, Any], payload: dict[str, Any], *, title: str) -> None:
    records = payload.pop("_records", [])
    preview["parsed_records"] = payload
    preview["artifact_type"] = f"parsed_{payload.get('family') or 'records'}"
    preview["content_type"] = "text/plain"
    preview["encoding"] = None
    header = (
        f"{title} — {payload['record_count']:,} parsed record(s) "
        f"[{payload.get('parser')} {payload.get('parser_version') or ''}]".strip()
    )
    preview["body"] = f"{header}\n\n{records_text(records)}"
    preview["body_text"] = preview["body"]


def run_and_store_parse(db, row: dict[str, Any], data: bytes) -> dict[str, Any] | None:
    """Run the registered parser once on demand and store it like stage 5 does."""
    from app.parsers import PARSER_VERSION, run_parser

    path = str(row.get("file_path") or "")
    try:
        parser_name, records = run_parser(path, data)
    except Exception as exc:
        log.warning("on-demand parse failed artifact=%s path=%s: %s", row.get("id"), path, exc)
        return None
    if not records:
        return None
    try:
        payload = json.dumps(records, default=str)
    except Exception:
        return None
    artifact_id = str(row.get("id") or "")
    try:
        execute(
            db,
            """INSERT INTO artifact_parse_results
                 (job_artifact_id, parser_name, parser_version, record_count, byte_offset, normalized)
               VALUES (:aid, :pname, :pver, :n, 0, CAST(:norm AS jsonb))""",
            {"aid": artifact_id, "pname": parser_name, "pver": f"{PARSER_VERSION}+ondemand",
             "n": len(records), "norm": payload},
        )
        execute(
            db,
            """UPDATE job_artifacts SET parse_status='parsed', updated_at=NOW()
               WHERE id=:id AND parse_status IS DISTINCT FROM 'parsed'""",
            {"id": artifact_id},
        )
        db.commit()
    except Exception:
        log.warning("on-demand parse store failed artifact=%s", artifact_id, exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        return None
    return latest_parse_meta(db, artifact_id)
