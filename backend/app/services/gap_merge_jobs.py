"""V1.10.6: scan jobs that can be merged into one Gap Assessment Report.

A case often holds several scan jobs (re-scans, network segments, a laptop per
site). Gap reports are produced per job (V1.10.3), so the merge picks jobs, not
cases. A job is offered when it has finished (completed / incomplete) and its
case has a saved site overview, which provides the report header.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from app.db.sql_helpers import fetchall, fetchone
from app.services.aetheris_severity import aetheris_severity_sql

DEFAULT_LIMIT = 20
MAX_LIMIT = 200
MERGEABLE_STATUSES = ("completed", "incomplete")
_IST = ZoneInfo("Asia/Kolkata")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DETAIL_KEYS = ("client_name", "branch_locations", "contact_person", "date_of_visit", "author",
                "document_version", "num_endpoints", "geographic_locations")


class MergeDateError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def ist_today() -> date:
    return datetime.now(_IST).date()


def _parse_day(raw: str | None, field: str) -> date | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise MergeDateError("invalid_date", f"{field} must be YYYY-MM-DD") from exc


def merge_window(from_date: str | None, to_date: str | None) -> tuple[date | None, date | None]:
    start = _parse_day(from_date, "from_date")
    end = _parse_day(to_date, "to_date")
    if start and end and start > end:
        raise MergeDateError("invalid_date_range", "from_date must be on or before to_date")
    return start, end


def day_label(day: date | None, today: date) -> str:
    if day is None:
        return "unknown"
    if day == today:
        return "today"
    if day == today.fromordinal(today.toordinal() - 1):
        return "yesterday"
    return f"{day.day:02d} {_MONTHS[day.month - 1]} {day.year}"


def _site(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return str(value) if value else None


def list_merge_job_candidates(
    db,
    *,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Finished scan jobs whose case has a saved site overview, newest scan first.

    Without dates: the latest 20. With From and/or To: jobs whose scan started
    on those days (Asia/Kolkata), up to 200.
    """
    start, end = merge_window(from_date, to_date)
    filtered = bool(start or end)
    lim = max(1, min(MAX_LIMIT, int(limit or (MAX_LIMIT if filtered else DEFAULT_LIMIT))))
    where = [
        f"j.status IN ({', '.join(repr(s) for s in MERGEABLE_STATUSES)})",
        "c.gap_site_json IS NOT NULL",
        "jsonb_typeof(c.gap_site_json) = 'object'",
        "c.gap_site_json <> '{}'::jsonb",
    ]
    params: dict[str, Any] = {}
    scan_day = "(COALESCE(j.started_at, j.created_at) AT TIME ZONE 'Asia/Kolkata')::date"
    if start:
        where.append(f"{scan_day} >= CAST(:from_d AS date)")
        params["from_d"] = start.isoformat()
    if end:
        where.append(f"{scan_day} <= CAST(:to_d AS date)")
        params["to_d"] = end.isoformat()
    where_sql = " AND ".join(where)
    total_row = fetchone(
        db, f"SELECT COUNT(*) AS c FROM vuln_scan_jobs j JOIN cases c ON c.id = j.case_id WHERE {where_sql}", params
    )
    total_matching = int((total_row or {}).get("c") or 0)
    rows = fetchall(
        db,
        f"""SELECT j.id AS job_id, j.case_id, j.status, j.started_at, j.completed_at, j.created_at,
                   {scan_day} AS scan_ist_date,
                   c.title AS case_title, c.number AS case_number, c.gap_site_json,
                   (SELECT COUNT(*)::int FROM vuln_scan_targets t
                     WHERE t.scan_job_id = j.id AND NOT COALESCE(t.excluded, FALSE)) AS target_count
              FROM vuln_scan_jobs j
              JOIN cases c ON c.id = j.case_id
             WHERE {where_sql}
             ORDER BY COALESCE(j.completed_at, j.started_at, j.created_at) DESC
             LIMIT :lim""",
        {**params, "lim": lim},
    )
    counts = _severity_counts(db, [str(r["job_id"]) for r in rows])
    today = ist_today()
    items: list[dict[str, Any]] = []
    for row in rows:
        site = _site(row.get("gap_site_json"))
        scan_day_val = row.get("scan_ist_date")
        if isinstance(scan_day_val, datetime):
            scan_day_val = scan_day_val.date()
        elif isinstance(scan_day_val, str):
            try:
                scan_day_val = date.fromisoformat(scan_day_val[:10])
            except ValueError:
                scan_day_val = None
        jid = str(row["job_id"])
        items.append({
            "job_id": jid,
            "case_id": str(row["case_id"]),
            "case_title": row.get("case_title"),
            "case_number": row.get("case_number"),
            "status": row.get("status"),
            "started_at": _iso(row.get("started_at")),
            "completed_at": _iso(row.get("completed_at")),
            "created_at": _iso(row.get("created_at")),
            "target_count": int(row.get("target_count") or 0),
            "severity_counts": counts.get(jid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}),
            "day_label": day_label(scan_day_val if isinstance(scan_day_val, date) else None, today),
            "gap_details": {k: site.get(k) for k in _DETAIL_KEYS if str(site.get(k) or "").strip()},
        })
    return {
        "items": items,
        "total": len(items),
        "total_matching": max(total_matching, len(items)),
        "has_more": total_matching > len(items),
        "limit": lim,
        "filtered": filtered,
        "from_date": start.isoformat() if start else None,
        "to_date": end.isoformat() if end else None,
    }


def _severity_counts(db, job_ids: list[str]) -> dict[str, dict[str, int]]:
    if not job_ids:
        return {}
    params = {f"j{i}": jid for i, jid in enumerate(job_ids)}
    placeholders = ", ".join(f"CAST(:j{i} AS uuid)" for i in range(len(job_ids)))
    out: dict[str, dict[str, int]] = {}
    for r in fetchall(
        db,
        f"""SELECT scan_job_id, {aetheris_severity_sql('')} AS severity, COUNT(*)::int AS c
              FROM vuln_findings
             WHERE scan_job_id IN ({placeholders}) AND status = 'open'
             GROUP BY 1, 2""",
        params,
    ):
        bucket = out.setdefault(str(r["scan_job_id"]), {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        sev = str(r.get("severity") or "info").lower()
        bucket[sev if sev in bucket else "info"] += int(r.get("c") or 0)
    return out
