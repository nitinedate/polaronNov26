"""Registry / SetupAPI evidence records for artifact inventory — read once per job.

Why this exists
---------------
Stage 5 (native parsing) runs ``parse_registry_hive`` / ``parse_setupapi_log`` on
every hive and SetupAPI log and stores the complete record list in
``artifact_parse_results.normalized``. Inventory collectors (USB Devices, Your
Phone Device, RDP, Feature Usage, Installed Microsoft / Non-Microsoft Programs)
nevertheless re-read the same hives from the extracted tar shards and parsed them
again — each collector separately, eight at a time. Every re-read streams and
zstd-decompresses a multi-GB shard from MinIO until the wanted member appears, so
one inventory pass streamed the same shards six or seven times concurrently.
That is the stall seen at "Normalize / correlate / artifact inventory".

This module serves all those collectors from ONE indexed SQL read of the stored
parse results. Raw bytes are read only for a hive or SetupAPI log whose parse
result is missing (failed / timed-out parse), and then in a single shard pass for
all such files together. The records are identical: the same parser function
produced them in stage 5.

Provenance is preserved: every record carries the source path, the
``job_artifact_id`` and whether it came from the stored parse or a live fallback.
VSS / backup copies with the same SHA-256 are counted once, as before.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterator

from app.db.sql_helpers import fetchall

log = logging.getLogger("registry_evidence_index")

# Hive basename -> kind. Matches app.parsers.REGISTRY_NAMES plus kinds the
# collectors filter on.
HIVE_KINDS: dict[str, str] = {
    "system": "system",
    "software": "software",
    "sam": "sam",
    "security": "security",
    "default": "default",
    "ntuser.dat": "ntuser",
    "usrclass.dat": "usrclass",
    "amcache.hve": "amcache",
}
# parser_name values stage 5 stores for these sources (see app.parsers.select_parser:
# REGISTRY_NAMES -> "registry"; ``.dat`` / ``.hve`` extension routing; SetupAPI).
REGISTRY_PARSER_NAMES: tuple[str, ...] = ("registry", ".dat", ".hve")
SETUPAPI_PARSER_NAMES: tuple[str, ...] = ("setupapi",)
INDEXED_RECORD_TYPES: tuple[str, ...] = (
    "usb_device",
    "usb_usage_event",
    "rdp_connection",
    "feature_usage",
    "installed_program",
    "phone_device",
)

_CACHE_TTL_SEC = 1800.0
_HIVE_MIN_BYTES = 4096
_SETUPAPI_MAX_BYTES = 4_000_000

_cache_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}
_cache: dict[str, tuple[float, "RegistryEvidence"]] = {}


def hive_kind(path: str) -> str | None:
    name = PurePosixPath((path or "").replace("\\", "/")).name.lower()
    return HIVE_KINDS.get(name)


def is_setupapi_path(path: str) -> bool:
    name = PurePosixPath((path or "").replace("\\", "/")).name.lower()
    return name.startswith("setupapi.dev")


@dataclass
class RegistryEvidence:
    """Records grouped by ``record_type``: (source_path, source_kind, record)."""

    by_type: dict[str, list[tuple[str, str, dict[str, Any]]]] = field(default_factory=dict)
    stats: dict[str, int] = field(default_factory=dict)

    def records(self, record_type: str, *, kinds: set[str] | frozenset[str] | None = None
                ) -> Iterator[tuple[str, str, dict[str, Any]]]:
        for path, kind, rec in self.by_type.get(record_type, ()):
            if kinds is None or kind in kinds:
                yield path, kind, rec

    def add(self, record_type: str, path: str, kind: str, rec: dict[str, Any]) -> None:
        self.by_type.setdefault(record_type, []).append((path, kind, rec))


def _job_lock(job_id: str) -> threading.Lock:
    with _cache_lock:
        lock = _job_locks.get(job_id)
        if lock is None:
            lock = _job_locks[job_id] = threading.Lock()
        return lock


def clear_registry_evidence_cache(job_id: str | None = None) -> None:
    with _cache_lock:
        if job_id is None:
            _cache.clear()
        else:
            _cache.pop(str(job_id), None)


def select_sources(rows: list[dict[str, Any]], covered_ids: set[str]) -> list[dict[str, Any]]:
    """One source per content hash, preferring a row whose parse result exists.

    Rows arrive largest-first. Identical VSS / backup copies (same SHA-256) must
    not multiply records; without a hash each row stands alone.
    """
    chosen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        digest = str(row.get("sha256") or "").strip().lower()
        key = f"sha:{digest}" if digest else f"id:{row.get('id')}"
        current = chosen.get(key)
        if current is None:
            chosen[key] = row
            order.append(key)
            continue
        if str(current.get("id")) not in covered_ids and str(row.get("id")) in covered_ids:
            chosen[key] = row
    return [chosen[k] for k in order]


def _source_rows(db, job_id: str) -> list[dict[str, Any]]:
    return fetchall(
        db,
        """SELECT id, file_path, file_name, size_bytes, sha256
           FROM job_artifacts
           WHERE job_id=:j AND size_bytes > 32 AND (
             lower(coalesce(file_name,'')) = ANY(:hives)
             OR lower(coalesce(file_name,'')) LIKE 'setupapi.dev%'
             OR file_path ~* '/(system|software|sam|security|default|ntuser\\.dat|usrclass\\.dat|amcache\\.hve)$'
             OR file_path ILIKE '%setupapi.dev%'
           )
           ORDER BY size_bytes DESC NULLS LAST, id
           LIMIT 4000""",
        {"j": job_id, "hives": list(HIVE_KINDS)},
    )


def _stored_records(db, ids: list[str]) -> tuple[set[str], list[dict[str, Any]]]:
    """Latest parse result per artifact (a re-parse must not double records)."""
    if not ids:
        return set(), []
    parsers = list(REGISTRY_PARSER_NAMES + SETUPAPI_PARSER_NAMES)
    covered = {
        str(r["aid"])
        for r in fetchall(
            db,
            """SELECT DISTINCT job_artifact_id AS aid FROM artifact_parse_results
               WHERE job_artifact_id = ANY(CAST(:ids AS uuid[]))
                 AND parser_name = ANY(:parsers)""",
            {"ids": ids, "parsers": parsers},
        )
    }
    if not covered:
        return covered, []
    rows = fetchall(
        db,
        """WITH latest AS (
             SELECT DISTINCT ON (apr.job_artifact_id) apr.job_artifact_id, apr.normalized
             FROM artifact_parse_results apr
             WHERE apr.job_artifact_id = ANY(CAST(:ids AS uuid[]))
               AND apr.parser_name = ANY(:parsers)
             ORDER BY apr.job_artifact_id, apr.created_at DESC NULLS LAST
           )
           SELECT l.job_artifact_id AS aid, elem AS rec
           FROM latest l
           CROSS JOIN LATERAL jsonb_array_elements(
             CASE WHEN jsonb_typeof(l.normalized)='array' THEN l.normalized ELSE '[]'::jsonb END
           ) AS elem
           WHERE elem->>'record_type' = ANY(:types)""",
        {"ids": sorted(covered), "parsers": parsers, "types": list(INDEXED_RECORD_TYPES)},
    )
    return covered, rows


def _live_records(db, job_id: str, rows: list[dict[str, Any]]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Parse raw bytes for sources without a stored parse — one shard pass per call."""
    if not rows:
        return
    from app.parsers.registry import parse_registry_hive
    from app.parsers.setupapi import parse_setupapi_log
    from app.services.artifact_live_counts import _read_job_files

    hives = [r for r in rows if hive_kind(r.get("file_path") or "") and int(r.get("size_bytes") or 0) > _HIVE_MIN_BYTES]
    setup = [r for r in rows if is_setupapi_path(r.get("file_path") or "")]
    for group, cap, parser in ((hives, None, parse_registry_hive), (setup, _SETUPAPI_MAX_BYTES, parse_setupapi_log)):
        if not group:
            continue
        contents = _read_job_files(db, job_id, group, max_bytes=cap)
        for row in group:
            path = (row.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            try:
                for rec in parser(data, path):
                    if isinstance(rec, dict) and rec.get("record_type") in INDEXED_RECORD_TYPES:
                        yield row, rec
            except Exception:
                log.debug("live registry fallback parse failed path=%s", path, exc_info=True)


def build_registry_evidence(db, job_id: str) -> RegistryEvidence:
    started = time.monotonic()
    out = RegistryEvidence()
    source_rows = _source_rows(db, job_id)
    ids = [str(r["id"]) for r in source_rows]
    covered, stored = _stored_records(db, ids)
    chosen = select_sources(source_rows, covered)
    chosen_ids = {str(r["id"]) for r in chosen}
    row_by_id = {str(r["id"]): r for r in source_rows}

    def _kind(path: str) -> str:
        return "setupapi" if is_setupapi_path(path) else (hive_kind(path) or "other")

    for item in stored:
        aid = str(item.get("aid"))
        if aid not in chosen_ids:
            continue  # duplicate content (VSS copy) already represented
        rec = item.get("rec")
        if not isinstance(rec, dict):
            continue
        path = str((row_by_id.get(aid) or {}).get("file_path") or "").replace("\\", "/")
        out.add(str(rec.get("record_type")), path, _kind(path), rec)

    uncovered = [r for r in chosen if str(r["id"]) not in covered]
    live_n = 0
    for row, rec in _live_records(db, job_id, uncovered):
        path = (row.get("file_path") or "").replace("\\", "/")
        out.add(str(rec.get("record_type")), path, _kind(path), rec)
        live_n += 1
    out.stats = {
        "source_files": len(source_rows),
        "unique_sources": len(chosen),
        "from_stored_parse": len(chosen) - len(uncovered),
        "live_fallback_sources": len(uncovered),
        "live_fallback_records": live_n,
        "records": sum(len(v) for v in out.by_type.values()),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    log.info("registry evidence index job=%s %s", job_id, out.stats)
    return out


def registry_evidence(db, job_id: str) -> RegistryEvidence:
    """Single-flight per job: concurrent collectors wait for one build and share it."""
    job_id = str(job_id)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(job_id)
        if hit and now - hit[0] < _CACHE_TTL_SEC:
            return hit[1]
    with _job_lock(job_id):
        with _cache_lock:
            hit = _cache.get(job_id)
            if hit and time.monotonic() - hit[0] < _CACHE_TTL_SEC:
                return hit[1]
        built = build_registry_evidence(db, job_id)
        with _cache_lock:
            _cache[job_id] = (time.monotonic(), built)
        return built
