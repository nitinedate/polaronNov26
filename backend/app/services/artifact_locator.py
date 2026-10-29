"""Fast byte access for opening one artifact.

Before this module every click on an artifact without its own MinIO object did:

1. ``_job_index_map`` — download and zstd-decompress the *entire* extraction
   index (all shards, 50k–250k entries) to find one path; then
2. ``read_files_from_part`` — decompress the single-frame zstd tar shard from
   byte 0 until the member is reached (multi-GB for members late in a shard).

Now:

* ``job_artifact_locations`` (PRIMARY KEY ``(job_id, path)``) is built once per
  job from the manifest index and answers "which shard holds this path" with
  one index lookup.
* For disk images the file is read **from the original evidence first**
  (TSK on the mounted, read-only E01/raw image): cost is the file size, not the
  shard position.  Bytes are accepted only when size and, where recorded,
  SHA-256 match the extraction record; deleted entries without a recorded hash
  are never read by path (the name may now point at a different inode).
* The shard remains the fallback, located through the index.

Switch: ``ARTIFACT_READ_SOURCE_FIRST=0`` restores shard-first reading.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any

from sqlalchemy import text

from app.db.sql_helpers import fetchone

log = logging.getLogger("artifact_locator")

SOURCE_FIRST = os.environ.get("ARTIFACT_READ_SOURCE_FIRST", "1").strip().lower() not in ("0", "false", "no")
_SOURCE_MODES = frozenset({"ewf", "raw"})
_VD_FAIL_TTL = 120.0
_BATCH = 5000

_LOCATIONS_DDL = (
    """CREATE TABLE IF NOT EXISTS job_artifact_locations (
           job_id UUID NOT NULL,
           path TEXT NOT NULL,
           part_uri TEXT NOT NULL,
           part_id INTEGER,
           data_offset BIGINT,
           size_bytes BIGINT,
           sha256 TEXT,
           PRIMARY KEY (job_id, path)
       )""",
    """CREATE TABLE IF NOT EXISTS job_artifact_location_builds (
           job_id UUID PRIMARY KEY,
           fingerprint TEXT NOT NULL,
           entry_count INTEGER NOT NULL DEFAULT 0,
           built_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
       )""",
)

_ready_schemas: set[str] = set()
_ready_lock = threading.Lock()
_job_locks: dict[str, threading.Lock] = {}
_job_locks_guard = threading.Lock()
_vd_failures: dict[str, float] = {}


def _job_lock(job_id: str) -> threading.Lock:
    with _job_locks_guard:
        lock = _job_locks.get(job_id)
        if lock is None:
            lock = threading.Lock()
            _job_locks[job_id] = lock
        return lock


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/")


def _current_schema(db) -> str:
    try:
        row = fetchone(db, "SELECT current_schema() AS s")
        return str((row or {}).get("s") or "public")
    except Exception:
        return "public"


def ensure_location_tables(db) -> bool:
    schema = _current_schema(db)
    with _ready_lock:
        if schema in _ready_schemas:
            return True
    try:
        with db.begin_nested():
            for ddl in _LOCATIONS_DDL:
                db.execute(text(ddl))
        db.commit()
    except Exception:
        log.warning("job_artifact_locations unavailable in schema %s", schema, exc_info=True)
        return False
    with _ready_lock:
        _ready_schemas.add(schema)
    return True


def _load_manifest(db, job_id: str) -> dict[str, Any]:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    manifest = row.get("disk_source") or {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except json.JSONDecodeError:
            manifest = {}
    return manifest if isinstance(manifest, dict) else {}


def manifest_fingerprint(manifest: dict[str, Any]) -> str:
    """Changes whenever the shard set or its indexes change (re-extraction)."""
    parts = manifest.get("parts_map") or {}
    if not parts and manifest.get("parts"):
        parts = {str(i): u for i, u in enumerate(manifest.get("parts") or [])}
    basis = {
        "index_uri": manifest.get("index_uri") or "",
        "shard_indexes": {str(k): v for k, v in sorted((manifest.get("shard_indexes") or {}).items(), key=lambda x: str(x[0]))},
        "parts": {str(k): v for k, v in sorted(parts.items(), key=lambda x: str(x[0]))},
    }
    return hashlib.sha1(json.dumps(basis, sort_keys=True).encode()).hexdigest()


def location_rows(manifest: dict[str, Any], entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Index entries -> table rows; last entry for a path wins (as build_index_map)."""
    from app.services.disk_manifest import resolve_part_uri

    by_path: dict[str, dict[str, Any]] = {}
    for e in entries:
        path = _norm(str(e.get("path") or ""))
        if not path:
            continue
        try:
            part_id = int(e.get("part_id", 0))
        except (TypeError, ValueError):
            part_id = 0
        uri = resolve_part_uri(manifest, part_id)
        if not uri:
            continue
        by_path[path] = {
            "path": path,
            "part_uri": uri,
            "part_id": part_id,
            "data_offset": e.get("offset"),
            "size_bytes": e.get("size_bytes"),
            "sha256": e.get("sha256") or None,
        }
    return list(by_path.values())


def build_locations(db, job_id: str, *, force: bool = False) -> int:
    """Populate ``job_artifact_locations`` for one job (single-flight)."""
    from app.services.disk_manifest import load_index_entries

    if not ensure_location_tables(db):
        return -1
    manifest = _load_manifest(db, job_id)
    if not (manifest.get("index_uri") or manifest.get("shard_indexes")):
        return 0
    fp = manifest_fingerprint(manifest)
    with _job_lock(job_id):
        done = fetchone(
            db, "SELECT fingerprint, entry_count FROM job_artifact_location_builds WHERE job_id=:j", {"j": job_id}
        )
        if done and done.get("fingerprint") == fp and not force:
            return int(done.get("entry_count") or 0)
        started = time.monotonic()
        rows = location_rows(manifest, load_index_entries(manifest))
        try:
            with db.begin_nested():
                db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"artloc:{job_id}"})
                db.execute(text("DELETE FROM job_artifact_locations WHERE job_id=:j"), {"j": job_id})
                for i in range(0, len(rows), _BATCH):
                    chunk = [dict(r, job_id=job_id) for r in rows[i:i + _BATCH]]
                    db.execute(
                        text(
                            """INSERT INTO job_artifact_locations
                                 (job_id, path, part_uri, part_id, data_offset, size_bytes, sha256)
                               VALUES (:job_id, :path, :part_uri, :part_id, :data_offset, :size_bytes, :sha256)
                               ON CONFLICT (job_id, path) DO UPDATE SET
                                 part_uri=EXCLUDED.part_uri, part_id=EXCLUDED.part_id,
                                 data_offset=EXCLUDED.data_offset, size_bytes=EXCLUDED.size_bytes,
                                 sha256=EXCLUDED.sha256"""
                        ),
                        chunk,
                    )
                db.execute(
                    text(
                        """INSERT INTO job_artifact_location_builds (job_id, fingerprint, entry_count, built_at)
                           VALUES (:j, :fp, :n, NOW())
                           ON CONFLICT (job_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,
                             entry_count=EXCLUDED.entry_count, built_at=NOW()"""
                    ),
                    {"j": job_id, "fp": fp, "n": len(rows)},
                )
            db.commit()
        except Exception:
            log.warning("location index build failed job=%s", job_id, exc_info=True)
            try:
                db.rollback()
            except Exception:
                pass
            return -1
        log.info("artifact location index job=%s entries=%d in %.1fs", job_id, len(rows), time.monotonic() - started)
        return len(rows)


def locate(db, job_id: str, path: str) -> dict[str, Any] | None:
    """Shard location for one path, building the index on first use."""
    norm = _norm(path)
    if not norm or not ensure_location_tables(db):
        return None
    sql = """SELECT part_uri, part_id, data_offset, size_bytes, sha256
             FROM job_artifact_locations WHERE job_id=:j AND path=:p"""
    try:
        row = fetchone(db, sql, {"j": job_id, "p": norm})
        if row:
            return dict(row)
        if build_locations(db, job_id) <= 0:
            return None
        row = fetchone(db, sql, {"j": job_id, "p": norm})
        return dict(row) if row else None
    except Exception:
        log.debug("locate failed job=%s path=%s", job_id, norm, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Source-first reading
# ---------------------------------------------------------------------------

def _is_deleted(row: dict[str, Any]) -> bool:
    meta = row.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    flag = str((meta or {}).get("is_deleted") or "").lower() in ("true", "1", "t", "yes")
    low = _norm(str(row.get("file_path") or "")).lower()
    return flag or "$orphanfiles" in low or low.startswith("unallocated") or "/$recycle.bin/$r" in low


def _source_disk(db, job_id: str):
    failed_at = _vd_failures.get(job_id)
    if failed_at and time.monotonic() - failed_at < _VD_FAIL_TTL:
        return None
    try:
        from app.services.virtual_disk import open_virtual_disk_cached

        vd = open_virtual_disk_cached(db, job_id)
    except Exception as exc:
        _vd_failures[job_id] = time.monotonic()
        log.debug("source evidence unavailable job=%s: %s", job_id, exc)
        return None
    if getattr(vd, "mode", "") not in _SOURCE_MODES or not getattr(vd, "_fs_info", None):
        return None
    return vd


def source_read_allowed(row: dict[str, Any]) -> bool:
    if not SOURCE_FIRST:
        return False
    if _is_deleted(row) and not row.get("sha256"):
        return False
    return bool(row.get("file_path"))


def read_from_source(db, job_id: str, row: dict[str, Any], *, max_bytes: int | None) -> bytes | None:
    """Read one file from the original image; None unless it verifies."""
    if not source_read_allowed(row):
        return None
    vd = _source_disk(db, job_id)
    if vd is None:
        return None
    from app.services.virtual_disk import read_full_file_from_disk

    path = _norm(str(row.get("file_path") or "")).lstrip("/")
    expected_size = row.get("size_bytes")
    try:
        expected_size = int(expected_size) if expected_size not in (None, "") else None
    except (TypeError, ValueError):
        expected_size = None
    full_read = max_bytes is None or (expected_size is not None and expected_size <= max_bytes)
    try:
        data = read_full_file_from_disk(vd, path, max_bytes=None if full_read else max_bytes)
    except Exception as exc:
        log.debug("source read failed job=%s path=%s: %s", job_id, path, exc)
        return None
    if data is None:
        return None
    if full_read:
        if expected_size is not None and expected_size > 0 and len(data) != expected_size:
            log.info("source read size mismatch job=%s path=%s got=%d want=%d", job_id, path, len(data), expected_size)
            return None
        expected_hash = str(row.get("sha256") or "").strip().lower()
        if expected_hash and hashlib.sha256(data).hexdigest() != expected_hash:
            log.warning("source read SHA-256 mismatch job=%s path=%s — using extracted copy", job_id, path)
            return None
    return data


def read_from_located_shard(db, job_id: str, row: dict[str, Any], *, max_bytes: int | None) -> tuple[bool, bytes | None]:
    """``(located, data)``. ``located`` False means the index could not place the path
    (no manifest index, or table unavailable) and the caller may use its legacy reader;
    True with ``data`` None means the shard was read and the member was absent."""
    from app.services.tar_cache import read_file_from_part

    path = _norm(str(row.get("file_path") or ""))
    loc = locate(db, job_id, path)
    if not loc:
        return False, None
    try:
        return True, read_file_from_part(loc["part_uri"], path, max_bytes=max_bytes)
    except Exception:
        log.debug("located shard read failed job=%s path=%s", job_id, path, exc_info=True)
        return True, None


def iter_from_source(db, job_id: str, row: dict[str, Any], *, max_bytes: int | None, chunk_size: int = 1_048_576):
    """Streaming variant for downloads. Only for live entries with a known size."""
    if not source_read_allowed(row) or _is_deleted(row):
        return None
    vd = _source_disk(db, job_id)
    if vd is None:
        return None
    from app.services.virtual_disk import iter_file_from_disk

    path = _norm(str(row.get("file_path") or "")).lstrip("/")
    try:
        gen = iter_file_from_disk(vd, path, max_bytes=max_bytes, chunk_size=chunk_size)
        first = next(gen)
    except StopIteration:
        return None
    except Exception:
        return None

    def _chain():
        yield first
        yield from gen

    return _chain()
