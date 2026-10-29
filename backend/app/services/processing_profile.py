"""Standard / Deep processing profile — one place every stage reads it.

The profile is chosen at intake and stored in ``jobs.disk_source.processing_profile``.
Before this module each stage re-parsed ``disk_source`` itself, and only two stages
(extraction filter and signature carving) ever looked at it, so Standard and Deep
ran the same work after extraction.

Profiles
--------
standard
    Report-oriented examination. Selective extraction of user-space evidence and
    system forensic artifacts (vendor app assets and OS binaries are excluded and
    recorded), no unallocated signature carving, picture/video observations only
    for user-space media, no Neo4j graph, no semantic vectors (retrieval is
    lexical/FTS + parsed records, which is deterministic), no entity-mention
    statistics. Every skipped stage is recorded as a limitation in validation.
deep
    Full examination. Full extraction, carving, all media, graph, vectors.
legacy
    Jobs created before profiles existed. Behave exactly like ``deep`` so a
    resumed historical case does not silently lose coverage.
"""

from __future__ import annotations

import json
from typing import Any

from app.db.sql_helpers import fetchone

STANDARD = "standard"
DEEP = "deep"
LEGACY = "legacy"

# Stage -> examiner-facing reason recorded in the stage details and validation.
STANDARD_SKIPPED_STAGES: dict[str, str] = {
    "graph": (
        "Standard profile: Neo4j relationship graph not built. Report retrieval uses "
        "PostgreSQL full-text, keyword and parsed-record search, which do not depend on "
        "the graph. Reprocess as Deep examination for graph investigation."
    ),
}

STANDARD_LIMITATIONS: tuple[str, ...] = (
    "Standard profile: unallocated-space signature carving was not performed.",
    "Standard profile: operating-system binaries and vendor application assets "
    "(icons, UI scripts, fonts) were excluded from extraction; exclusions are listed "
    "in the extraction manifest.",
    "Standard profile: picture/video observations cover user-space media only.",
    "Standard profile: semantic (vector) retrieval was not built; report retrieval is "
    "lexical/full-text plus parsed records.",
    "Standard profile: Neo4j relationship graph was not built.",
)


def _disk_source(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return {}
    return raw if isinstance(raw, dict) else {}


def profile_from_disk_source(raw: Any) -> str:
    value = str(_disk_source(raw).get("processing_profile") or "").strip().lower()
    if value in (STANDARD, DEEP):
        return value
    return LEGACY


def job_processing_profile(db, job_id: str) -> str:
    """``standard`` | ``deep`` | ``legacy`` (pre-profile jobs behave like deep)."""
    try:
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    except Exception:
        return LEGACY
    return profile_from_disk_source((row or {}).get("disk_source"))


def is_standard(db, job_id: str) -> bool:
    return job_processing_profile(db, job_id) == STANDARD


def normalize_requested_profile(value: str | None) -> str | None:
    """``standard`` | ``deep`` | None (not given). Raises ValueError otherwise."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if not v:
        return None
    if v not in (STANDARD, DEEP):
        raise ValueError("processing_profile must be standard or deep")
    return v


def resolve_ingest_profile(requested: str | None, stored: str | None) -> str:
    """Profile to freeze at registration.

    Explicit request wins; otherwise the examiner's stored choice; otherwise
    Standard (the documented default for new disk jobs).
    """
    req = normalize_requested_profile(requested)
    if req:
        return req
    st = str(stored or "").strip().lower()
    return st if st in (STANDARD, DEEP) else STANDARD


def stored_profile(db, job_id: str) -> str | None:
    row = fetchone(db, "SELECT disk_source->>'processing_profile' AS p FROM jobs WHERE id=:id", {"id": job_id})
    value = str((row or {}).get("p") or "").strip().lower()
    return value if value in (STANDARD, DEEP) else None


def extraction_started(db, job_id: str) -> bool:
    """True once any file was extracted: the profile is then frozen for the case."""
    row = fetchone(
        db,
        """SELECT extracted_disk_uri, COALESCE(files_extracted, 0) AS fx,
                  (jsonb_typeof(disk_source->'parts_map') = 'object'
                     AND disk_source->'parts_map' <> '{}'::jsonb) AS has_parts,
                  COALESCE(disk_source->>'index_uri', '') <> '' AS has_index
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    ) or {}
    return bool(
        row.get("extracted_disk_uri")
        or int(row.get("fx") or 0) > 0
        or row.get("has_parts")
        or row.get("has_index")
    )


def set_job_processing_profile(db, job_id: str, profile: str) -> None:
    """Atomic jsonb_set — never a read-modify-write of the whole disk_source."""
    from app.db.sql_helpers import execute

    value = normalize_requested_profile(profile)
    if not value:
        raise ValueError("processing_profile must be standard or deep")
    execute(
        db,
        """UPDATE jobs SET disk_source =
               jsonb_set(COALESCE(disk_source, '{}'::jsonb), '{processing_profile}',
                         to_jsonb(CAST(:profile AS text)), true),
               updated_at = NOW()
           WHERE id = :jid""",
        {"profile": value, "jid": job_id},
    )


PROFILE_LABELS = {STANDARD: "Standard forensic", DEEP: "Deep examination", LEGACY: "Legacy (behaves as Deep)"}


# User-space media predicate for Standard picture/video observations.
# Vendor/OS image assets (Program Files, WindowsApps, Windows\SystemApps,
# Windows\Web, icon caches) are identical on every machine of a build and carry
# no case facts; user media lives under the profile trees and the recycle bin.
USER_SPACE_PATH_SQL = """(
  lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE 'users/%'
  OR lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE '%/users/%'
  OR lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE 'documents and settings/%'
  OR lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE '%/documents and settings/%'
  OR lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE '%$recycle.bin/%'
  OR lower(replace(coalesce(file_path,''), chr(92), '/')) LIKE '%recycler/%'
  OR (
    lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE 'windows/%'
    AND lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE '%/windows/%'
    AND lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE 'program files%'
    AND lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE '%/program files%'
    AND lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE 'programdata/%'
    AND lower(replace(coalesce(file_path,''), chr(92), '/')) NOT LIKE '%/programdata/%'
  )
)"""


def is_user_space_path(path: str) -> bool:
    """Python mirror of ``USER_SPACE_PATH_SQL`` (used by tests and callers without SQL)."""
    p = (path or "").replace("\\", "/").strip("/").lower()
    padded = f"/{p}"
    if p.startswith("users/") or "/users/" in padded:
        return True
    if p.startswith("documents and settings/") or "/documents and settings/" in padded:
        return True
    if "$recycle.bin/" in p or "recycler/" in p:
        return True
    vendor = (
        p.startswith("windows/") or "/windows/" in padded
        or p.startswith("program files") or "/program files" in padded
        or p.startswith("programdata/") or "/programdata/" in padded
    )
    return not vendor
