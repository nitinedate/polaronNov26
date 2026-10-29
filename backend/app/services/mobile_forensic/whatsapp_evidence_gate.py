"""Platform-aware WhatsApp evidence preparation gate.

This gate runs after the mobile platform has been verified and before normal
WhatsApp parsing.  It preserves encrypted originals, prepares authenticated
working copies when authorised key/credential material is available, and
records a non-fatal key-required state when it is not.

The gate never modifies acquisition/source bytes and never fabricates keys.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

log = logging.getLogger("mobile_forensic.whatsapp_gate")


def _meta(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _safe_name(path: str) -> str:
    name = PurePosixPath(str(path or "").replace("\\", "/")).name or "whatsapp-evidence.bin"
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(". ") or "whatsapp-evidence.bin"
    return name[:180]


def _platform_name(value: str | None) -> str | None:
    from app.services.mobile_os import normalize_mobile_os

    family = normalize_mobile_os(value)
    return family if family in {"android", "ios"} else None


def _persist_gate_state(db, job_id: str, result: dict[str, Any]) -> None:
    from app.db.sql_helpers import execute

    patch = {"whatsapp_evidence_gate": result}
    try:
        execute(
            db,
            """UPDATE jobs
               SET disk_source=coalesce(disk_source,'{}'::jsonb) || CAST(:patch AS jsonb),
                   updated_at=NOW()
               WHERE id=:jid""",
            {"jid": job_id, "patch": json.dumps(patch)},
        )
    except Exception:
        # Some older schemas do not expose updated_at on jobs.  Do not block the
        # forensic pipeline merely because status metadata could not be stamped.
        try:
            execute(
                db,
                """UPDATE jobs
                   SET disk_source=coalesce(disk_source,'{}'::jsonb) || CAST(:patch AS jsonb)
                   WHERE id=:jid""",
                {"jid": job_id, "patch": json.dumps(patch)},
            )
        except Exception as exc:
            log.warning("could not persist WhatsApp gate state job=%s: %s", job_id, exc)


def _stamp_platform_paths(db, job_id: str, platform: str, rows: list[dict[str, Any]]) -> None:
    """Stamp a stable case-relative logical path without moving source evidence."""
    from app.db.sql_helpers import execute
    for row in rows:
        source_path = str(row.get("file_path") or "")
        if not source_path:
            continue
        name = _safe_name(source_path)
        lower = source_path.lower().replace("\\", "/")
        if platform == "android" and ".crypt" in PurePosixPath(lower).name:
            canonical = f"mobile/android/encrypted/whatsapp/{name}"
        elif platform == "ios":
            canonical = f"mobile/ios/whatsapp/database/{name}"
        else:
            canonical = f"mobile/android/whatsapp/database/{name}"
        patch = {"whatsapp_case_path": {"platform": platform, "canonical_path": canonical, "source_path": source_path}}
        try:
            execute(db, """UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb)||CAST(:patch AS jsonb), updated_at=NOW()
                            WHERE job_id=:jid AND file_path=:path""",
                    {"jid": job_id, "path": source_path, "patch": json.dumps(patch)})
        except Exception as exc:
            log.warning("could not stamp WhatsApp case path job=%s path=%s: %s", job_id, source_path, exc)


def _preserve_android_encrypted_sources(db, job_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Write exact encrypted bytes to the canonical Android case namespace.

    A second job_artifacts row is deliberately not created, avoiding duplicate
    evidence counts.  Instead the original artifact receives preservation URI,
    SHA-256 and canonical path metadata.
    """
    from app.db.sql_helpers import execute
    from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes
    from app.services.mobile_forensic.whatsapp_crypt import MAX_PAYLOAD_BYTES, is_whatsapp_crypt_path
    from app.services.storage import put_bytes

    preserved = 0
    failed = 0
    skipped = 0
    paths: list[str] = []
    for row in rows:
        source_path = str(row.get("file_path") or "")
        if not is_whatsapp_crypt_path(source_path):
            continue
        old = _meta(_meta(row.get("metadata")).get("whatsapp_preservation"))
        if old.get("state") == "preserved" and old.get("uri") and old.get("sha256"):
            preserved += 1
            paths.append(str(old.get("canonical_path") or ""))
            continue
        expected = int(row.get("size_bytes") or 0)
        if expected <= 0 or expected > MAX_PAYLOAD_BYTES:
            skipped += 1
            patch = {
                "whatsapp_preservation": {
                    "state": "deferred",
                    "reason": "source_size_unavailable_or_over_gate_limit",
                    "platform": "android",
                    "source_path": source_path,
                }
            }
            execute(db, """UPDATE job_artifacts
                            SET metadata=coalesce(metadata,'{}'::jsonb)||CAST(:patch AS jsonb), updated_at=NOW()
                            WHERE job_id=:jid AND file_path=:path""",
                    {"jid": job_id, "path": source_path, "patch": json.dumps(patch)})
            continue
        raw = _read_artifact_bytes(db, job_id, source_path, max_bytes=expected + 1)
        if raw is None or len(raw) != expected:
            failed += 1
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if row.get("sha256") and str(row.get("sha256")) != digest:
            failed += 1
            continue
        canonical = f"mobile/android/encrypted/whatsapp/{digest[:24]}/{_safe_name(source_path)}"
        uri = put_bytes(f"jobs/{job_id}/{canonical}", raw, "application/octet-stream")
        patch = {
            "whatsapp_preservation": {
                "state": "preserved",
                "platform": "android",
                "source_path": source_path,
                "canonical_path": canonical,
                "uri": uri,
                "sha256": digest,
                "size_bytes": len(raw),
                "source_untouched": True,
            }
        }
        execute(db, """UPDATE job_artifacts
                        SET sha256=COALESCE(sha256,:sha),
                            metadata=coalesce(metadata,'{}'::jsonb)||CAST(:patch AS jsonb), updated_at=NOW()
                        WHERE job_id=:jid AND file_path=:path""",
                {"jid": job_id, "path": source_path, "sha": digest, "patch": json.dumps(patch)})
        preserved += 1
        paths.append(canonical)
    return {"preserved": preserved, "failed": failed, "deferred": skipped, "canonical_paths": paths}


def _ios_gate(db, job_id: str, disk_source: dict[str, Any]) -> dict[str, Any]:
    from app.db.sql_helpers import fetchall
    from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source

    rows = fetchall(
        db,
        """SELECT file_path,file_name,size_bytes,sha256,metadata FROM job_artifacts
           WHERE job_id=:jid AND (
             lower(file_path) LIKE '%chatstorage.sqlite%' OR
             lower(file_path) LIKE '%chatstorage.sqlite-wal%' OR
             lower(file_path) LIKE '%chatstorage.sqlite-shm%' OR
             lower(file_path) LIKE '%manifest.db%' OR
             lower(file_path) LIKE '%manifest.plist%' OR
             (lower(file_path) LIKE '%whatsapp%' AND (lower(file_path) LIKE '%.enc' OR lower(file_name) LIKE '%.enc'))
           )
           ORDER BY file_path""",
        {"jid": job_id},
    )
    _stamp_platform_paths(db, job_id, "ios", rows)
    paths = [str(r.get("file_path") or "") for r in rows]
    chatstorage = [p for p in paths if "chatstorage.sqlite" in p.lower() and not p.lower().endswith(("-wal", "-shm", "-journal"))]
    wal = [p for p in paths if p.lower().endswith(("-wal", "-journal")) and "chatstorage.sqlite" in p.lower()]
    manifests = [p for p in paths if p.lower().endswith(("manifest.db", "manifest.plist"))]
    protected = [p for p in paths if p.lower().endswith(".enc")]
    intake = load_intake_keys_from_disk_source(disk_source)
    password_present = bool(intake.get("ios_backup_password"))

    # If ChatStorage is already readable, decryption occurred during acquisition/
    # import and parsing can proceed immediately.  If it is absent but an encrypted
    # backup/protected object is present, the gate records the credential gap rather
    # than attempting unsupported key guessing.
    if chatstorage:
        state = "ready"
        reason = "plaintext_chatstorage_available"
    elif protected and not password_present:
        state = "credential_required"
        reason = "protected_ios_whatsapp_without_authorized_credential"
    elif manifests and password_present:
        state = "partial"
        reason = "authorized_backup_credential_present_but_chatstorage_not_materialized"
    elif manifests:
        state = "partial"
        reason = "ios_backup_present_but_chatstorage_not_found"
    else:
        state = "not_found"
        reason = "whatsapp_chat_database_not_present_in_acquisition"

    return {
        "platform": "ios",
        "state": state,
        "reason": reason,
        "source_root": "mobile/ios/whatsapp",
        "decrypted_root": "derived/mobile/ios/whatsapp_decrypted",
        "chatstorage_files": len(chatstorage),
        "wal_or_journal_files": len(wal),
        "manifest_files": len(manifests),
        "protected_files": len(protected),
        "authorized_backup_credential_present": password_present,
        "chatstorage_paths": chatstorage[:20],
        "recovery_enabled": bool(chatstorage),
    }


def prepare_whatsapp_evidence(db, job_id: str, *, platform: str | None = None, progress=None) -> dict[str, Any]:
    """Run the mandatory WhatsApp preparation/decryption gate.

    This function is intentionally non-fatal for a missing key.  Other mobile
    evidence continues to process, while WhatsApp is surfaced as key/credential
    required and can be retried when authorised material is supplied.
    """
    from app.db.sql_helpers import fetchall, fetchone
    from app.services.mobile_platform_agents import (
        mobile_os_family_from_job_row,
        reconcile_mobile_platform_from_registered_evidence,
    )

    job = fetchone(db, "SELECT type,disk_source FROM jobs WHERE id=:jid", {"jid": job_id}) or {}
    ds = _meta(job.get("disk_source"))
    detected = None
    try:
        detected = reconcile_mobile_platform_from_registered_evidence(db, job_id)
    except Exception as exc:
        log.warning("WhatsApp gate platform reconciliation failed job=%s: %s", job_id, exc)
    family = detected or _platform_name(platform) or mobile_os_family_from_job_row(job)
    if family not in {"android", "ios"}:
        result = {
            "stage": "whatsapp_evidence_preparation",
            "state": "platform_unknown",
            "platform": None,
            "blocking_whatsapp_only": True,
            "message": "Android/iPhone platform could not be verified; WhatsApp-specific decryption was not guessed.",
        }
        _persist_gate_state(db, job_id, result)
        return result

    if family == "ios":
        ios = _ios_gate(db, job_id, ds)
        result = {
            "stage": "whatsapp_evidence_preparation",
            **ios,
            "blocking_whatsapp_only": ios["state"] in {"credential_required", "not_found"},
            "normal_mobile_processing_continues": True,
        }
        _persist_gate_state(db, job_id, result)
        return result

    from app.services.mobile_forensic.whatsapp_crypt import is_whatsapp_crypt_path
    from app.services.mobile_forensic.sqlite_counts import discover_whatsapp_keys
    from app.services.mobile_forensic.whatsapp_derivation import materialize_registered_whatsapp_backups

    rows = fetchall(
        db,
        """SELECT file_path,file_name,size_bytes,sha256,metadata FROM job_artifacts
           WHERE job_id=:jid AND (
              lower(file_path) ~ '\\.crypt[a-z0-9_-]*$' OR
              lower(file_path) LIKE '%msgstore.db%' OR
              lower(file_path) LIKE '%wa.db%' OR
              lower(file_path) LIKE '%whatsapp%'
           ) ORDER BY file_path""",
        {"jid": job_id},
    )
    _stamp_platform_paths(db, job_id, "android", rows)
    crypt_rows = [r for r in rows if is_whatsapp_crypt_path(str(r.get("file_path") or ""))]
    plaintext = [str(r.get("file_path") or "") for r in rows
                 if PurePosixPath(str(r.get("file_path") or "").replace("\\", "/")).name.lower() in {"msgstore.db", "wa.db"}]
    keys = discover_whatsapp_keys(db, job_id)
    preservation = _preserve_android_encrypted_sources(db, job_id, crypt_rows)
    decrypt = materialize_registered_whatsapp_backups(db, job_id, progress=progress, platform="android")

    encrypted_count = len(crypt_rows)
    blocked = int(decrypt.get("blocked_files") or 0)
    decrypted = int(decrypt.get("decrypted_files") or 0)
    if plaintext or decrypted:
        state = "ready" if blocked == 0 else "partial"
    elif encrypted_count and not keys:
        state = "key_required"
    elif encrypted_count:
        state = "blocked"
    else:
        state = "not_found"

    result = {
        "stage": "whatsapp_evidence_preparation",
        "platform": "android",
        "state": state,
        "source_root": "mobile/android/whatsapp",
        "encrypted_root": "mobile/android/encrypted/whatsapp",
        "decrypted_root": "derived/mobile/android/whatsapp_decrypted",
        "encrypted_files": encrypted_count,
        "plaintext_databases": len(plaintext),
        "authorized_key_candidates": len(keys),
        "preservation": preservation,
        "decryption": decrypt,
        "recovery_enabled": bool(plaintext or decrypted),
        "blocking_whatsapp_only": state in {"key_required", "blocked", "not_found"},
        "normal_mobile_processing_continues": True,
        "message": (
            "WhatsApp database ready for active + deleted chat parsing."
            if state == "ready" else
            "Some WhatsApp sources are ready; blocked encrypted sources remain preserved for retry."
            if state == "partial" else
            "Encrypted WhatsApp chat backup preserved; matching authorized key material is required."
            if state == "key_required" else
            "WhatsApp encrypted source could not be authenticated/decrypted with the available authorized material."
            if state == "blocked" else
            "No WhatsApp chat database/backup was present in this acquisition."
        ),
    }
    _persist_gate_state(db, job_id, result)
    return result
