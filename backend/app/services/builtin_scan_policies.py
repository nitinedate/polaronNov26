"""Built-in scan policies (V1.8.0).

Field issue: the Launch dropdown only listed rows in ``vuln_scan_policies``.
Templates (Nexpose / Nessus equivalents) were never turned into rows, and
``scripts/_purge_all_jobs.sql`` and case deletion remove policy rows, so the
dropdown showed only "— default —".

Every template whose ``seed_as_builtin`` flag is true becomes one ready-to-use,
``active`` policy row per tenant. Seeding is idempotent (unique ``builtin_key``),
runs at most once per schema and template-catalog version per process, and
never breaks a request: on any database error it is skipped and logged.
Templates that need credentials, and the unsafe Denial-of-service template,
are not seeded; a policy manager creates them in Scan policies.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchone, rollback_aborted_transaction

log = logging.getLogger("builtin_scan_policies")

_DONE: set[tuple[str, str]] = set()
_LOCK = threading.Lock()

VENDOR_LABEL = {"polaron": "Polaron", "nexpose": "Nexpose", "nessus": "Nessus", "aetheris": "Aetheris"}


def seedable_templates() -> list[dict[str, Any]]:
    from app.services.scanner_service_policy import scan_templates

    return [t for t in scan_templates()["templates"] if t.get("seed_as_builtin")]


def builtin_name(template: dict[str, Any]) -> str:
    """Display name. Nexpose templates already carry their 'Nexpose · ' prefix."""
    name = str(template["name"])
    vendor = str(template.get("vendor") or "")
    if vendor == "nessus" and not name.startswith("Nessus"):
        return f"Nessus · {name}"
    return name


def ensure_builtin_policy_columns(db: Session) -> None:
    """Idempotent upgrade of old tenant tables (same pattern as scanner readiness columns)."""
    row = fetchone(
        db,
        """SELECT COUNT(*)::int AS n FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'vuln_scan_policies'
              AND column_name IN ('is_builtin', 'builtin_key')""",
    ) or {}
    if int(row.get("n") or 0) < 2:
        execute(
            db,
            """ALTER TABLE vuln_scan_policies
                 ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
                 ADD COLUMN IF NOT EXISTS builtin_key TEXT""",
        )
    execute(
        db,
        """CREATE UNIQUE INDEX IF NOT EXISTS ux_vuln_scan_policies_builtin_key
             ON vuln_scan_policies (builtin_key) WHERE builtin_key IS NOT NULL""",
    )


def _catalog_version() -> str:
    from app.services.scanner_service_policy import scan_templates

    return str(scan_templates().get("catalog_version") or "")


def _schema(db: Session) -> str:
    row = fetchone(db, "SELECT current_schema() AS s") or {}
    return str(row.get("s") or "")


def _builtin_rows_complete(db: Session, keys: list[str]) -> bool:
    """One cheap query: are all seedable templates present and active?"""
    row = fetchone(
        db,
        """SELECT COUNT(*)::int AS n FROM vuln_scan_policies
            WHERE is_builtin AND lifecycle_state = 'active' AND builtin_key = ANY(:keys)""",
        {"keys": keys},
    ) or {}
    return int(row.get("n") or 0) >= len(keys)


def ensure_builtin_policies(db: Session, *, force: bool = False) -> int:
    """Create or refresh built-in policy rows. Returns how many templates were (re)seeded.

    Never raises: a failure is logged and the caller continues with whatever
    rows exist. The column upgrade runs once per schema per process; the row
    check runs on every call so a purge (scripts/_purge_all_jobs.sql) or a
    deleted row is repaired on the next list, without an API restart.
    """
    try:
        schema = _schema(db)
        key = (schema, _catalog_version())
        templates = seedable_templates()
        keys = [t["key"] for t in templates]
        with _LOCK:
            with db.begin_nested():
                if key not in _DONE:
                    ensure_builtin_policy_columns(db)
                if not force and key in _DONE and _builtin_rows_complete(db, keys):
                    return 0
                for template in templates:
                    execute(
                        db,
                        """INSERT INTO vuln_scan_policies
                             (case_id, name, policy_type, settings_json, compliance_framework,
                              lifecycle_state, is_builtin, builtin_key, created_by)
                           VALUES (NULL, :name, :ptype, CAST(:settings AS jsonb), :fw,
                                   'active', TRUE, :bkey, NULL)
                           ON CONFLICT (builtin_key) WHERE builtin_key IS NOT NULL DO UPDATE
                             SET name = EXCLUDED.name,
                                 policy_type = EXCLUDED.policy_type,
                                 settings_json = EXCLUDED.settings_json,
                                 compliance_framework = EXCLUDED.compliance_framework,
                                 lifecycle_state = 'active',
                                 is_builtin = TRUE,
                                 updated_at = NOW()""",
                        {
                            "name": builtin_name(template),
                            "ptype": str(template.get("category") or "vulnerability"),
                            "settings": json.dumps({"template": template["key"]}),
                            "fw": template.get("compliance_framework"),
                            "bkey": template["key"],
                        },
                    )
                # A template that is no longer seedable stays usable by old jobs,
                # but is retired from the launch list.
                execute(
                    db,
                    """UPDATE vuln_scan_policies SET lifecycle_state = 'retired', updated_at = NOW()
                        WHERE is_builtin AND builtin_key IS NOT NULL
                          AND NOT (builtin_key = ANY(:keys)) AND lifecycle_state <> 'retired'""",
                    {"keys": keys},
                )
            db.commit()
            _DONE.add(key)
            log.info("Built-in scan policies ready in %s (%d templates)", schema, len(templates))
            return len(templates)
    except Exception:
        log.warning("Built-in scan policies could not be seeded; continuing with existing rows", exc_info=True)
        try:
            rollback_aborted_transaction(db)
        except Exception:
            pass
        return 0


def builtin_policy_id(db: Session, template_key: str) -> str | None:
    """Policy row id for a seeded template, seeding first if needed."""
    ensure_builtin_policies(db)
    try:
        row = fetchone(
            db,
            "SELECT id FROM vuln_scan_policies WHERE builtin_key = :k AND lifecycle_state = 'active' LIMIT 1",
            {"k": template_key},
        )
    except Exception:
        log.warning("Built-in policy lookup failed for %s", template_key, exc_info=True)
        return None
    return str(row["id"]) if row and row.get("id") else None


def reset_cache() -> None:
    """Tests and the purge script: forget which schemas were seeded."""
    with _LOCK:
        _DONE.clear()


__all__ = [
    "VENDOR_LABEL",
    "builtin_name",
    "builtin_policy_id",
    "ensure_builtin_policies",
    "ensure_builtin_policy_columns",
    "reset_cache",
    "seedable_templates",
]
