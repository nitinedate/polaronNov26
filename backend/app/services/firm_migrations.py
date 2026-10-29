"""Apply idempotent firm-scoped migrations for existing organizations."""

from __future__ import annotations

import logging
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.platform import Firm
from app.services.firm_schema_apply import apply_firm_extension_functions

log = logging.getLogger("firm_migrations")


def apply_firm_migrations(db: Session, schema_name: str) -> None:
    """Re-apply all firm extension functions (safe / IF NOT EXISTS)."""
    apply_firm_extension_functions(db, schema_name, strict=False)
    try:
        from app.services.pipeline_heal import ensure_pipeline_heal_table

        ensure_pipeline_heal_table(db, schema_name)
    except Exception as exc:
        log.warning("pipeline_heal ensure failed for %s: %s", schema_name, exc)


def boot_migrations_disabled() -> bool:
    """True when this stack should NOT run firm DDL at boot.

    Every Compose stack (forensic, mobile-android, mobile-ios, mobile-extract,
    vuln) shares one PostgreSQL. Each stack's api re-runs the idempotent
    ``ALTER TABLE … ADD COLUMN IF NOT EXISTS`` migrations at startup. When another
    stack is already up, its workers hold locks/transactions on shared tables
    (``firm_p.jobs`` …), so these ALTERs block until lock_timeout, one after
    another — minutes of doomed work that pushes the api past its healthcheck
    window even though the schema is already current.

    Only the **forensic** stack owns the schema and applies these migrations; every
    other stack (mobile *and* vuln) is a secondary consumer of the same DB and
    skips them so it boots promptly. Override per stack with
    ``AETHERIS_SKIP_BOOT_MIGRATIONS=1`` (force skip) or ``=0`` (force run) — e.g. to
    run a non-forensic stack standalone against its own database.
    """
    value = (os.environ.get("AETHERIS_SKIP_BOOT_MIGRATIONS") or "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False  # explicit override: force this stack to run them
    # Default: only the forensic stack (DB owner) runs boot migrations; all other
    # stacks skip and start promptly instead of queueing behind forensic's locks.
    try:
        from app.service_identity import FORENSIC, current_service

        return str(current_service()) != FORENSIC
    except Exception:
        return False


def apply_all_firm_migrations(db: Session) -> int:
    if boot_migrations_disabled():
        log.info("firm migrations skipped at boot (AETHERIS_SKIP_BOOT_MIGRATIONS set)")
        return 0
    firms = db.execute(select(Firm).where(Firm.status == "active")).scalars().all()
    for firm in firms:
        if not firm.schema_name:
            continue
        try:
            apply_firm_migrations(db, firm.schema_name)
        except Exception as exc:
            log.warning("firm migration skipped for %s: %s", firm.schema_name, exc)
    db.commit()
    return len(firms)
