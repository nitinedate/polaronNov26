"""Authenticate on-site scanner agents via bearer token + X-Tenant."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, apply_firm_search_path, bind_firm_schema
from app.db.sql_helpers import execute, fetchall, fetchone
from app.models.platform import Firm

bearer = HTTPBearer(auto_error=False)

EDGE_AGENT_URL = "agent://local"
CONNECTION_MODE_EDGE = "edge_agent"
CONNECTION_MODE_GMP = "gmp"


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_agent_token() -> str:
    return secrets.token_urlsafe(32)


def token_hint(token: str) -> str:
    return token[-4:] if len(token) >= 4 else token


PREVIOUS_TOKEN_GRACE_HOURS = 24


def ensure_edge_agent_readiness_columns(db: Session) -> None:
    """Upgrade old tenant tables once; normal heartbeats only read column metadata."""
    row = fetchone(db, """SELECT COUNT(*)::int AS n FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='vuln_scanners'
        AND column_name IN ('openvas_ready','agent_status_detail','openvas_ready_at')""") or {}
    if int(row.get("n") or 0) == 3:
        return
    execute(db, """ALTER TABLE vuln_scanners ADD COLUMN IF NOT EXISTS openvas_ready boolean,
        ADD COLUMN IF NOT EXISTS agent_status_detail text,
        ADD COLUMN IF NOT EXISTS openvas_ready_at timestamptz""")
    db.flush()


def ensure_edge_agent_recovery_columns(db: Session) -> None:
    """Best-effort ADD COLUMN for recovery/grace fields (idempotent)."""
    try:
        execute(
            db,
            """ALTER TABLE vuln_scanners
               ADD COLUMN IF NOT EXISTS agent_recovery_token_hash TEXT,
               ADD COLUMN IF NOT EXISTS agent_previous_token_hash TEXT,
               ADD COLUMN IF NOT EXISTS agent_previous_token_valid_until TIMESTAMPTZ,
               ADD COLUMN IF NOT EXISTS agent_computer_name TEXT,
               ADD COLUMN IF NOT EXISTS agent_instance_id TEXT""",
        )
        db.flush()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def is_edge_agent_scanner(row: dict[str, Any] | None) -> bool:
    if not row:
        return False
    mode = str(row.get("connection_mode") or CONNECTION_MODE_GMP).strip().lower()
    if mode == CONNECTION_MODE_EDGE:
        return True
    url = str(row.get("url") or "").strip().lower()
    return url.startswith("agent://")


_log = logging.getLogger(__name__)


# --- V1.10.0: which laptop is calling ------------------------------------------
# The emailed access token identifies a USER, not a laptop: every laptop of that
# user binds the same token. Agent requests were resolved with "token hash ...
# LIMIT 1", so all of a user's laptops landed on one scanner record (heartbeats,
# job claims) and the others stayed "offline" (Laptop-DESKTOP-J19GUGP vs
# Laptop-NITIN). The agent now also sends its Windows computer name and its
# per-install instance id; together with the token they pick (or register) the
# laptop's own scanner record.

def normalize_computer_name(value: Any) -> str:
    """Windows computer name as sent by the laptop, reduced to safe characters."""
    return re.sub(r"[^A-Za-z0-9._-]", "", str(value or "").strip())[:63]


def _fold(value: Any) -> str:
    return str(value or "").strip().casefold()


def _names_for(computer: str, wanted_name: str) -> set[str]:
    names = {_fold(wanted_name)} if _fold(wanted_name) else set()
    if computer:
        names.add(_fold(f"Laptop-{computer}"))
    return names


def _another_laptops_auto_name(name: Any, own_names: set[str]) -> bool:
    """True for "Laptop-<other computer>": that record belongs to a different laptop."""
    folded = _fold(name)
    return folded.startswith("laptop-") and folded not in own_names


def _legacy_order(row: dict[str, Any]) -> tuple:
    hb = row.get("last_heartbeat_at")
    try:
        ts = -hb.timestamp() if hb is not None else 0.0
    except AttributeError:
        ts = 0.0
    return (0 if hb is not None else 1, ts, _fold(row.get("name")), str(row.get("id")))


def pick_laptop_scanner(
    rows: list[dict[str, Any]],
    *,
    computer: str,
    instance: str,
    wanted_name: str = "",
    preferred_id: str = "",
) -> tuple[dict[str, Any] | None, bool]:
    """Pick the scanner record of the calling laptop among ``rows``.

    Returns ``(row, claim)``; ``claim`` means the row's laptop identity
    (computer name / instance id) should be stored. ``(None, False)`` means no
    record belongs to this laptop yet. Never returns a record already bound to a
    different computer, nor one named after another laptop ("Laptop-<other>").
    Without a computer name (agent older than V1.10.0) the previous behaviour is
    kept, made deterministic: the instance id if known, else the most recently
    seen record.
    """
    if not rows:
        return None, False
    comp = _fold(normalize_computer_name(computer))
    inst = str(instance or "").strip()
    if not comp:
        if inst:
            for row in rows:
                if str(row.get("agent_instance_id") or "") == inst:
                    return row, False
        if preferred_id:
            for row in rows:
                if str(row.get("id")) == preferred_id:
                    return row, False
        return sorted(rows, key=_legacy_order)[0], False

    own = _names_for(normalize_computer_name(computer), wanted_name)
    same_computer = [r for r in rows if _fold(r.get("agent_computer_name")) == comp]
    if same_computer:
        for row in same_computer:
            if inst and str(row.get("agent_instance_id") or "") == inst:
                return row, False
        row = same_computer[0]
        return row, bool(inst and str(row.get("agent_instance_id") or "") != inst)

    unbound = [r for r in rows if not _fold(r.get("agent_computer_name"))]
    if preferred_id:
        for row in unbound:
            if str(row.get("id")) == preferred_id and not _another_laptops_auto_name(row.get("name"), own):
                return row, True
    for row in unbound:
        if _fold(row.get("name")) in own:
            return row, True
    if inst:
        for row in unbound:
            if str(row.get("agent_instance_id") or "") == inst and not _another_laptops_auto_name(row.get("name"), own):
                return row, True
    if len(rows) == 1 and unbound and not _another_laptops_auto_name(unbound[0].get("name"), own):
        # One laptop before V1.10.0, possibly renamed in the UI: keep its record.
        return unbound[0], True
    return None, False


_TOKEN_MATCH_SQL = """(agent_token_hash = :th
                      OR agent_recovery_token_hash = :th
                      OR (agent_previous_token_hash = :th
                          AND agent_previous_token_valid_until IS NOT NULL
                          AND agent_previous_token_valid_until > NOW()))"""


def resolve_edge_scanner(
    db: Session,
    token_hash: str,
    *,
    computer: str = "",
    instance: str = "",
    wanted_name: str = "",
) -> dict[str, Any] | None:
    """Scanner record of the laptop presenting ``token_hash`` (V1.10.0)."""
    rows = fetchall(
        db,
        f"""SELECT * FROM vuln_scanners
           WHERE {_TOKEN_MATCH_SQL}
             AND lower(coalesce(connection_mode, 'gmp')) = :mode
             AND lower(status) = 'active'""",
        {"th": token_hash, "mode": CONNECTION_MODE_EDGE},
    )
    if not rows:
        return None
    comp = normalize_computer_name(computer)
    inst = str(instance or "").strip()[:128]
    row, claim = pick_laptop_scanner(rows, computer=comp, instance=inst, wanted_name=wanted_name)
    if row is not None:
        if claim and comp:
            execute(
                db,
                """UPDATE vuln_scanners
                      SET agent_computer_name = :comp,
                          agent_instance_id = COALESCE(NULLIF(:inst, ''), agent_instance_id),
                          updated_at = NOW()
                    WHERE id = CAST(:id AS uuid)""",
                {"comp": comp, "inst": inst, "id": str(row["id"])},
            )
            db.commit()
            row = dict(row, agent_computer_name=comp, agent_instance_id=inst or row.get("agent_instance_id"))
            _log.info("Edge scanner %s (%s) linked to laptop %s", row.get("name"), row.get("id"), comp)
        return row

    # A laptop of this token's user that has no scanner record yet: register it
    # under its own name instead of borrowing another laptop's record. The token
    # was bound by a signed-in user (bind-client-token), so the laptop holding it
    # carries that user's authorization, as before.
    name = (str(wanted_name or "").strip() or f"Laptop-{comp}")[:120]
    template = rows[0]
    reuse = fetchone(
        db,
        """SELECT * FROM vuln_scanners
            WHERE lower(name) = lower(:name)
              AND lower(coalesce(connection_mode, 'gmp')) = :mode
              AND (coalesce(agent_computer_name, '') = '' OR lower(agent_computer_name) = lower(:comp))
            ORDER BY created_at
            LIMIT 1""",
        {"name": name, "mode": CONNECTION_MODE_EDGE, "comp": comp},
    )
    if reuse:
        execute(
            db,
            """UPDATE vuln_scanners
                  SET agent_token_hash = :th,
                      agent_token_hint = :hint,
                      agent_computer_name = :comp,
                      agent_instance_id = NULLIF(:inst, ''),
                      status = 'active',
                      updated_at = NOW()
                WHERE id = CAST(:id AS uuid)""",
            {"th": token_hash, "hint": template.get("agent_token_hint"), "comp": comp, "inst": inst,
             "id": str(reuse["id"])},
        )
        db.commit()
        _log.info("Edge scanner %s (%s) re-linked to laptop %s", reuse.get("name"), reuse.get("id"), comp)
        return fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": str(reuse["id"])})
    from app.services.scanner_credentials import ensure_scanner_role_column

    ensure_scanner_role_column(db)
    created = fetchone(
        db,
        """INSERT INTO vuln_scanners
             (name, url, edition, api_key_ref, connection_mode, scanner_role,
              agent_token_hash, agent_token_hint, agent_computer_name, agent_instance_id)
           VALUES (:name, :url, 'openvas', NULL, :mode, :role, :th, :hint, :comp, NULLIF(:inst, ''))
           RETURNING *""",
        {"name": name, "url": EDGE_AGENT_URL, "mode": CONNECTION_MODE_EDGE,
         "role": str(template.get("scanner_role") or "portable"), "th": token_hash,
         "hint": template.get("agent_token_hint"), "comp": comp, "inst": inst},
    )
    db.commit()
    _log.warning("Registered new laptop scanner %s for computer %s (same access token as %s)",
                 name, comp, template.get("name"))
    return created


@dataclass
class EdgeAgentContext:
    firm_slug: str
    schema_name: str
    scanner_id: str
    scanner_name: str
    scanner: dict[str, Any]


def resolve_firm_schema(db: Session, tenant_slug: str) -> tuple[str, str]:
    slug = (tenant_slug or "").strip().lower()
    if not slug:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "tenant_required", "message": "X-Tenant header is required"}},
        )
    firm = db.execute(select(Firm).where(Firm.slug == slug)).scalar_one_or_none()
    if not firm and slug in {"a", "aetheris"}:
        # Laptop kits often ship TENANT_SLUG=a or aetheris; map to the only active firm.
        firms = db.execute(select(Firm).where(Firm.status == "active")).scalars().all()
        if len(firms) == 1:
            firm = firms[0]
    if not firm:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "tenant_not_found", "message": "Organization not found"}},
        )
    if firm.status != "active":
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "tenant_suspended", "message": "Organization is suspended"}},
        )
    return firm.slug, firm.schema_name


def get_edge_agent(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    x_tenant: str | None = Header(default=None, alias="X-Tenant"),
    x_agent_instance: str | None = Header(default=None, alias="X-Aetheris-Agent-Instance"),
    x_agent_computer: str | None = Header(default=None, alias="X-Aetheris-Agent-Computer"),
    x_agent_name: str | None = Header(default=None, alias="X-Aetheris-Agent-Name"),
) -> EdgeAgentContext:
    if not creds or not creds.credentials:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "unauthorized", "message": "Agent bearer token required"}},
        )
    db = SessionLocal()
    try:
        db.execute(text("SET search_path TO public"))
        firm_slug, schema_name = resolve_firm_schema(db, x_tenant or "")
        bind_firm_schema(db, schema_name)
        apply_firm_search_path(db, schema_name)
        ensure_edge_agent_recovery_columns(db)
        apply_firm_search_path(db, schema_name)
        token_hash = hash_agent_token(creds.credentials)
        # V1.10.0: the same emailed token may be bound on several laptops of one
        # user; pick the calling laptop's own record (or register it).
        row = resolve_edge_scanner(
            db,
            token_hash,
            computer=x_agent_computer or "",
            instance=x_agent_instance or "",
            wanted_name=x_agent_name or "",
        )
        if not row:
            raise HTTPException(
                status_code=401,
                detail={"error": {"code": "unauthorized", "message": "Invalid agent token"}},
            )
        return EdgeAgentContext(
            firm_slug=firm_slug,
            schema_name=schema_name,
            scanner_id=str(row["id"]),
            scanner_name=str(row.get("name") or ""),
            scanner=dict(row),
        )
    finally:
        db.close()
