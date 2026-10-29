"""Attach / inspect / release client-workstation evidence for a job."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchone
from app.services.client_evidence import (
    ClientEvidenceError,
    is_client_evidence_path,
    is_valid_share_id,
    split_client_path,
    to_virtual_path,
    virtual_root,
)
from app.services.client_evidence import agent_client, mount, registry, relay

log = logging.getLogger(__name__)

# A running pipeline must never have its source swapped underneath it.
_ACTIVE_STATUSES = {
    "processing", "building_disk", "disk_ready", "extracting", "extracted",
    "artifacts_registered", "parsing", "parsed", "indexing", "ocr", "ocring",
}


def _load_ds(db: Session, job_id: str) -> tuple[dict[str, Any], str]:
    row = fetchone(db, "SELECT status, disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    raw = row.get("disk_source") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    return (dict(raw) if isinstance(raw, dict) else {}), str(row.get("status") or "")


def _save_ds(db: Session, job_id: str, ds: dict[str, Any]) -> None:
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:id",
        {"ds": json.dumps(ds), "id": job_id},
    )


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


def describe(record: registry.ShareRecord, rel: str = "") -> str:
    where = record.client_root.rstrip("\\/")
    if rel:
        where = f"{where}\\{rel.replace('/', chr(92))}"
    host = record.hostname or "client workstation"
    return f"{host}: {where}"


def attach_client_source(
    db: Session,
    job_id: str,
    *,
    share_id: str,
    token: str,
    port: int,
    addresses: list[str],
    hostname: str,
    client_root: str,
    file_count: int,
    total_bytes: int,
    manifest_sha256: str,
    source_type: str,
    agent_url: str | None,
    request_ip: str | None,
    user_email: str = "",
    replace_existing: bool = True,
    relay_supported: bool = False,
) -> dict[str, Any]:
    from app.services.disk_build_log import write_disk_log

    share_id = (share_id or "").strip().lower()
    if not is_valid_share_id(share_id):
        raise ClientEvidenceError("The agent returned an invalid share id")
    if len(token or "") < 24:
        raise ClientEvidenceError("The agent returned an invalid share token")

    ds, status = _load_ds(db, job_id)
    if status in _ACTIVE_STATUSES:
        raise ClientEvidenceError("Stop the running pipeline before changing this job's evidence source")
    if str(ds.get("intake") or "") == "browser_upload" and str(ds.get("upload_status") or "") in {"receiving", "verifying"}:
        raise ClientEvidenceError("A browser upload is still running for this job. Stop it first.")

    candidates, rejected = agent_client.build_candidates(
        port=port,
        explicit_url=agent_url,
        request_ip=request_ip,
        addresses=addresses,
        hostname=hostname,
    )
    use_relay = relay_supported and relay.enabled()
    if use_relay:
        # Fallback when the server cannot open a connection to the PC (home, other site, NAT).
        candidates.append(relay.RELAY_URL)
    if not candidates:
        raise ClientEvidenceError(
            "None of this computer's addresses is permitted for client evidence"
            + (f" ({'; '.join(rejected)})" if rejected else "")
            + ". Ask the administrator to add your network to CLIENT_EVIDENCE_ALLOWED_NETWORKS,"
            " or install the latest Client Evidence Agent, which connects out to the server."
        )
    provisional = False
    if use_relay and registry.load_share(share_id) is None:
        # The agent's relay polls are accepted only for shares this server knows,
        # so register the share before asking the agent for its manifest.
        registry.save_share(registry.ShareRecord(
            share_id=share_id, job_id=str(job_id), token=token, agent_url=relay.RELAY_URL,
            hostname=hostname, client_root=client_root, manifest_sha256=manifest_sha256,
        ))
        provisional = True
    try:
        url, manifest = agent_client.choose_reachable(
            candidates, share_id=share_id, token=token, expected_digest=manifest_sha256 or None
        )
    except ClientEvidenceError:
        if provisional:
            registry.delete_share(share_id, str(job_id))
        raise
    files = manifest["files"]
    if file_count and len(files) != int(file_count):
        raise ClientEvidenceError("The agent manifest does not match the selected folder (file count differs)")
    if not files:
        raise ClientEvidenceError("The selected folder on this computer contains no files")

    # A new selection replaces earlier client folders of this job; the 2nd..nth
    # directory of one multi-directory selection is added alongside instead.
    if replace_existing:
        stale = (set(registry.shares_for_job(job_id)) | set(_job_share_map(ds))) - {share_id}
        for old in stale:
            release_share(old, job_id=job_id, revoke=True)
        _forget_shares(ds, stale)

    record = registry.ShareRecord(
        share_id=share_id,
        job_id=str(job_id),
        token=token,
        agent_url=url,
        base_urls=[u for u in candidates if u != url],
        hostname=str(manifest.get("hostname") or hostname or "")[:120],
        client_root=str(manifest.get("root") or client_root or "")[:1024],
        file_count=len(files),
        total_bytes=sum(int(f["size"]) for f in files),
        manifest_sha256=str(manifest["manifest_sha256"]),
        truncated=bool(manifest.get("truncated")),
        source_type="mobile" if source_type == "mobile" else "disk",
        registered_at=time.time(),
        registered_by=user_email,
    )
    registry.save_share(record)

    entry = {
        **record.public_dict(),
        "token_sealed": registry.seal_token(token),
        "virtual_root": virtual_root(share_id),
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "agent_version": str(manifest.get("agent_version") or ""),
    }
    shares = _job_share_map(ds)
    shares[share_id] = entry
    ds["client_sources"] = shares
    ds["client_source"] = entry
    ds["evidence_location"] = "client"
    _save_ds(db, job_id, ds)
    transport = "relay" if relay.is_relay_url(url) else "direct"
    via = (
        "an outbound connection from that computer to this server"
        if transport == "relay"
        else url
    )
    write_disk_log(
        db,
        job_id,
        (
            f"Client workstation evidence connected — {describe(record)} "
            f"({record.file_count} file(s), {_human_bytes(record.total_bytes)}) via {via}. "
            "The image stays on the client computer; the forensic server reads it in place over the network."
        ),
        stage="evidence_register",
        metadata={
            "client_share_id": share_id,
            "client_host": record.hostname,
            "client_root": record.client_root,
            "agent_url": url,
            "transport": transport,
            "manifest_sha256": record.manifest_sha256,
            "file_count": record.file_count,
            "total_bytes": record.total_bytes,
            "truncated": record.truncated,
        },
    )
    db.commit()

    mp = mount.ensure_mounted(share_id)
    return {
        "ok": True,
        "share_id": share_id,
        "path": virtual_root(share_id),
        "display_path": describe(record),
        "hostname": record.hostname,
        "client_root": record.client_root,
        "agent_url": url,
        "transport": transport,
        "file_count": record.file_count,
        "total_bytes": record.total_bytes,
        "truncated": record.truncated,
        "manifest_sha256": record.manifest_sha256,
        "mounted": str(mp),
    }


def _job_share_map(ds: dict[str, Any]) -> dict[str, dict[str, Any]]:
    shares: dict[str, dict[str, Any]] = {}
    raw = ds.get("client_sources")
    if isinstance(raw, dict):
        for sid, entry in raw.items():
            if is_valid_share_id(str(sid)) and isinstance(entry, dict):
                shares[str(sid)] = entry
    latest = ds.get("client_source")
    if isinstance(latest, dict) and is_valid_share_id(str(latest.get("share_id") or "")):
        shares.setdefault(str(latest["share_id"]), latest)
    return shares


def _forget_shares(ds: dict[str, Any], share_ids: set[str]) -> None:
    """Drop released shares and their saved folders so Resume never re-registers them."""
    if not share_ids:
        return

    def stale(path: Any) -> bool:
        text = str(path or "")
        if not is_client_evidence_path(text):
            return False
        try:
            return split_client_path(text)[0] in share_ids
        except ClientEvidenceError:
            return True

    shares = {k: v for k, v in _job_share_map(ds).items() if k not in share_ids}
    ds["client_sources"] = shares
    latest = ds.get("client_source")
    if isinstance(latest, dict) and str(latest.get("share_id") or "") in share_ids:
        ds.pop("client_source", None)
    folders = [f for f in ds.get("evidence_folders") or [] if not stale(f)]
    ds["evidence_folders"] = folders
    for key in ("evidence_folder", "last_host_path"):
        if stale(ds.get(key)):
            ds.pop(key, None)
    if not ds.get("evidence_folder") and folders:
        ds["evidence_folder"] = folders[0]


def reseed_job_shares(db: Session, job_id: str) -> list[str]:
    """Re-create missing Redis records from the job (e.g. after a Redis flush)."""
    ds, _ = _load_ds(db, job_id)
    out: list[str] = []
    for share_id, entry in _job_share_map(ds).items():
        out.append(share_id)
        if registry.load_share(share_id) is not None:
            continue
        try:
            record = registry.record_from_job_source(job_id, entry)
        except ClientEvidenceError as exc:
            log.warning("cannot re-seed client share %s for job %s: %s", share_id, job_id, exc)
            continue
        if record is not None:
            registry.save_share(record)
            log.info("re-seeded client evidence share %s for job %s", share_id, job_id)
    return out


def reseed_for_path(db: Session, job_id: str | None, raw: str | None) -> None:
    if not job_id or not raw or not is_client_evidence_path(raw):
        return
    try:
        share_id, _ = split_client_path(raw)
    except ClientEvidenceError:
        return
    if registry.load_share(share_id) is None:
        reseed_job_shares(db, job_id)


def resolve_client_path(raw: str) -> Path:
    """Mount (if needed) and return the container path for a client evidence path."""
    share_id, rel = split_client_path(raw)
    mp = mount.ensure_mounted(share_id)
    target = mp / rel if rel else mp
    if not target.exists():
        raise ClientEvidenceError(f"Path not found on the client workstation share: {to_virtual_path(raw)}")
    return target


def release_share(share_id: str, *, job_id: str | None = None, revoke: bool = True) -> None:
    record = registry.load_share(share_id)
    if record and revoke:
        for url in record.candidates():
            if relay.is_relay_url(url):
                # Must happen before the record is deleted: the agent's poll needs it.
                if relay.agent_online(share_id) and relay.revoke(share_id):
                    break
            elif agent_client.revoke_share(url, share_id, record.token):
                break
    mount.unmount(share_id)
    try:
        registry.delete_share(share_id, job_id or (record.job_id if record else None))
    except Exception as exc:
        log.warning("could not delete client share record %s: %s", share_id, exc)


def release_job_client_sources(job_id: str, disk_source: dict[str, Any] | None = None, *, revoke: bool = True) -> int:
    ids = set(registry.shares_for_job(job_id))
    if isinstance(disk_source, dict):
        ids |= set(_job_share_map(disk_source))
        _forget_shares(disk_source, ids)
    for share_id in ids:
        try:
            release_share(share_id, job_id=job_id, revoke=revoke)
        except Exception as exc:
            log.warning("release of client share %s failed: %s", share_id, exc)
    return len(ids)


def client_source_status(db: Session, job_id: str, *, probe: bool = True) -> dict[str, Any]:
    ds, status = _load_ds(db, job_id)
    cs = ds.get("client_source") if isinstance(ds.get("client_source"), dict) else None
    if not cs:
        return {"configured": False}
    share_id = str(cs.get("share_id") or "")
    reseed_job_shares(db, job_id)
    record = registry.load_share(share_id)
    out: dict[str, Any] = {
        "configured": True,
        "share_id": share_id,
        "path": virtual_root(share_id),
        "hostname": cs.get("hostname"),
        "client_root": cs.get("client_root"),
        "display_path": describe(record) if record else f"{cs.get('hostname') or 'client'}: {cs.get('client_root') or ''}",
        "file_count": cs.get("file_count"),
        "total_bytes": cs.get("total_bytes"),
        "truncated": bool(cs.get("truncated")),
        "agent_url": record.agent_url if record else cs.get("agent_url"),
        "registered": record is not None,
        "mounted_here": mount.is_mounted(mount.mountpoint_for(share_id)) if is_valid_share_id(share_id) else False,
        "reader": registry.read_health(share_id) or {},
        # Bytes the server has read from the PC so far vs the selected evidence size.
        "transfer": registry.read_transfer_stats(share_id) if is_valid_share_id(share_id) else {},
        "job_status": status,
    }
    out["transport"] = "relay" if record and relay.is_relay_url(record.agent_url) else "direct"
    if probe and record:
        health = None
        if out["transport"] == "direct":
            for url in record.candidates():
                if relay.is_relay_url(url):
                    continue
                health = agent_client.probe_health(url, timeout=2.5)
                if health:
                    out["agent_url"] = url
                    break
        online = bool(health and health.get("ok"))
        if not online and any(relay.is_relay_url(u) for u in record.candidates()):
            online = relay.agent_online(share_id)
        out["agent_online"] = online
        out["agent_version"] = (health or {}).get("version")
    return out
