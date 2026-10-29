"""Registry of client-workstation shares, visible to every container through Redis.

The API writes a record when the examiner connects a client folder.  Workers
and the FUSE daemons read it to find the agent address and bearer token.  The
job's ``disk_source.client_source`` keeps a durable copy (token sealed with the
server secret) so the record can be re-seeded if Redis is ever flushed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from app.services.client_evidence import ClientEvidenceError, is_valid_share_id

log = logging.getLogger(__name__)

_PREFIX = "polaron:client-evidence"
SHARES_SET = f"{_PREFIX}:shares"


def _share_key(share_id: str) -> str:
    return f"{_PREFIX}:share:{share_id}"


def _job_key(job_id: str) -> str:
    return f"{_PREFIX}:job:{job_id}"


def health_key(share_id: str) -> str:
    return f"{_PREFIX}:health:{share_id}"


def stats_key(share_id: str) -> str:
    return f"{_PREFIX}:stats:{share_id}"


@dataclass
class ShareRecord:
    share_id: str
    job_id: str
    token: str
    agent_url: str
    base_urls: list[str] = field(default_factory=list)
    hostname: str = ""
    client_root: str = ""
    file_count: int = 0
    total_bytes: int = 0
    manifest_sha256: str = ""
    truncated: bool = False
    source_type: str = "disk"
    registered_at: float = field(default_factory=time.time)
    registered_by: str = ""

    def candidates(self) -> list[str]:
        out: list[str] = []
        for url in [self.agent_url, *self.base_urls]:
            url = (url or "").rstrip("/")
            if url and url not in out:
                out.append(url)
        return out

    def public_dict(self) -> dict[str, Any]:
        """Job-facing metadata. Never contains the bearer token."""
        data = asdict(self)
        data.pop("token", None)
        return data


def _redis():
    import redis

    url = os.environ.get("REDIS_URL")
    if not url:
        from app.config import get_settings

        url = get_settings().redis_url
    return redis.Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5, decode_responses=True)


def save_share(record: ShareRecord) -> None:
    if not is_valid_share_id(record.share_id):
        raise ClientEvidenceError("Invalid share id")
    client = _redis()
    pipe = client.pipeline()
    pipe.set(_share_key(record.share_id), json.dumps(asdict(record)))
    pipe.sadd(SHARES_SET, record.share_id)
    pipe.sadd(_job_key(record.job_id), record.share_id)
    pipe.execute()


def load_share(share_id: str) -> ShareRecord | None:
    if not is_valid_share_id(share_id):
        return None
    try:
        raw = _redis().get(_share_key(share_id))
    except Exception as exc:  # Redis unavailable: callers decide how to fail
        log.warning("client evidence registry unavailable: %s", exc)
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
        known = {f for f in ShareRecord.__dataclass_fields__}
        return ShareRecord(**{k: v for k, v in data.items() if k in known})
    except Exception as exc:
        log.warning("corrupt client evidence record %s: %s", share_id, exc)
        return None


def delete_share(share_id: str, job_id: str | None = None) -> None:
    client = _redis()
    if job_id is None:
        rec = load_share(share_id)
        job_id = rec.job_id if rec else None
    pipe = client.pipeline()
    pipe.delete(_share_key(share_id))
    pipe.delete(health_key(share_id))
    pipe.delete(stats_key(share_id))
    pipe.srem(SHARES_SET, share_id)
    if job_id:
        pipe.srem(_job_key(job_id), share_id)
    pipe.execute()


def shares_for_job(job_id: str) -> list[str]:
    if not job_id:
        return []
    try:
        return sorted(_redis().smembers(_job_key(str(job_id))) or [])
    except Exception as exc:
        log.debug("client evidence job lookup failed: %s", exc)
        return []


def all_share_ids() -> list[str]:
    try:
        return sorted(_redis().smembers(SHARES_SET) or [])
    except Exception:
        return []


def write_health(share_id: str, payload: dict[str, Any]) -> None:
    try:
        _redis().set(health_key(share_id), json.dumps({**payload, "updated_at": time.time()}), ex=3600)
    except Exception:
        pass


TRANSFER_FIELDS = ("logical_bytes", "wire_bytes", "zero_bytes", "requests")


def add_transfer_stats(share_id: str, deltas: dict[str, int]) -> None:
    """Cumulative bytes read from the PC for this share, summed over every container."""
    try:
        pipe = _redis().pipeline()
        for name in TRANSFER_FIELDS:
            value = int(deltas.get(name) or 0)
            if value:
                pipe.hincrby(stats_key(share_id), name, value)
        pipe.execute()
    except Exception:
        pass


def read_transfer_stats(share_id: str) -> dict[str, int]:
    try:
        raw = _redis().hgetall(stats_key(share_id)) or {}
    except Exception:
        raw = {}
    return {name: int(raw.get(name) or 0) for name in TRANSFER_FIELDS}


def read_health(share_id: str) -> dict[str, Any] | None:
    try:
        raw = _redis().get(health_key(share_id))
        return json.loads(raw) if raw else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Token sealing for the durable copy in jobs.disk_source
# ---------------------------------------------------------------------------

def _fernet():
    from cryptography.fernet import Fernet

    secret = os.environ.get("CLIENT_EVIDENCE_SECRET", "")
    if not secret:
        try:
            from app.config import get_settings

            secret = get_settings().jwt_secret
        except Exception:
            secret = ""
    if not secret:
        raise ClientEvidenceError("No server secret is configured to protect client evidence tokens")
    key = base64.urlsafe_b64encode(hashlib.sha256(f"polaron-client-evidence|{secret}".encode()).digest())
    return Fernet(key)


def seal_token(token: str) -> str:
    return _fernet().encrypt(token.encode()).decode()


def open_token(sealed: str) -> str:
    try:
        return _fernet().decrypt(sealed.encode()).decode()
    except Exception as exc:
        raise ClientEvidenceError("The stored client evidence token cannot be decrypted") from exc


def record_from_job_source(job_id: str, client_source: dict[str, Any]) -> ShareRecord | None:
    """Rebuild a registry record from ``disk_source.client_source`` (Redis re-seed)."""
    if not isinstance(client_source, dict):
        return None
    share_id = str(client_source.get("share_id") or "")
    sealed = str(client_source.get("token_sealed") or "")
    if not is_valid_share_id(share_id) or not sealed:
        return None
    return ShareRecord(
        share_id=share_id,
        job_id=str(job_id),
        token=open_token(sealed),
        agent_url=str(client_source.get("agent_url") or ""),
        base_urls=[str(u) for u in client_source.get("base_urls") or []],
        hostname=str(client_source.get("hostname") or ""),
        client_root=str(client_source.get("client_root") or ""),
        file_count=int(client_source.get("file_count") or 0),
        total_bytes=int(client_source.get("total_bytes") or 0),
        manifest_sha256=str(client_source.get("manifest_sha256") or ""),
        truncated=bool(client_source.get("truncated")),
        source_type=str(client_source.get("source_type") or "disk"),
        registered_at=float(client_source.get("registered_at") or time.time()),
        registered_by=str(client_source.get("registered_by") or ""),
    )
