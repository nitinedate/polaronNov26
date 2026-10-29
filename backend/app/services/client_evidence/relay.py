"""Outbound ("relay") transport: the agent connects to the server, not the other way round.

Used when the forensic server cannot open a connection to the examiner's PC,
for example a PC at home or on another site behind a router. The agent keeps
a few HTTPS long-poll requests open to the Polaron console
(``POST /api/client-agent/relay/poll``). A reader that needs bytes queues a
request in Redis; a waiting poll hands it to the agent, which reads the bytes
locally and posts them back (``POST /api/client-agent/relay/respond/<id>``).

* No inbound port on the PC, works behind NAT and proxies, encrypted by the
  console's HTTPS certificate.
* Works across processes and containers: readers (any container) and the API
  process holding the poll meet only in Redis.
* The agent authenticates with the share's bearer token, so the relay serves
  exactly one share per credential.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Any

RELAY_URL = "relay:"
_P = "polaron:client-evidence:relay"
SEEN_TTL = 75            # seconds a poll keeps the agent marked online
MAX_POLL_WAIT = 25.0     # seconds a poll is held open (below proxy idle timeouts)
MAX_BODY = 64 * 1024 * 1024


class RelayError(OSError):
    """The agent could not be reached through the relay (transient)."""


@dataclass
class RelayReply:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def enabled() -> bool:
    return os.environ.get("CLIENT_EVIDENCE_RELAY_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def is_relay_url(url: str | None) -> bool:
    return bool(url) and str(url).startswith(RELAY_URL)


def _queue(share_id: str) -> str:
    return f"{_P}:q:{share_id}"


def _resp(req_id: str) -> str:
    return f"{_P}:resp:{req_id}"


def _owner(req_id: str) -> str:
    return f"{_P}:req:{req_id}"


def _seen(share_id: str) -> str:
    return f"{_P}:seen:{share_id}"


def _ack(req_id: str) -> str:
    return f"{_P}:ack:{req_id}"


def ack_wait() -> float:
    """Seconds a picked-up request may go unacknowledged before it counts as lost."""
    try:
        return max(2.0, float(os.environ.get("CLIENT_EVIDENCE_RELAY_ACK_SECONDS", "15")))
    except ValueError:
        return 15.0


def _redis_url() -> str:
    url = os.environ.get("REDIS_URL")
    if not url:
        from app.config import get_settings

        url = get_settings().redis_url
    return url


_sync_client = None


def _sync():
    """Binary-safe client; blocking pops need an unlimited socket timeout."""
    global _sync_client
    if _sync_client is None:
        import redis

        _sync_client = redis.Redis.from_url(_redis_url(), socket_connect_timeout=5, socket_timeout=None)
    return _sync_client


_async_clients: dict[int, Any] = {}


def _async():
    import redis.asyncio as aredis

    loop_id = id(asyncio.get_running_loop())
    client = _async_clients.get(loop_id)
    if client is None:
        client = aredis.Redis.from_url(_redis_url(), socket_connect_timeout=5, socket_timeout=None)
        _async_clients[loop_id] = client
    return client


def pack(header: dict[str, Any], body: bytes) -> bytes:
    head = json.dumps(header).encode()
    return struct.pack(">I", len(head)) + head + body


def unpack(blob: bytes) -> tuple[dict[str, Any], bytes]:
    (n,) = struct.unpack(">I", blob[:4])
    return json.loads(blob[4:4 + n]), blob[4 + n:]


# ---------------------------------------------------------------------------
# Reader side (sync; FUSE daemon, attach, status)
# ---------------------------------------------------------------------------

def agent_online(share_id: str) -> bool:
    try:
        return bool(_sync().exists(_seen(share_id)))
    except Exception:
        return False


def call(share_id: str, op: str, params: dict[str, Any] | None = None, *,
         timeout: float = 120.0, connect_wait: float = 0.0) -> RelayReply:
    """Send one request to the agent through the relay and wait for its reply."""
    client = _sync()
    deadline = time.time() + max(0.0, connect_wait)
    while not client.exists(_seen(share_id)):
        if time.time() >= deadline:
            raise RelayError(f"the agent for share {share_id} is not connected to this server")
        time.sleep(0.5)
    req_id = secrets.token_hex(12)
    expires = time.time() + timeout
    message = json.dumps({"req_id": req_id, "op": op, "expires_at": expires, **(params or {})})
    pipe = client.pipeline()
    pipe.set(_owner(req_id), share_id, ex=int(timeout) + 60)
    pipe.lpush(_queue(share_id), message)
    pipe.expire(_queue(share_id), 3600)
    pipe.execute()
    popped = None
    while popped is None:
        remaining = expires - time.time()
        if remaining <= 0:
            break
        acked = client.exists(_ack(req_id))
        # Until the agent acknowledges, wait in short slices so a request lost on a
        # dropped connection is noticed in seconds, not after the full timeout.
        slice_s = remaining if acked else min(remaining, ack_wait())
        popped = client.blpop([_resp(req_id)], timeout=max(1, math.ceil(slice_s)))
        if popped is not None or acked:
            continue
        if client.exists(_ack(req_id)):
            continue  # acknowledged meanwhile: a slow upload is under way
        if client.lrem(_queue(share_id), 1, message):
            client.rpush(_queue(share_id), message)  # still waiting its turn: keep its place at the front
            continue
        client.delete(_owner(req_id))
        raise RelayError("the request was lost on a dropped agent connection")
    client.delete(_ack(req_id))
    if popped is None:
        client.delete(_owner(req_id))
        raise RelayError(f"the agent did not answer within {int(timeout)} s")
    header, body = unpack(popped[1])
    headers = {str(k).lower(): str(v) for k, v in (header.get("headers") or {}).items()}
    return RelayReply(status=int(header.get("status") or 502), headers=headers, body=body)


def get_range(share_id: str, index: int, start: int, end: int, *, timeout: float = 120.0, accept: str = "") -> RelayReply:
    params: dict[str, Any] = {"index": int(index), "start": int(start), "end": int(end)}
    if accept:
        params["accept"] = accept  # e.g. "zero,deflate": the agent may skip empty blocks / compress
    return call(share_id, "range", params, timeout=timeout)


def get_manifest(share_id: str, *, connect_wait: float = 20.0, timeout: float = 20.0, attempts: int = 3) -> dict[str, Any]:
    """Fetch the frozen file list. Short attempts: a request lost on a dropped connection is retried."""
    last: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            reply = call(share_id, "manifest", timeout=timeout, connect_wait=connect_wait if attempt == 0 else 5.0)
        except RelayError as exc:
            last = exc
            continue
        if reply.status != 200:
            raise RelayError(f"the agent answered {reply.status} for the manifest")
        return json.loads(reply.body.decode("utf-8"))
    raise RelayError(str(last) if last else "no answer from the agent")


def revoke(share_id: str) -> bool:
    try:
        return call(share_id, "revoke", timeout=10.0).status in (200, 204, 404)
    except (RelayError, Exception):
        return False


# ---------------------------------------------------------------------------
# API side (async; called from the agent-facing endpoints)
# ---------------------------------------------------------------------------

async def poll(share_id: str, wait: float = MAX_POLL_WAIT, is_disconnected=None) -> dict[str, Any] | None:
    """Hand the next queued request to a waiting agent poll.

    Waits in 1-second slices and checks that the agent is still connected: a
    poll whose agent went away (restart, network drop) must not take a request
    it can no longer deliver. A request taken by such a poll is put back at the
    front of the queue for the next live poll.
    """
    client = _async()
    await client.set(_seen(share_id), str(time.time()), ex=SEEN_TTL)
    deadline = time.monotonic() + max(1.0, min(wait, MAX_POLL_WAIT))
    while time.monotonic() < deadline:
        if is_disconnected is not None and await is_disconnected():
            return None
        popped = await client.brpop([_queue(share_id)], timeout=1)
        if popped is None:
            continue
        message = json.loads(popped[1])
        if float(message.get("expires_at") or 0) < time.time():
            continue  # the reader already gave up on this one
        if is_disconnected is not None and await is_disconnected():
            await client.rpush(_queue(share_id), popped[1])
            return None
        return message
    return None


async def acknowledge(share_id: str, req_id: str) -> bool:
    """The agent received the request and is working on it."""
    client = _async()
    owner = await client.get(_owner(req_id))
    if owner is None or owner.decode() != share_id:
        return False
    await client.set(_ack(req_id), b"1", ex=3600)
    return True


async def respond(share_id: str, req_id: str, header: dict[str, Any], body: bytes) -> bool:
    client = _async()
    owner = await client.get(_owner(req_id))
    if owner is None or owner.decode() != share_id:
        return False
    pipe = client.pipeline()
    pipe.rpush(_resp(req_id), pack(header, body))
    pipe.expire(_resp(req_id), 120)
    pipe.delete(_owner(req_id))
    await pipe.execute()
    return True


async def forget(share_id: str) -> None:
    client = _async()
    await client.delete(_seen(share_id), _queue(share_id))
