"""Client-workstation evidence endpoints (image stays on the examiner PC).

Flow used by the UI:
1. Browser asks the local Client Evidence Agent (http://127.0.0.1:9877) to
   publish the selected folder → share id + token.
2. ``POST /api/jobs/{id}/evidence/client-source`` — the server reaches the agent
   over the LAN, verifies the manifest and mounts it read-only.  Returns the
   virtual path ``client-evidence://<share>``.
3. The usual ``list-folder`` and ``ingest-path`` calls run with that path,
   exactly as for a server drive path.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission
from app.schemas.forensic import ClientSourceBody
from app.services.client_evidence import ClientEvidenceError

router = APIRouter(prefix="/api", tags=["client-evidence"])


def _request_ip(request: Request) -> str | None:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    real = (request.headers.get("x-real-ip") or "").strip()
    if real:
        return real
    return request.client.host if request.client else None


def _error(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})


@router.post("/jobs/{job_id}/evidence/client-source")
def register_client_source(
    job_id: str,
    body: ClientSourceBody,
    request: Request,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.routers.jobs import _ensure_job, _job_source_type
    from app.services.client_evidence.job_source import attach_client_source

    _ensure_job(db, job_id)
    source_type = body.source_type
    if _job_source_type(db, job_id) == "mobile":
        source_type = "mobile"
    try:
        return attach_client_source(
            db,
            job_id,
            share_id=body.share_id,
            token=body.token,
            port=body.port,
            addresses=body.addresses,
            hostname=body.hostname,
            client_root=body.client_root,
            file_count=body.file_count,
            total_bytes=body.total_bytes,
            manifest_sha256=body.manifest_sha256,
            source_type=source_type,
            agent_url=body.agent_url,
            request_ip=_request_ip(request),
            user_email=getattr(current, "email", "") or "",
            replace_existing=body.replace_existing,
            relay_supported=body.relay,
        )
    except ClientEvidenceError as exc:
        db.rollback()
        message = str(exc)
        if "Stop the running pipeline" in message or "still running" in message:
            raise _error(409, "client_source_busy", message)
        if "could not reach" in message or "Timed out" in message:
            raise _error(502, "client_agent_unreachable", message)
        if "/dev/fuse" in message or "libfuse" in message or "disabled" in message:
            raise _error(503, "client_mount_unavailable", message)
        raise _error(400, "client_source_failed", message)


@router.get("/jobs/{job_id}/evidence/client-source")
def get_client_source(
    job_id: str,
    probe: bool = True,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.routers.jobs import _ensure_job
    from app.services.client_evidence.job_source import client_source_status

    _ensure_job(db, job_id)
    return client_source_status(db, job_id, probe=probe)


@router.delete("/jobs/{job_id}/evidence/client-source")
def release_client_source(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.routers.jobs import _ensure_job
    from app.services.client_evidence.job_source import (
        _ACTIVE_STATUSES,
        _load_ds,
        _save_ds,
        release_job_client_sources,
    )

    _ensure_job(db, job_id)
    ds, status = _load_ds(db, job_id)
    if status in _ACTIVE_STATUSES:
        raise _error(409, "client_source_busy", "Stop the running pipeline before disconnecting its evidence source")
    released = release_job_client_sources(job_id, ds, revoke=True)
    ds.pop("client_source", None)
    if ds.get("evidence_location") == "client":
        ds.pop("evidence_location", None)
    _save_ds(db, job_id, ds)
    db.commit()
    return {"ok": True, "released": released}


# ---------------------------------------------------------------------------
# Agent-facing relay endpoints (outbound connection from the examiner's PC)
# ---------------------------------------------------------------------------
# The agent has no user session: it authenticates with the share's bearer
# token, which only it and this server know. Both endpoints touch Redis only.

import hmac

from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

agent_router = APIRouter(prefix="/api/client-agent", tags=["client-evidence-agent"])


async def _authorize_agent(request: Request) -> str:
    from app.services.client_evidence import is_valid_share_id, registry

    share_id = (request.headers.get("x-polaron-share") or "").strip().lower()
    auth = request.headers.get("authorization") or ""
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not is_valid_share_id(share_id) or not token:
        raise _error(401, "agent_unauthorized", "Missing share credentials")
    record = await run_in_threadpool(registry.load_share, share_id)
    if record is None:
        # Unknown here (not attached yet, released, or Redis re-seed pending): the agent retries later.
        raise _error(404, "share_unknown", "This server does not know the share")
    if not hmac.compare_digest(record.token.encode(), token.encode()):
        raise _error(401, "agent_unauthorized", "Invalid share token")
    return share_id


@agent_router.post("/relay/poll")
async def relay_poll(request: Request):
    from app.services.client_evidence import relay

    if not relay.enabled():
        raise _error(503, "relay_disabled", "The outbound agent connection is disabled on this server")
    share_id = await _authorize_agent(request)
    try:
        wait = float(request.headers.get("x-polaron-wait") or relay.MAX_POLL_WAIT)
    except ValueError:
        wait = relay.MAX_POLL_WAIT
    await request.body()  # consume the small hello so disconnects are visible
    message = await relay.poll(share_id, wait, is_disconnected=request.is_disconnected)
    if message is None:
        return Response(status_code=204)
    return JSONResponse(message)


@agent_router.post("/relay/ack/{req_id}")
async def relay_ack(req_id: str, request: Request):
    from app.services.client_evidence import relay

    share_id = await _authorize_agent(request)
    if not req_id.isalnum() or len(req_id) > 64:
        raise _error(400, "bad_request", "Invalid request id")
    if not await relay.acknowledge(share_id, req_id):
        raise _error(404, "request_unknown", "The server is no longer waiting for this request")
    return {"ok": True}


@agent_router.post("/relay/respond/{req_id}")
async def relay_respond(req_id: str, request: Request):
    from app.services.client_evidence import relay

    share_id = await _authorize_agent(request)
    if not req_id.isalnum() or len(req_id) > 64:
        raise _error(400, "bad_request", "Invalid request id")
    declared = int(request.headers.get("content-length") or 0)
    if declared > relay.MAX_BODY:
        raise _error(413, "too_large", "Relay response too large")
    body = await request.body()
    if len(body) > relay.MAX_BODY:
        raise _error(413, "too_large", "Relay response too large")
    try:
        status = int(request.headers.get("x-relay-status") or 502)
    except ValueError:
        status = 502
    headers = {}
    for name in ("etag", "content-range", "error", "encoding", "raw-length"):
        value = request.headers.get(f"x-relay-{name}")
        if value:
            headers[name] = value[:512]
    if not await relay.respond(share_id, req_id, {"status": status, "headers": headers}, body):
        raise _error(404, "request_unknown", "The server is no longer waiting for this response")
    return {"ok": True}
