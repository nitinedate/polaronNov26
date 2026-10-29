"""Shared FastAPI factory for isolated Disk, Android, iOS and vulnerability products."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.access_log import install_access_log_filter
from app.deps import tenant_middleware
from app.service_identity import (
    FORENSIC,
    MOBILE_ANDROID,
    MOBILE_EXTRACT,
    MOBILE_IOS,
    MOBILE_MALWARE,
    MOBILE_SERVICES,
    VULN,
    current_service,
    health_payload,
)

log = logging.getLogger("app.startup")
install_access_log_filter()


def _startup_perf() -> None:
    from app.services.host_capacity import apply_dynamic_performance
    from app.services.perf_broadcast import publish_live_plan
    from app.services.perf_policy import build_live_plan

    plan = apply_dynamic_performance()
    live = build_live_plan()
    publish_live_plan(live)
    log.info(
        "Dynamic performance: profile=%s pace=%s rag_batch=%s notes=%s",
        plan.profile,
        live.get("pace"),
        live.get("rag_batch_size"),
        "; ".join(plan.notes),
    )


def _startup_catalog(*, load_forensic_catalogs: bool) -> None:
    from app.db.session import SessionLocal
    from app.services.firm_migrations import apply_all_firm_migrations

    db = SessionLocal()
    try:
        if load_forensic_catalogs:
            from app.services.axiom_catalog_ingest import load_axiom_catalog_from_files
            from app.services.encyclopedia_ingest import load_encyclopedia_from_jsonl

            enc = load_encyclopedia_from_jsonl(db, force=False)
            log.info("Encyclopedia catalog: %s", enc)
            axiom = load_axiom_catalog_from_files(db, force=False)
            log.info("AXIOM catalog: %s", axiom)
        apply_all_firm_migrations(db)
    finally:
        db.close()


def _make_lifespan(*, load_forensic_catalogs: bool, probe_perf: bool, recover_pipelines: bool = True):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        import asyncio

        if probe_perf:
            try:
                await asyncio.wait_for(asyncio.to_thread(_startup_perf), timeout=8)
            except TimeoutError:
                log.warning("Dynamic performance probe timed out — starting API without a live GPU plan")
            except Exception:
                log.exception("Dynamic performance probe failed")
        try:
            await asyncio.wait_for(
                asyncio.to_thread(_startup_catalog, load_forensic_catalogs=load_forensic_catalogs),
                timeout=45,
            )
        except TimeoutError:
            log.warning("Startup catalog bootstrap timed out — API will serve without it")
        except Exception:
            log.exception("Startup catalog bootstrap failed")
        # Power-loss / laptop-shutdown recovery: stale stage claims are superseded
        # from PostgreSQL checkpoints after the API is back.  This is deliberately
        # best-effort; if Celery is not ready yet, progressAgent retries the same
        # persisted stage without redoing completed evidence.
        try:
            from app.services.restart_resume import recover_all_firms_for_current_service
            # Malware Detection owns no extraction pipeline; its own watchdog resumes scans.
            recovery = (
                await asyncio.wait_for(asyncio.to_thread(recover_all_firms_for_current_service), timeout=20)
                if recover_pipelines
                else "skipped (service owns no forensic pipelines)"
            )
            log.info("Startup pipeline recovery: %s", recovery)
        except TimeoutError:
            log.warning("Startup pipeline recovery timed out — progressAgent will continue recovery")
        except Exception:
            log.exception("Startup pipeline recovery failed; progressAgent will retry")
        yield

    return lifespan


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": "http_error", "message": str(exc.detail)}},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation", "message": "Invalid request payload"}},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": str(exc)}},
        )


def _install_iam_routers(app: FastAPI) -> None:
    from app.routers import auth, authz, logs, permissions, roles, tenants, users

    app.include_router(auth.router)
    app.include_router(tenants.router)
    app.include_router(users.router)
    app.include_router(roles.router)
    app.include_router(permissions.router)
    app.include_router(authz.router)
    app.include_router(logs.router)


def create_app(service: str | None = None) -> FastAPI:
    svc = service or current_service()
    titles = {
        FORENSIC: "Aetheris Disk Forensics",
        MOBILE_ANDROID: "Aetheris Android Forensics",
        MOBILE_IOS: "Aetheris iOS Forensics",
        MOBILE_EXTRACT: "Aetheris Mobile Extraction (Legacy)",
        VULN: "Aetheris Vulnerabilities",
        MOBILE_MALWARE: "Aetheris Mobile Malware Detection",
    }
    probe_perf = svc != MOBILE_MALWARE
    load_catalogs = svc == FORENSIC or svc in MOBILE_SERVICES

    app = FastAPI(
        title=titles.get(svc, "Aetheris"),
        version="0.4.0",
        lifespan=_make_lifespan(
            load_forensic_catalogs=load_catalogs,
            probe_perf=probe_perf,
            recover_pipelines=svc != MOBILE_MALWARE,
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def tenant_context_middleware(request: Request, call_next):
        return await tenant_middleware(request, call_next)

    _install_error_handlers(app)

    @app.get("/health")
    def health_root():
        return health_payload(svc)

    @app.get("/internal/host-mounts")
    def host_mounts_internal():
        """Peer workers ask the API which /host/<letter> binds are actually readable."""
        from app.services.drive_mount_agent import inspect_local_host_letters, mounted_letters

        rows = inspect_local_host_letters()
        return {"ok": True, "mounted": mounted_letters(rows), "inspect": rows}

    _install_iam_routers(app)

    from app.routers import health as health_router

    app.include_router(health_router.router)

    if svc == FORENSIC:
        _mount_forensic(app)
    elif svc in {MOBILE_ANDROID, MOBILE_IOS, MOBILE_EXTRACT}:
        _mount_mobile_extract(app)
    elif svc == VULN:
        _mount_vuln(app)
    elif svc == MOBILE_MALWARE:
        _mount_malware(app)

    return app


def _mount_forensic(app: FastAPI) -> None:
    from app.routers import (
        agents,
        artifacts,
        catalog_reconciliation,
        cases,
        client_evidence,
        encyclopedia,
        extract_review,
        hostdrive,
        jobs,
        rag_image_evidence,
        report,
        retrieval,
    )

    app.include_router(jobs.router)
    app.include_router(client_evidence.router)
    app.include_router(client_evidence.agent_router)
    app.include_router(extract_review.router)
    app.include_router(catalog_reconciliation.router)
    app.include_router(agents.router)
    app.include_router(hostdrive.router)
    app.include_router(encyclopedia.router)
    app.include_router(report.router)
    app.include_router(retrieval.router)
    app.include_router(artifacts.router)
    app.include_router(cases.router)
    app.include_router(rag_image_evidence.router)


def _mount_mobile_extract(app: FastAPI) -> None:
    # Mobile has its own runtime DB/Redis/MinIO and never mounts Disk-only
    # image-evidence/catalog/agent routers. Shared report/retrieval modules are
    # stateless libraries behind the platform service boundary; service guards
    # and physically separate stores prevent cross-platform job access.
    from app.routers import acquisition, artifacts, cases, client_evidence, extract_review, hostdrive, jobs, report, retrieval

    app.include_router(jobs.router)
    app.include_router(client_evidence.router)
    app.include_router(client_evidence.agent_router)
    app.include_router(extract_review.router)
    app.include_router(hostdrive.router)
    app.include_router(acquisition.router)
    app.include_router(artifacts.router)
    app.include_router(cases.router)
    app.include_router(report.router)
    app.include_router(retrieval.router)


def _mount_vuln(app: FastAPI) -> None:
    from app.routers import cases, scanner_agent, vuln, vuln_brd, vuln_extended, vuln_orchestrator

    # Scan jobs live on this service's DB — case list/create/delete must too.
    app.include_router(cases.router)
    app.include_router(vuln.router)
    app.include_router(vuln_brd.router)
    app.include_router(vuln_extended.router)
    app.include_router(vuln_orchestrator.router)
    app.include_router(scanner_agent.router)


def _mount_malware(app: FastAPI) -> None:
    """Malware Detection mounts only its own router; never jobs/acquisition/artifacts."""
    from app.malware.router import router as malware_router

    app.include_router(malware_router)
