"""The single Disk/Mobile progress coordinator; no voting or competing repairs."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("forensic.progress")

CHECK_AFTER_SECONDS = 60
# A process that never leaves its startup declaration is not examining evidence.
STARTUP_STALL_SECONDS = 180
# A live heartbeat with no new committed item is a halt, whatever the deadline says.
ITEM_STALL_SECONDS = 90
# After a declared operation's deadline, one short grace, then restart the owner.
LIVELOCK_AFTER_DEADLINE_SECONDS = 90
MAX_RECOVERY_ATTEMPTS = 3
# A bounded inventory prewarm is not a per-item catalog counter.
# Longer than the generic 90-second progress threshold, but never unlimited.
INVENTORY_PREWARM_GRACE_SECONDS = max(600, min(3600, int(os.getenv("FORENSIC_INVENTORY_PREWARM_GRACE_SECONDS", "1800"))))
_SCHEMA_READY = set()
_QUEUE_STATE = (0, None)
PROGRESS_AGENT = {
    "id": "progressAgent", "name": "progressAgent", "role": "control",
    "lane": "control", "stage": "orchestration",
    "action": "Verify committed counts and producers, expose writing in, and recover bounded stalls",
    "description": "One coordinator; respects pauses, bounded operations, dependencies and product ownership.",
    "consults": [], "task": "app.tasks.progress_agent_task",
}


def progress_queue(service=None):
    from app.service_identity import current_service
    return {"forensic": "disk-progress", "mobile-android": "android-progress",
            "mobile-ios": "ios-progress", "mobile-extract": "mobile-progress"}.get(service or current_service(), "disk-progress")


def report_queue():
    from app.service_identity import current_service
    return {'mobile-android':'android-report','mobile-ios':'ios-report','mobile-extract':'mobile-build'}.get(current_service(),'report-gen')


def _catalog_names(db, kind: str) -> set[str]:
    """Names in the current schema. Does not lock the examined tables."""
    rows = fetchall(
        db,
        """SELECT c.relname FROM pg_class c
           JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname=current_schema() AND c.relkind=:kind""",
        {"kind": kind},
    )
    return {str(row["relname"]) for row in rows}


def _column_names(db, table: str) -> set[str]:
    rows = fetchall(
        db,
        """SELECT column_name FROM information_schema.columns
           WHERE table_schema=current_schema() AND table_name=:table""",
        {"table": table},
    )
    return {str(row["column_name"]) for row in rows}


def ensure_progress_schema(db):
    from app.services.forensic_serial_pipeline import ensure_serial_schema
    schema=fetchone(db,"SELECT current_schema() AS name")['name']
    key=(str(getattr(db,'bind','')),schema)
    if key in _SCHEMA_READY:
        return
    ensure_serial_schema(db)
    tables = _catalog_names(db, "r")
    indexes = _catalog_names(db, "i")
    if "pipeline_progress_events" not in tables:
        execute(db, """CREATE TABLE IF NOT EXISTS pipeline_progress_events (
            id bigserial PRIMARY KEY,job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            stage text,decision text NOT NULL,reason text NOT NULL,details jsonb NOT NULL DEFAULT '{}',
            created_at timestamptz NOT NULL DEFAULT NOW())""")
    if "progress_events_job" not in indexes:
        execute(db, "CREATE INDEX IF NOT EXISTS progress_events_job ON pipeline_progress_events(job_id,created_at DESC)")
    if "ix_jobs_progress_watch" not in indexes:
        execute(db, "CREATE INDEX IF NOT EXISTS ix_jobs_progress_watch ON jobs(status,updated_at,id) WHERE stop_requested=FALSE")
    if "pipeline_progress_checks" not in tables:
        execute(db, """CREATE TABLE IF NOT EXISTS pipeline_progress_checks (
            job_id uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
            fingerprint text NOT NULL,last_change_at timestamptz NOT NULL DEFAULT NOW(),
            checked_at timestamptz NOT NULL DEFAULT NOW(),decision text,reason text,
            acquisition_recoveries integer NOT NULL DEFAULT 0,
            acquisition_last_dispatch_at timestamptz)""")
    checks = _column_names(db, "pipeline_progress_checks")
    if "acquisition_recoveries" not in checks:
        execute(db, "ALTER TABLE pipeline_progress_checks ADD COLUMN IF NOT EXISTS acquisition_recoveries integer NOT NULL DEFAULT 0")
    if "acquisition_last_dispatch_at" not in checks:
        execute(db, "ALTER TABLE pipeline_progress_checks ADD COLUMN IF NOT EXISTS acquisition_last_dispatch_at timestamptz")
    if "recovery_dispatches" not in _column_names(db, "pipeline_stage_runs"):
        execute(db, "ALTER TABLE pipeline_stage_runs ADD COLUMN IF NOT EXISTS recovery_dispatches integer NOT NULL DEFAULT 0")
    from app.services.suspicious_activity import ensure_suspicious_schema
    ensure_suspicious_schema(db)
    if "report_runs" in tables or "report_runs" in _catalog_names(db, "r"):
        present = _column_names(db, "report_runs")
        for column in ('owner_task_id text','heartbeat_at timestamptz','progress_at timestamptz','operation_deadline timestamptz','cancel_requested_at timestamptz','recovery_dispatches integer NOT NULL DEFAULT 0'):
            if column.split()[0] not in present:
                execute(db, f"ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS {column}")
        if "progress_report_active_job" not in indexes:
            execute(db, "CREATE INDEX IF NOT EXISTS progress_report_active_job ON report_runs(job_id,created_at DESC) WHERE status IN ('running','queued','waiting')")
    db.commit()
    _SCHEMA_READY.add(key)


def _age(value, now):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not value:
        return float("inf")
    return max(0, (now - value.replace(tzinfo=timezone.utc) if value.tzinfo is None else now - value).total_seconds())


def _obj(value):
    return json.loads(value) if isinstance(value, str) else value or {}


def _is_auto_resumable_pause(row):
    if not row or str(row.get("status") or "") != "paused" or row.get("stop_requested"):
        return False
    err=str(row.get("error") or "").lower()
    return any(k in err for k in ("thermal","capacity","restart","worker unavailable","dependency"))


def classify_stage(job, stage, *, now=None):
    """A heartbeat proves liveness, never that useful work advanced."""
    now = now or datetime.now(timezone.utc)
    if job.get("stop_requested") or job.get("status") == "paused":
        return "valid_wait", "Paused by the user or thermal protection"
    state = stage.get("status")
    if state in {"done", "skipped"}:
        return "complete", "Stage finished"
    progress_age = _age(stage.get("progress_at") or stage.get("started_at") or stage.get("updated_at"), now)
    if state == "failed":
        error = str(stage.get("error") or "").lower()
        retryable = any(token in error for token in ("deadlock", "connection reset", "server closed", "process exited", "timed out", "stage process", "progressagent", "current transaction is aborted", "infailedsqltransaction", "lock timeout", "database lock"))
        return ("recover", "Transient stage failure") if retryable and int(stage.get("attempt") or 0) <= MAX_RECOVERY_ATTEMPTS else ("blocked", "Failed stage needs a source/dependency correction")
    if state == "running" and progress_age < CHECK_AFTER_SECONDS:
        return "progressing", "Useful work advanced within the last minute"
    if state == "running":
        total_items = int(stage.get("total_items") or 0)
        accounted = sum(int(stage.get(key) or 0) for key in ("completed_items", "failed_items", "skipped_items"))
        operation = str(stage.get("operation") or "")
        startup = (not operation) or operation.endswith((": bounded evidence operation", ": starting"))
        # Heartbeats continue while a child is blocked in a catalog lock or a
        # native call. That is a livelock: the process is alive and no evidence
        # item has been committed. Cancel only that child so the stage retries.
        if progress_age >= STARTUP_STALL_SECONDS and total_items <= 0 and accounted <= 0 and startup:
            if _age(stage.get("heartbeat_at"), now) >= CHECK_AFTER_SECONDS:
                return "recover", "Stage never started evidence work and its heartbeat is stale"
            return "valid_wait", "Stage owner is alive; waiting for initial evidence work"
        if total_items > 0 and accounted >= total_items:
            return "valid_wait", f"Bounded operation in progress: {stage.get('operation') or stage['stage']}"
        # The operation deadline used to hide this. A child blocked on a file
        # mount keeps its heartbeat and its deadline while the item count is frozen.
        # Inventory counts a few dozen catalog rows. A live path index or
        # catalog count can sit on one row for longer than a minute while the
        # heartbeat stays fresh. Restarting that child throws away the index.
        if (
            str(stage.get("stage") or "") == "inventory"
            and total_items > 0
            and not startup
            and _age(stage.get("heartbeat_at"), now) < CHECK_AFTER_SECONDS
            and progress_age < 600
        ):
            return "valid_wait", f"Inventory is writing: {operation or stage['stage']}"
        # Prewarm consists of path indexing, unallocated signature carving and
        # optional URL cache construction. It may not commit a *catalog item*
        # until the entire operation returns. Restarting it after 90 seconds
        # repeatedly throws away minutes of verified work (observed in logs).
        # An existing live heartbeat justifies bounded grace, never success.
        if (
            str(stage.get("stage") or "") == "inventory"
            and not startup
            and any(token in operation.lower() for token in (
                "carv", "prewarm", "path index", "counting catalog",
                "url inventory", "encryption warm", "census",
            ))
            and progress_age < INVENTORY_PREWARM_GRACE_SECONDS
            and _age(stage.get("heartbeat_at"), now) < CHECK_AFTER_SECONDS
        ):
            return "valid_wait", f"Active bounded inventory operation: {operation}"
        if progress_age >= ITEM_STALL_SECONDS:
            if _age(stage.get("heartbeat_at"), now) >= CHECK_AFTER_SECONDS:
                return "recover", "No evidence item committed and the stage heartbeat is stale"
            return "valid_wait", "Stage owner is alive; waiting for a committed batch"
        deadline = stage.get("operation_deadline")
        if deadline and _age(deadline, now) == 0:
            return "valid_wait", f"Bounded operation in progress: {stage.get('operation') or stage['stage']}"
        if _age(stage.get('heartbeat_at'),now)>=CHECK_AFTER_SECONDS:
            return 'recover','Owning stage heartbeat is stale and its operation deadline expired'
        if deadline and _age(deadline, now) >= LIVELOCK_AFTER_DEADLINE_SECONDS:
            return "valid_wait", "Stage owner is alive past its operation deadline; report slow stage without duplicate restart"
        # A live owner is still inside the stage. Quiet progress is not a pause.
        return "valid_wait", f"Owning stage is still running: {stage.get('operation') or stage['stage']}"
    if state == "queued" and _age(stage.get("updated_at"), now) < CHECK_AFTER_SECONDS:
        return "valid_wait", "Delivery is within its one-minute queue grace period"
    if state == "waiting" and _age(stage.get("updated_at"), now) < CHECK_AFTER_SECONDS:
        return "valid_wait", str(stage.get("error") or "Waiting for the next dependency check")
    if state == 'waiting' and any(word in str(stage.get('error') or '').lower() for word in ('gpu','thermal','lease','capacity','model','unavailable','dependency','source key','quality triage','still writing','writing in','interrupted by progressagent','cancelled by progressagent','stage process cancelled','exited without a result','database lock','lock timeout','deadlock','canceling statement')):
        return 'retry_dependency','A bounded dependency wait is ready to be checked again'
    return "recover", "Current stage has no executing claim or its delivery is stale"


def queue_delivery_state(queue):
    """Inspect queue ownership without mistaking an unreachable inspector for an empty queue.

    A queue with no consumer is an actionable deployment blocker, not a normal
    wait. Never revoke queued tasks or change evidence counters here.
    """
    global _QUEUE_STATE
    if time.monotonic() - _QUEUE_STATE[0] > 30 or _QUEUE_STATE[1] is None:
        try:
            from celery import current_app
            inspector = current_app.control.inspect(timeout=1)
            queues = inspector.active_queues()
            active = inspector.active()
            if queues is None:
                # A broker/control-plane outage cannot prove the consumer is absent.
                _QUEUE_STATE = (time.monotonic(), (None, None))
            else:
                _QUEUE_STATE = (time.monotonic(), (queues, active or {}))
        except Exception:
            _QUEUE_STATE = (time.monotonic(), (None, None))
    queues, active = _QUEUE_STATE[1]
    if queues is None:
        return 'valid_wait', (
            'Cannot verify Celery consumers; inspect broker connection, worker logs '
            'and inspect permissions before retrying the stage'
        )
    consumers = [worker for worker, entries in queues.items()
                 if any(entry.get('name') == queue for entry in (entries or []))]
    if not consumers:
        service = 'worker-ocr-gpu' if queue == 'ocr' else f'consumer of {queue}'
        return 'blocked', (
            f'No worker subscribes to Celery queue {queue}; verify {service} '
            'is running, connected to the same broker and has the correct -Q setting'
        )
    if all(active.get(worker) for worker in consumers):
        return 'valid_wait', 'Consumers are executing bounded process work; delivery is queued'
    return 'recover', 'A consumer is available but the stage delivery is stale'


def _event(db, job_id, stage, decision, reason, *, details=None):
    previous = fetchone(db, "SELECT decision,reason FROM pipeline_progress_checks WHERE job_id=:jid", {"jid": job_id})
    changed = not previous or previous.get("decision") != decision or previous.get("reason") != reason
    if changed:
        execute(db, """INSERT INTO pipeline_progress_events(job_id,stage,decision,reason,details)
            VALUES(:jid,:stage,:decision,:reason,CAST(:details AS jsonb))""",
            {"jid": job_id, "stage": stage, "decision": decision, "reason": reason, "details": json.dumps(details or {})})
        from app.services.disk_build_log import write_disk_log
        # The card already shows counts. Repeating the same wait on every pass
        # made the extraction log look like a stuck loop.
        noisy = str(reason or "").startswith((
            "Still writing", "Useful work advanced", "Bounded operation",
            "Delivery is within", "Paused by the user", "Owning stage is still running",
            "Chunk barrier", "OCR quality triage", "A bounded dependency",
            "Quality triage", "No unfinished work found", "Neo4j unavailable",
            "Deadlock", "Priority evidence",
        ))
        logged = f"progressAgent: {reason}"
        last = None if noisy else fetchone(
            db,
            """SELECT message FROM disk_build_logs
               WHERE job_id=:jid AND message LIKE 'progressAgent:%'
               ORDER BY id DESC LIMIT 1""",
            {"jid": job_id},
        )
        if not noisy and (not last or last.get("message") != logged):
            write_disk_log(db, job_id, logged, stage=stage or "progress", level="warning" if decision in {"cancel", "blocked"} else "info")
    execute(db, "UPDATE pipeline_progress_checks SET checked_at=NOW(),decision=:d,reason=:r WHERE job_id=:jid", {"jid": job_id, "d": decision, "r": reason})


def note_operation(db, job_id, stage, operation, *, timeout_seconds=300, advanced=False):
    """Declare a bounded operation; heartbeats never extend this deadline."""
    timeout_seconds = max(1, min(float(timeout_seconds), 3600))
    execute(db, """UPDATE pipeline_stage_runs SET operation=:op,
        operation_deadline=NOW()+make_interval(secs=>CAST(:seconds AS double precision)),
        progress_at=CASE WHEN :advanced THEN NOW() ELSE progress_at END
        WHERE job_id=:jid AND stage=:stage AND status='running'""",
        {"jid": job_id, "stage": stage, "op": operation[:300], "seconds": timeout_seconds, "advanced": advanced})
    db.commit()



def _stage_remaining_state(db, job_id: str, stage: dict) -> dict:
    """Return authoritative unfinished work for the active forensic stage.

    Stage counters are display counters; completion is decided from the tables that
    own the work. This prevents a card from remaining at 99% after every evidence
    item has already reached a terminal state.
    """
    stage_name = str(stage.get("stage") or "")
    remaining: dict[str, int] = {}

    work = fetchone(db, """SELECT
        count(*) FILTER (WHERE status='pending') AS pending,
        count(*) FILTER (WHERE status='running') AS running
        FROM pipeline_work_items WHERE stage_run_id=:sid""", {"sid": stage["id"]}) or {}
    if int(work.get("pending") or 0):
        remaining["work_pending"] = int(work["pending"])
    if int(work.get("running") or 0):
        remaining["work_running"] = int(work["running"])

    if stage_name == "parse":
        row = fetchone(db, """SELECT
            count(*) FILTER (WHERE parse_status='pending') AS pending,
            count(*) FILTER (WHERE parse_status='parsing') AS running
            FROM job_artifacts WHERE job_id=:jid""", {"jid": job_id}) or {}
        if int(row.get("pending") or 0):
            remaining["parse_pending"] = int(row["pending"])
        if int(row.get("running") or 0):
            remaining["parse_running"] = int(row["running"])
    elif stage_name == "materialize":
        expected = int(stage.get("total_items") or 0)
        registered = int((fetchone(db, """SELECT count(*) AS c FROM job_artifacts
            WHERE job_id=:jid AND metadata->>'serial_materialized'='true'""", {"jid": job_id}) or {}).get("c") or 0)
        if expected > registered:
            remaining["unregistered"] = expected - registered
    elif stage_name == "ocr":
        try:
            from app.services.ocr_gpu import count_pending_ocr
            pending = int(count_pending_ocr(db, job_id) or 0)
            if pending:
                remaining["ocr_pending"] = pending
        except Exception:
            remaining["ocr_check_unavailable"] = 1
    elif stage_name == "chunk":
        from app.services.forensic_serial_policy import chunk_policy_accepted_sql
        pending = int((fetchone(db, f"""SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
            AND NOT (COALESCE(metadata->>'serial_chunked','false')='true'
              AND {chunk_policy_accepted_sql()})""",
            {"jid": job_id}) or {}).get("c") or 0)
        if pending:
            remaining["chunk_pending"] = pending
    elif stage_name == "media_review":
        table = fetchone(db, "SELECT to_regclass('forensic_media_observations') AS t")
        if table and table.get("t"):
            pending = int((fetchone(db, """SELECT count(*) AS c FROM forensic_media_observations
                WHERE job_id=:jid AND status IN ('pending','running')""", {"jid": job_id}) or {}).get("c") or 0)
            if pending:
                remaining["media_pending"] = pending
    elif stage_name == "inventory":
        try:
            from app.services.catalog_artifact_runner import axiom_inventory_progress
            inv = axiom_inventory_progress(db, job_id) or {}
            if not inv.get("done"):
                total = int(inv.get("total") or 0)
                completed = int(inv.get("completed") or 0)
                remaining["inventory_pending"] = max(total - completed, 1)
        except Exception:
            remaining["inventory_check_unavailable"] = 1

    # A worker may have finished all counted rows but still be flushing a tar,
    # hashing a large object, writing MinIO/PostgreSQL, or finalizing a model batch.
    # Keep the stage open while its declared bounded operation is still live and
    # expose that I/O explicitly instead of an unexplained 99%.
    deadline = stage.get("operation_deadline")
    if stage.get("operation") and deadline and _age(deadline, datetime.now(timezone.utc)) == 0:
        remaining["io_active"] = 1

    total = int(stage.get("total_items") or 0)
    accounted = sum(int(stage.get(k) or 0) for k in ("completed_items", "failed_items", "skipped_items"))
    return {
        "stage": stage_name,
        "total": total,
        "accounted": accounted,
        "remaining": remaining,
        "remaining_count": sum(v for k, v in remaining.items() if not k.endswith("_unavailable")),
        "checks_available": not any(k.endswith("_unavailable") for k in remaining),
        "operation": stage.get("operation"),
    }


def _remaining_summary(state: dict) -> str:
    remaining = state.get("remaining") or {}
    labels = {
        "work_pending": "queued work units", "work_running": "running work units",
        "parse_pending": "files waiting to parse", "parse_running": "files still parsing",
        "unregistered": "files waiting for registration", "ocr_pending": "OCR items",
        "chunk_pending": "files waiting for RAG chunks", "media_pending": "media observations",
        "inventory_pending": "inventory items", "io_active": "active I/O / final write",
        "producer_finalization": "producer finalization / committed barrier check",
    }
    parts = [f"{int(value):,} {labels.get(key, key.replace('_', ' '))}"
             for key, value in remaining.items() if int(value or 0) > 0 and not key.endswith("_unavailable")]
    if parts:
        op = str(state.get("operation") or "")
        # Shard and priority lines already name the fraction, rate, and current
        # file. Prefixing "1 active I/O" hid that and left the 99% card opaque.
        if op.startswith(("Shard scan", "Parsing ", "Priority evidence")):
            return op
        suffix = f" — {op}" if op else ""
        return "Still writing / processing: " + ", ".join(parts) + suffix
    if not state.get("checks_available", True):
        return "Completion verification is waiting for a stage-specific checker"
    return "No unfinished work found; progressAgent verified the stage barrier"


def reconcile_count_complete_stage(db, job_id: str, stage: dict) -> dict | None:
    """Explain a 99% stage when its displayed denominator is fully accounted for.

    This is deliberately conservative: all stage-specific pending/running sources
    plus pipeline work-items must be empty. If work remains, persist an exact UI
    explanation instead of leaving an unexplained 99%.
    """
    if str(stage.get("status") or "") not in {"running", "waiting", "queued"}:
        return None
    total = int(stage.get("total_items") or 0)
    accounted = sum(int(stage.get(k) or 0) for k in ("completed_items", "failed_items", "skipped_items"))
    if total <= 0 or accounted < total:
        return None
    state = _stage_remaining_state(db, job_id, stage)
    # Counts do not prove producer termination or completion of downstream writes.
    # Only the controller, after its isolated worker returns and DB barriers pass,
    # may seal a stage. The monitor records exact remaining work and never races it.
    # Queued or running units are the real remainder. A finalization flag on top of
    # them made a busy stage look like it was stuck on one last write.
    unfinished = sum(
        int(value or 0)
        for key, value in (state.get("remaining") or {}).items()
        if not str(key).endswith("_unavailable")
    )
    if unfinished <= 0:
        state["remaining"]["producer_finalization"] = 1
        state["remaining_count"] += 1
    summary = _remaining_summary(state)
    details_patch = json.dumps({
        "progress_agent_reconciliation": {
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "accounted": accounted, "total": total,
            "remaining": state.get("remaining") or {},
            "summary": summary,
        }
    })
    execute(db, """UPDATE pipeline_stage_runs
        SET details=COALESCE(details,'{}'::jsonb) || CAST(:patch AS jsonb)
        WHERE id=:id""", {"id": stage["id"], "patch": details_patch})
    return {"completed": False, "summary": summary, **state}

def _queue_pending_directory(db, job, *, schema_name: str) -> None:
    """Start a saved directory that the first extract left behind.

    Later stages may already be running. The directory extract uses its own
    claim and does not restart those stages.
    """
    job_id = str(job.get("id") or "")
    if not job_id:
        return
    try:
        from app.services.next_evidence_directory import unfinished_directory_reason

        reason = unfinished_directory_reason(db, job_id, job)
        if not reason or "starts after" not in reason:
            return
        source = job.get("disk_source") or {}
        if isinstance(source, str):
            source = json.loads(source)
        if not isinstance(source, dict):
            source = {}
        append = source.get("directory_append") if isinstance(source.get("directory_append"), dict) else {}
        try:
            heartbeat = float(append.get("heartbeat_at") or 0)
        except (TypeError, ValueError):
            heartbeat = 0.0
        try:
            queued_at = float(source.get("directory_append_queued_at") or 0)
        except (TypeError, ValueError):
            queued_at = 0.0
        now = time.time()
        if now - heartbeat < 180 or now - queued_at < 180:
            return
        execute(
            db,
            """UPDATE jobs
                  SET disk_source = jsonb_set(
                        COALESCE(disk_source, '{}'::jsonb),
                        '{directory_append_queued_at}',
                        CAST(:payload AS jsonb),
                        true
                      ),
                      updated_at = NOW()
                WHERE id = :id""",
            {"id": job_id, "payload": json.dumps(now)},
        )
        from app.services.disk_build_log import write_disk_log

        write_disk_log(db, job_id, reason, stage="extract")
        db.commit()
        from app.tasks import phase3_pipeline_task

        phase3_pipeline_task.delay(schema_name, job_id)
    except Exception:
        log.exception("pending directory was not queued job=%s", job_id)
        try:
            db.rollback()
        except Exception:
            pass


def monitor_job(db, job_id, *, schema_name):
    from app.services.forensic_serial_pipeline import (STAGES, stage_rows, first_open_stage,
        pipeline_execution_lock, start_serial_pipeline, dispatch_current_stage, persist_snapshot)
    from app.services.mobile_platform_agents import current_service_owns_job
    job = fetchone(db, "SELECT * FROM jobs WHERE id=:jid", {"jid": job_id})
    if not job:
        return {"status": "held", "reason": "missing_or_other_product", "job_id": job_id}
    if str(job.get('status') or '') == 'registered':
        try:
            from app.services.mobile_platform_agents import reconcile_mobile_platform_from_registered_evidence
            reconcile_mobile_platform_from_registered_evidence(db, job_id)
            job = fetchone(db, "SELECT * FROM jobs WHERE id=:jid", {"jid": job_id}) or job
        except Exception:
            try: db.rollback()
            except Exception: pass
    if not current_service_owns_job(db, job_id):
        return {"status": "held", "reason": "missing_or_other_product", "job_id": job_id}
    _queue_pending_directory(db, job, schema_name=schema_name)
    try:
        from app.services.safe_parallel import ensure_parse_shards

        ensure_parse_shards(db, job_id, schema_name=schema_name)
    except Exception:
        log.debug("parse shards were not requeued job=%s", job_id, exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
    # An extraction barrier always outranks leftover serial stage rows. A
    # partially processed historical case must not evade acquisition watchdogs.
    if (str(job.get("status") or "") in {"processing", "building_disk", "extracting"}
            and not job.get("extracted_disk_uri")):
        return _monitor_acquisition(db, job, schema_name=schema_name)
    report = _monitor_report(db, job, schema_name=schema_name)
    if report is not None:
        return report
    rows = stage_rows(db, job_id)
    if rows and [r['stage'] for r in rows] != [s[0] for s in STAGES]:
        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    active = first_open_stage(rows) if rows else None
    if not active:
        if rows:
            return {"status": "complete", "job_id": job_id}
        return _monitor_acquisition(db, job, schema_name=schema_name)

    # A newly eligible stage has no Celery owner. Dispatch it immediately rather
    # than waiting for the stale-claim watchdog interval. dispatch_current_stage
    # locks the job row and atomically moves the single authoritative stage to
    # queued before publishing, so concurrent process agents cannot double-start.
    if active.get('status') == 'pending':
        return {**dispatch_current_stage(db, job_id, schema_name=schema_name),
                'job_id': job_id, 'coordinator': 'progressAgent',
                'reason': 'Immediate dependency handoff'}

    # Resource-aware parallelism: while recovery/OCR is the critical path, start
    # independent CPU/DB sidecars (parsed-text prechunk + leakage analysis; inventory
    # only beside OCR). They never own CUDA or source extraction, so quality is not
    # traded for speed. Claims are persisted and restart-safe.
    try:
        from app.services.safe_parallel import schedule_safe_sidecars
        schedule_safe_sidecars(db, job_id, schema_name=schema_name, active_stage=str(active.get('stage') or ''))
    except Exception:
        try: db.rollback()
        except Exception: pass

    # Counts can reach their denominator a few seconds before the stage worker
    # returns. Verify the real barrier immediately so the UI never sits at an
    # unexplained 99%. If work remains, expose exactly what is still active.
    reconciled = reconcile_count_complete_stage(db, job_id, active)
    if reconciled:
        persist_snapshot(db, job_id)
        _event(db, job_id, active['stage'],
               'complete' if reconciled['completed'] else 'progressing', reconciled['summary'],
               details={"remaining": reconciled.get("remaining") or {}})
        db.commit()
        if reconciled['completed']:
            return {**dispatch_current_stage(db, job_id, schema_name=schema_name),
                    'job_id': job_id, 'coordinator': 'progressAgent',
                    'reconciled_stage': active['stage'], 'reason': reconciled['summary']}
        # Refresh the stage row so its new details are included in subsequent state.
        active = first_open_stage(stage_rows(db, job_id)) or active

    fingerprint = hashlib.sha256(json.dumps([active['id'],active['status'],active.get('completed_items'),
        active.get('failed_items'),active.get('skipped_items'),str(active.get('progress_at'))], default=str).encode()).hexdigest()
    execute(db, """INSERT INTO pipeline_progress_checks(job_id,fingerprint) VALUES(:jid,:fp)
        ON CONFLICT(job_id) DO UPDATE SET last_change_at=CASE WHEN pipeline_progress_checks.fingerprint<>EXCLUDED.fingerprint
        THEN NOW() ELSE pipeline_progress_checks.last_change_at END,fingerprint=EXCLUDED.fingerprint,checked_at=NOW()""", {"jid":job_id,"fp":fingerprint})
    decision, reason = classify_stage(job, active)
    if decision=='recover' and active['status']=='queued':
        from app.services.forensic_serial_pipeline import queue_for_stage
        decision,reason=queue_delivery_state(queue_for_stage(active['stage']))
    _event(db,job_id,active['stage'],decision,reason)
    if decision == 'cancel':
        # The owning parent cancels only its dedicated stage subprocess. No
        # broadcast terminate/revoke can kill a worker now executing another job.
        execute(db, """UPDATE pipeline_stage_runs SET cancel_requested_at=COALESCE(cancel_requested_at,NOW())
            WHERE id=:id AND task_id=:tid AND status='running'""", {'id':active['id'],'tid':active.get('task_id')})
        db.commit()
        return {'status':'recovering','reason':reason,'stage':active['stage'],'job_id':job_id}
    db.commit()
    if decision not in {'recover','retry_dependency'}:
        return {'status':decision,'reason':reason,'stage':active['stage'],'job_id':job_id}
    with pipeline_execution_lock(db,schema_name,job_id) as acquired:
        if not acquired:
            # The live owner holds this lock for the whole stage. A recover cannot
            # reset that row. Leaving an already-expired deadline in place makes the
            # next check cancel the child as soon as its heartbeat pulse lands.
            if decision == 'recover' and active.get('status') == 'running':
                execute(
                    db,
                    """UPDATE pipeline_stage_runs
                       SET operation_deadline=NOW()+make_interval(secs=>180),
                           operation=COALESCE(NULLIF(operation,''), :op)
                       WHERE id=:id AND status='running'
                         AND (operation_deadline IS NULL OR operation_deadline < NOW())""",
                    {"id": active["id"], "op": f"{active.get('stage') or 'stage'}: owner still running"},
                )
                db.commit()
            return {'status':'valid_wait','reason':'Owning stage is still releasing its execution lock','job_id':job_id}
        fresh=first_open_stage(stage_rows(db,job_id))
        latest=fetchone(db,'SELECT stop_requested,status FROM jobs WHERE id=:jid',{'jid':job_id})
        if not fresh or classify_stage(latest,fresh)[0] not in {'recover','retry_dependency'}:
            return {'status':'held','reason':'Progress changed during inspection','job_id':job_id}
        if decision=='recover' and int(fresh.get('recovery_dispatches') or 0)>=MAX_RECOVERY_ATTEMPTS:
            from app.services.forensic_failure_alerts import record_failure
            record_failure(db, job_id, fresh['stage'], 'retry-budget', RuntimeError(
                'progressAgent retry budget exhausted. Last error: '+str(fresh.get('error') or 'Worker exited without a traceback')))
            execute(db,"UPDATE pipeline_stage_runs SET status='failed',error='progressAgent retry budget exhausted',updated_at=NOW() WHERE id=:id",{'id':fresh['id']})
            persist_snapshot(db,job_id);db.commit()
            return {'status':'blocked','reason':'Retry budget exhausted','job_id':job_id}
        execute(db,"""UPDATE pipeline_stage_runs SET status='waiting',task_id=NULL,cancel_requested_at=NULL,
            operation=NULL,operation_deadline=NULL,recovery_dispatches=recovery_dispatches+:increment,updated_at=NOW() WHERE id=:id""",{'id':fresh['id'],'increment':int(decision=='recover')})
        db.commit()
    return {**dispatch_current_stage(db,job_id,schema_name=schema_name),'job_id':job_id,'coordinator':'progressAgent'}


def progress_events_page(db,job_id,*,limit=100):
    exists=fetchone(db,"SELECT to_regclass('pipeline_progress_events') AS t")
    if not exists or not exists['t']:
        return {'events':[],'coordinator':'progressAgent'}
    return {'events':fetchall(db,"SELECT * FROM pipeline_progress_events WHERE job_id=:jid ORDER BY id DESC LIMIT :lim",{'jid':job_id,'lim':max(1,min(int(limit),200))}),'coordinator':'progressAgent'}



def acquisition_fingerprint(job: dict) -> str:
    """Fingerprint actual acquisition work, not liveness touches or periodic logs."""
    activity = _obj(job.get("pipeline_progress")).get("extraction_activity") or {}
    checkpoint = _obj(job.get("extraction_checkpoint"))
    payload = [
        activity.get("subphase"), activity.get("files_found"),
        activity.get("entries_scanned"), activity.get("directories_scanned"),
        activity.get("files_extracted"), activity.get("bytes_extracted"),
        activity.get("shards_done"), activity.get("unreadable_directories"),
        activity.get("last_path"), activity.get("alias_directories_skipped"),
        len(checkpoint.get("completed_shards") or []),
        checkpoint.get("files_extracted"), checkpoint.get("bytes_extracted"),
    ]
    return "extract:" + hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()


def acquisition_diagnosis(job: dict, age_seconds: float) -> str:
    """Explain exactly which slow sub-operation the examiner should inspect."""
    activity = _obj(job.get("pipeline_progress")).get("extraction_activity") or {}
    subphase = str(activity.get("subphase") or "preparing")
    if subphase == "enumerating":
        files = int(activity.get("files_found") or 0)
        dirs = int(activity.get("directories_scanned") or 0)
        entries = int(activity.get("entries_scanned") or 0)
        errors = int(activity.get("unreadable_directories") or 0)
        last = str(activity.get("last_path") or "unknown")[:180]
        phase = str(activity.get("reader_phase") or "unknown")
        method = str(activity.get("root_open_strategy") or "unknown")
        attempt = int(activity.get("reader_attempt") or 0)
        inventory_mode = str(activity.get("inventory_mode") or "unknown")
        last_read = activity.get("last_source_read_offset")
        io_detail = (f"; last E01 byte offset={last_read}" if last_read is not None else "")
        if files == 0 and dirs == 0 and entries == 0:
            if phase in {"root_open", "root_first_entry"}:
                if last_read is not None:
                    detail = (f"native reader phase={phase}, root method={method}; "
                              f"still reading E01 metadata at byte {last_read} "
                              f"while the TSK root directory is opening{io_detail}")
                else:
                    detail = (f"native reader phase={phase}, root method={method}; "
                              f"blocked opening the TSK root or obtaining its first entry{io_detail}")
            else:
                detail = f"native reader phase={phase}; inspect image reopen/partition mount and segment I/O"
        else:
            detail = f"reader phase={phase}; last path={last}"
        return (f"TSK filesystem walk: no useful entry progress for {int(age_seconds)}s; "
                f"attempt={attempt} ({inventory_mode}), files={files:,}, dirs={dirs:,}, "
                f"entries={entries:,}, unreadable={errors:,}; "
                f"{detail}. Isolated watchdog will use serial fallback before alternating the root method; "
                "do not start a duplicate extraction.")
    if subphase == "copying":
        return (f"MinIO copy: no committed file/byte/shard progress for {int(age_seconds)}s; "
                "check S3 writes, disk source reads, extraction lock and storage capacity.")
    return (f"Extraction/{subphase}: no useful progress for {int(age_seconds)}s; "
            "check worker queue, evidence mount, CPU admission and source image read.")


def inspect_acquisition_progress(db, job: dict, *, schema_name: str, now=None) -> dict:
    """Acquisition-specific progressAgent rules. Never duplicate a live extractor.

    Native E01 readers now have their own disposable subprocess watchdog.
    progressAgent records the specific stall reason, and only requeues if *both*
    the extraction lock and the Celery task are known absent.
    """
    from app.services.job_locks import extract_task_in_flight, extract_celery_work_active

    now = now or datetime.now(timezone.utc)
    jid = str(job["id"])
    fp = acquisition_fingerprint(job)
    execute(db, """INSERT INTO pipeline_progress_checks(job_id,fingerprint) VALUES(:jid,:fp)
        ON CONFLICT(job_id) DO UPDATE SET
            last_change_at=CASE WHEN pipeline_progress_checks.fingerprint<>EXCLUDED.fingerprint
                THEN NOW() ELSE pipeline_progress_checks.last_change_at END,
            acquisition_recoveries=CASE WHEN pipeline_progress_checks.fingerprint<>EXCLUDED.fingerprint
                THEN 0 ELSE pipeline_progress_checks.acquisition_recoveries END,
            acquisition_last_dispatch_at=CASE WHEN pipeline_progress_checks.fingerprint<>EXCLUDED.fingerprint
                THEN NULL ELSE pipeline_progress_checks.acquisition_last_dispatch_at END,
            fingerprint=EXCLUDED.fingerprint,checked_at=NOW()""", {"jid": jid, "fp": fp})
    row = fetchone(db, "SELECT last_change_at,acquisition_recoveries,acquisition_last_dispatch_at FROM pipeline_progress_checks WHERE job_id=:jid", {"jid": jid}) or {}
    age = _age(row.get("last_change_at"), now)
    warn_at = max(45, int(os.environ.get("PROGRESS_AGENT_EXTRACT_WARN_SECONDS", "90")))
    # Per-child diagnostic clock is distinct from TRUE evidence progress.
    # Do not add an attempt restart to acquisition_fingerprint: doing so would
    # reset acquisition_recoveries and could allow unlimited job redispatches.
    activity = _obj(job.get("pipeline_progress")).get("extraction_activity") or {}
    attempt_age = float("inf")
    if str(activity.get("subphase") or "") == "enumerating":
        try:
            attempt_age = _age(activity.get("reader_attempt_started_at"), now)
        except (TypeError, ValueError, OverflowError):
            pass
    diagnostic_age = min(age, attempt_age)
    if age < warn_at:
        db.commit()
        return {"status": "progressing", "reason": "Useful extraction progress observed", "job_id": jid,
                "useful_progress_age_sec": int(age)}
    if diagnostic_age < warn_at:
        db.commit()
        return {"status": "valid_wait", "reason": "New isolated reader attempt is inside its monitoring grace period; no new evidence entries yet",
                "job_id": jid, "reader_attempt_age_sec": int(attempt_age),
                "useful_progress_age_sec": int(age)}
    # Keep log/event output stable for a window instead of changing a duration
    # number every 15s and flooding the case's immutable forensic audit log.
    elapsed_bucket = warn_at * max(1, int(diagnostic_age // warn_at))
    diagnosis = acquisition_diagnosis(job, elapsed_bucket)
    live_task = extract_celery_work_active(jid)
    # Avoid releasing a lock based on DB heartbeats. Celery absence must be
    # confirmed before extract_task_in_flight is allowed to inspect stale locks.
    if live_task is True or live_task is None:
        status = "investigate" if live_task is True else "valid_wait"
        reason = diagnosis + (" Isolated TSK watchdog owns bounded recovery; no duplicate task queued."
                              if live_task is True else " Worker inspection unavailable; no unsafe redispatch.")
    else:
        has_lock = extract_task_in_flight(db, jid, idle_sec=180)
        if has_lock:
            status = "investigate"
            reason = diagnosis + " Extract lock still active; waiting for owner/watchdog."
        else:
            status = "recover"
            reason = diagnosis + " No worker or extraction lease found; resume from checkpoint."
    # Log a diagnosable event instead of silently returning 'progressing' from
    # jobs.updated_at which the heartbeat thread updates without evidence work.
    _event(db, jid, "extract", status, reason)
    attempts = int(row.get("acquisition_recoveries") or 0)
    if status == "recover":
        # Queued Celery delivery can take a minute to acquire its lease. Never
        # post duplicate deliveries in that grace window.
        since_dispatch = _age(row.get("acquisition_last_dispatch_at"), now)
        if since_dispatch < 120:
            db.commit()
            return {"status": "valid_wait", "reason": "Checkpoint recovery was queued recently; waiting for its owner", "job_id": jid}
        if attempts >= MAX_RECOVERY_ATTEMPTS:
            status = "blocked"
            reason = "Acquisition recovery budget exhausted. " + diagnosis
            _event(db, jid, "extract", status, reason)
        else:
            execute(db, """UPDATE pipeline_progress_checks SET acquisition_recoveries=acquisition_recoveries+1
                    , acquisition_last_dispatch_at=NOW()
                WHERE job_id=:jid""", {"jid": jid})
            db.commit()
            from app.services.pipeline_supervisor import dispatch_stage_agent
            recommendation = {"agent_id": "extract_agent", "action": "resume_extraction",
                              "reason": "progressAgent repair: " + diagnosis}
            return dispatch_stage_agent(db, jid, schema_name=schema_name,
                                        recommendation=recommendation, coordinator="progressAgent")
    db.commit()
    return {"status": status, "reason": reason, "stage": "extract", "job_id": jid,
            "useful_progress_age_sec": int(age)}

def _monitor_acquisition(db, job, *, schema_name):
    """Recover abandoned extraction claims; never duplicate a live extractor."""
    from app.services.forensic_serial_pipeline import start_serial_pipeline
    from app.services.mobile_os import load_job_disk_source
    from app.services.host_evidence import is_client_upload_pending
    if job.get('stop_requested'):
        return {'status':'valid_wait','reason':'Paused by user — stop request is active','job_id':str(job['id'])}
    if job.get('status')=='paused' and not _is_auto_resumable_pause(job):
        return {'status':'valid_wait','reason':'Paused','job_id':str(job['id'])}
    if is_client_upload_pending(load_job_disk_source(job)):
        return {'status':'valid_wait','reason':'Evidence transfer incomplete','job_id':str(job['id'])}
    if str(job.get('status') or '') == 'registered':
        from app.services.pipeline_supervisor import analyze_job_pipeline, dispatch_stage_agent
        recommendation=analyze_job_pipeline(db,str(job['id']))
        if recommendation:
            return dispatch_stage_agent(db,str(job['id']),schema_name=schema_name,recommendation=recommendation,coordinator='progressAgent')
        return {'status':'valid_wait','reason':'Registered evidence manifest is complete but no extraction worker owns the job','job_id':str(job['id'])}
    if job.get('extracted_disk_uri') and job.get('status') in {'extracted','indexing','indexed','parsed','artifacts_registered'}:
        return start_serial_pipeline(db,str(job['id']),schema_name=schema_name)
    checkpoint=_obj(job.get('extraction_checkpoint'))
    if checkpoint.get('state')=='completed' or checkpoint.get('completed') is True:
        return start_serial_pipeline(db,str(job['id']),schema_name=schema_name)
    # A refreshed jobs.updated_at does not mean that an E01 reader made useful
    # progress. Observe stable source counters even while its heartbeat is alive.
    if str(job.get('status') or '') in {'processing', 'building_disk', 'extracting'} and not job.get('extracted_disk_uri'):
        return inspect_acquisition_progress(db, job, schema_name=schema_name)
    # Existing extraction locks and worker heartbeats are examined by the
    # domain engine. This coordinator is the only caller of its stage dispatch.
    from app.services.pipeline_supervisor import analyze_job_pipeline, dispatch_stage_agent
    recommendation=analyze_job_pipeline(db,str(job['id']))
    if recommendation and recommendation.get('agent_id') in {'extract_agent','extract_agent_disk','extract_agent_mobile','extract_agent_android','extract_agent_ios','drive_mount_agent','list_folder_agent','segments_agent','virtual_disk_agent','extraction_agent','report_generator_agent'}:
        return dispatch_stage_agent(db,str(job['id']),schema_name=schema_name,recommendation=recommendation,coordinator='progressAgent')
    return {'status':'valid_wait','reason':'Acquisition source, live extractor or dependency has not released its claim','job_id':str(job['id'])}


def release_blocking_index_waits(db) -> int:
    """Cancel CREATE INDEX sessions that are queued on a lock, not building.

    A waiting ShareLock blocks later inserts on that table, so image/video
    observations stay at 0% behind a no-op "IF NOT EXISTS" index. The statement
    has not changed any data. Cancelling it lets the stage retry or skip.
    """
    rows = fetchall(
        db,
        """SELECT pid FROM pg_stat_activity
           WHERE datname = current_database()
             AND pid <> pg_backend_pid()
             AND state = 'active'
             AND wait_event_type = 'Lock'
             AND now() - query_start > interval '45 seconds'
             AND query NOT ILIKE '%CONCURRENTLY%'
             AND (ltrim(query) ILIKE 'CREATE INDEX%'
                  OR ltrim(query) ILIKE 'ALTER TABLE%')""",
    )
    cancelled = 0
    for row in rows:
        ok = fetchone(db, "SELECT pg_cancel_backend(:pid) AS ok", {"pid": int(row["pid"])}) or {}
        if ok.get("ok"):
            cancelled += 1
            log.warning("progressAgent cancelled a lock-waiting CREATE INDEX (pid %s)", row["pid"])
    return cancelled


def supervise_progress(db, *, schema_name):
    from app.services.forensic_serial_pipeline import pipeline_execution_lock
    ensure_progress_schema(db);db.commit()
    try:
        release_blocking_index_waits(db)
        from app.services.safe_parallel import reap_stale_sidecars
        reap_stale_sidecars(db)
    except Exception:
        log.exception("progressAgent could not clear a lock-waiting index build")
        try:
            db.rollback()
        except Exception:
            pass
    from app.service_identity import current_service
    with pipeline_execution_lock(db,schema_name,'progressAgent:'+current_service()) as acquired:
        if not acquired:
            return {'status':'busy','coordinator':'progressAgent','actions':[]}
        actions=[]
        from app.services.mobile_platform_agents import mobile_os_family_from_job_row
        maximum=max(20,min(int(os.environ.get('PROGRESS_AGENT_JOB_BATCH','200')),1000))
        cursor=None;seen=set()
        while len(actions)<maximum:
            predicate=' AND (updated_at,id)>(:after_time,CAST(:after_id AS uuid))' if cursor else ''
            params={'lim':maximum}
            if cursor:params.update(after_time=cursor['updated_at'],after_id=str(cursor['id']))
            rows=fetchall(db,"""SELECT id,type,disk_source,status,error,updated_at FROM jobs WHERE stop_requested=FALSE
                AND ((status NOT IN ('ready','completed','report_ready','cancelled','deleted','created','awaiting_segments') OR (status='registered' AND EXISTS(SELECT 1 FROM evidence_files e WHERE e.job_id=jobs.id)))
                     OR EXISTS(SELECT 1 FROM report_runs r WHERE r.job_id=jobs.id AND r.status IN ('running','queued','waiting')))
                """+predicate+' ORDER BY updated_at,id LIMIT :lim',params)
            if not rows:break
            for row in rows:
                if str(row.get('status') or '') == 'registered':
                    try:
                        from app.services.mobile_platform_agents import reconcile_mobile_platform_from_registered_evidence
                        reconcile_mobile_platform_from_registered_evidence(db,str(row['id']))
                        row=fetchone(db,"SELECT id,type,disk_source,status,error,updated_at FROM jobs WHERE id=:id",{'id':row['id']}) or row
                    except Exception:
                        try: db.rollback()
                        except Exception: pass
                family=mobile_os_family_from_job_row(row);service=current_service()
                owned=(family is None if service=='forensic' else family=='android' if service=='mobile-android' else family=='ios' if service=='mobile-ios' else family in {'android','ios'})
                if not owned or row['id'] in seen:continue
                seen.add(row['id'])
                try:
                    actions.append(monitor_job(db,str(row['id']),schema_name=schema_name))
                except Exception as exc:
                    db.rollback()
                    actions.append({'job_id':str(row['id']),'status':'error','reason':str(exc)[:300]})
                if len(actions)>=maximum:break
            cursor=rows[-1]
        return {'status':'ok','coordinator':'progressAgent','schema':schema_name,'actions':actions}


def _monitor_report(db,job,*,schema_name):
    exists=fetchone(db,"SELECT to_regclass('report_runs') AS t")
    if not exists or not exists['t']:
        return None
    run=fetchone(db,"SELECT * FROM report_runs WHERE job_id=:jid AND status IN ('running','queued','waiting') ORDER BY created_at DESC LIMIT 1",{'jid':job['id']})
    if not run:
        return None
    stage={**run,'stage':'report','updated_at':run.get('heartbeat_at') or run.get('started_at') or run['created_at'],'attempt':run.get('recovery_dispatches',0)}
    decision,reason=classify_stage(job,stage)
    if decision=='recover' and run['status']=='queued':
        decision,reason=queue_delivery_state(report_queue())
    execute(db,"""INSERT INTO pipeline_progress_checks(job_id,fingerprint) VALUES(:jid,:fp)
        ON CONFLICT(job_id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,checked_at=NOW()""",
        {'jid':job['id'],'fp':'report:'+str(run['id'])+':'+str(run.get('progress_at'))})
    _event(db,str(job['id']),'report',decision,reason)
    db.commit()
    if decision=='cancel':
        execute(db,"UPDATE report_runs SET cancel_requested_at=COALESCE(cancel_requested_at,NOW()) WHERE id=:id AND owner_task_id=:tid AND status='running'",{'id':run['id'],'tid':run.get('owner_task_id')});db.commit()
        return {'status':'recovering','stage':'report','reason':reason,'job_id':str(job['id'])}
    if decision in {'recover','retry_dependency'}:
        from app.services.forensic_serial_pipeline import pipeline_execution_lock
        with pipeline_execution_lock(db,schema_name,str(job['id'])) as acquired:
            if not acquired:
                return {'status':'valid_wait','stage':'report','reason':'Report owner is releasing its claim'}
            fresh_job=fetchone(db,'SELECT status,stop_requested FROM jobs WHERE id=:jid',{'jid':job['id']})
            run=fetchone(db,'SELECT * FROM report_runs WHERE id=:id',{'id':run['id']})
            if not run or run['status'] not in {'running','queued','waiting'}:
                return {'status':'complete','stage':'report','reason':'Report state changed while checking its claim'}
            stage={**run,'stage':'report','updated_at':run.get('heartbeat_at') or run.get('started_at') or run['created_at']}
            decision,reason=classify_stage(fresh_job or {},stage)
            if decision not in {'recover','retry_dependency'}:
                return {'status':decision,'stage':'report','reason':reason}
            if decision=='recover' and int(run.get('recovery_dispatches') or 0)>=MAX_RECOVERY_ATTEMPTS:
                from app.services.forensic_failure_alerts import record_failure
                record_failure(db, str(job['id']), '__report__', 'retry-budget:'+str(run['id']), RuntimeError(
                    'progressAgent report retry budget exhausted. Last error: '+str(run.get('error') or 'Worker exited without a traceback')))
                execute(db,"UPDATE report_runs SET status='failed',error='progressAgent report retry budget exhausted' WHERE id=:id",{'id':run['id']});db.commit()
                return {'status':'blocked','stage':'report','reason':'Report retry budget exhausted'}
            execute(db,"UPDATE report_runs SET status='queued',owner_task_id=NULL,cancel_requested_at=NULL,operation_deadline=NULL,recovery_dispatches=recovery_dispatches+:increment,heartbeat_at=NOW() WHERE id=:id",{'id':run['id'],'increment':int(decision=='recover')});db.commit()
        from app.tasks import report_gen_task
        report_gen_task.apply_async(args=(schema_name,str(job['id']),str(run['id'])),queue=report_queue())
        return {'status':'queued','stage':'report','reason':'Report resumed from its saved sections','job_id':str(job['id'])}
    return {'status':decision,'stage':'report','reason':reason,'job_id':str(job['id'])}
