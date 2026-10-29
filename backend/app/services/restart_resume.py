"""Crash/power-loss recovery for persisted forensic pipeline stages."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from app.db.sql_helpers import execute, fetchall, fetchone


def _age_seconds(ts) -> float:
    if not ts: return 10**9
    if getattr(ts,"tzinfo",None) is None: ts=ts.replace(tzinfo=timezone.utc)
    return max(0.0,(datetime.now(timezone.utc)-ts).total_seconds())


def _is_auto_resumable_pause(row):
    if not row or str(row.get('status') or '') != 'paused' or row.get('stop_requested'):
        return False
    err=str(row.get('error') or '').lower()
    return any(k in err for k in ('thermal','capacity','restart','worker unavailable','dependency'))


def recover_interrupted_jobs(db, *, schema_name: str) -> dict:
    """Supersede stale deliveries and resume from persisted per-item checkpoints.

    Completed rows/chunks/OCR results are retained.  Only abandoned *claims* are
    reset to pending, so a reboot never restarts the case from the beginning.
    """
    from app.services.forensic_serial_pipeline import ensure_serial_schema, dispatch_current_stage, stage_rows, first_open_stage
    from app.services.mobile_platform_agents import current_service_owns_job
    ensure_serial_schema(db)
    stale=max(20,min(int(os.environ.get("STARTUP_RESUME_STALE_SECONDS","45") or 45),300))
    # Sidecars use persisted checkpoints too.  A power loss can leave a sidecar
    # row forever in queued/running even though its Celery process disappeared.
    # Reset only stale claims; completed leakage scans/chunks remain in their
    # own tables and are therefore resumed incrementally, never from zero.
    try:
        execute(db, """UPDATE pipeline_sidecar_runs
            SET status='pending', task_id=NULL, heartbeat_at=NULL, updated_at=NOW(),
                details=coalesce(details,'{}'::jsonb) || jsonb_build_object('restart_recovered',true)
            WHERE status IN ('queued','running')
              AND coalesce(heartbeat_at,updated_at) < NOW() - (:secs * interval '1 second')""",
            {'secs': stale})
        db.commit()
    except Exception:
        try: db.rollback()
        except Exception: pass
    jobs=fetchall(db,"""SELECT id,status,stop_requested,error FROM jobs
        WHERE stop_requested=FALSE AND (status NOT IN ('ready','completed','report_ready','cancelled','deleted','created','awaiting_segments') OR (status='registered' AND EXISTS(SELECT 1 FROM evidence_files e WHERE e.job_id=jobs.id)))""")
    resumed=[]; held=[]
    for job in jobs:
        jid=str(job['id'])
        if str(job.get('status') or '') == 'registered':
            try:
                from app.services.mobile_platform_agents import reconcile_mobile_platform_from_registered_evidence
                reconcile_mobile_platform_from_registered_evidence(db,jid)
            except Exception:
                try: db.rollback()
                except Exception: pass
            if not current_service_owns_job(db,jid): continue
            try:
                from app.services.pipeline_supervisor import analyze_job_pipeline, dispatch_stage_agent
                rec=analyze_job_pipeline(db,jid)
                if rec:
                    resumed.append({'job_id':jid,'stage':'registered_manifest','dispatch':dispatch_stage_agent(db,jid,schema_name=schema_name,recommendation=rec,coordinator='progressAgent')})
                    continue
            except Exception:
                try: db.rollback()
                except Exception: pass
        if not current_service_owns_job(db,jid): continue
        rows=stage_rows(db,jid); active=first_open_stage(rows) if rows else None
        if not active: continue
        state=str(active.get('status') or '')
        hb=active.get('heartbeat_at') or active.get('updated_at') or active.get('started_at')
        if state in {'running','queued'} and _age_seconds(hb)<stale:
            held.append(jid); continue
        # Supersede any old Celery delivery. If Redis redelivers it later, task_id
        # mismatch makes run_serial_stage reject it as superseded_delivery.
        execute(db,"""UPDATE pipeline_stage_runs SET status='waiting',task_id=NULL,
            operation=NULL,operation_deadline=NULL,cancel_requested_at=NULL,
            error='Recovered after host/application restart — continuing from persisted checkpoint',updated_at=NOW()
            WHERE id=:id AND status IN ('running','queued','waiting')""",{'id':active['id']})
        execute(db,"UPDATE pipeline_work_items SET status='pending',worker_id=NULL,started_at=NULL,error=NULL WHERE stage_run_id=:sid AND status='running'",{'sid':active['id']})
        if active['stage']=='parse':
            execute(db,"UPDATE job_artifacts SET parse_status='pending' WHERE job_id=:jid AND parse_status='parsing'",{'jid':jid})
        if active['stage']=='media_review':
            execute(db,"UPDATE forensic_media_observations SET status='pending',error=NULL,updated_at=NOW() WHERE job_id=:jid AND status='running'",{'jid':jid})
        db.commit()
        result=dispatch_current_stage(db,jid,schema_name=schema_name,force=True)
        resumed.append({'job_id':jid,'stage':active['stage'],'dispatch':result})
    return {'status':'ok','resumed':resumed,'held_live':held}


def recover_all_firms_for_current_service() -> dict:
    from app.db.session import SessionLocal,firm_session
    schemas=[]
    with SessionLocal() as public:
        rows=fetchall(public,"SELECT schema_name FROM public.firms WHERE status='active' AND schema_name IS NOT NULL")
        schemas=[str(r['schema_name']) for r in rows]
    results=[]
    for schema in schemas:
        try:
            with firm_session(schema) as db: results.append({'schema':schema,**recover_interrupted_jobs(db,schema_name=schema)})
        except Exception as exc:
            results.append({'schema':schema,'status':'error','error':str(exc)[:300]})
    return {'status':'ok','results':results}
