"""Pre-parse committed extraction shards without changing authoritative stage ownership.

Every sidecar uses its own database session. The final materialization barrier
waits for in-flight writers; the full parse/OCR stages reconcile missed work.
"""
from __future__ import annotations
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from app.db.sql_helpers import execute, fetchone
from app.services.forensic_serial_policy import shard_overlap_enabled, stage_context
log = logging.getLogger(__name__)


def ensure_overlap_table(db):
    execute(db, """CREATE TABLE IF NOT EXISTS forensic_shard_overlap (
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        shard_id integer NOT NULL,
        state text NOT NULL DEFAULT 'pending',
        attempts integer NOT NULL DEFAULT 0,
        updated_at timestamptz NOT NULL DEFAULT now(),
        error text,
        claim_token text,
        heartbeat_at timestamptz,
        PRIMARY KEY (job_id, shard_id)
    )""")
    execute(db, "ALTER TABLE forensic_shard_overlap ADD COLUMN IF NOT EXISTS claim_token text")
    execute(db, "ALTER TABLE forensic_shard_overlap ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz")


def register_shard(db, job_id, shard_id):
    ensure_overlap_table(db)
    execute(db, """INSERT INTO forensic_shard_overlap(job_id,shard_id)
        VALUES (:jid,:sid) ON CONFLICT DO NOTHING""", {'jid':job_id,'sid':shard_id})
    db.commit()


def recover_shards(db, job_id, schema_name=None):
    """Recover lost publications and stale claims; never wait forever on a dead worker.

    Runs from the existing authoritative barrier, so no extra cron service is required.
    A bounded retry limit sends permanently failing shards to authoritative parsing.
    """
    if not shard_overlap_enabled():
        return {'requeued': 0, 'exhausted': 0}
    ensure_overlap_table(db)
    lease = max(60, int(os.getenv('FORENSIC_SHARD_LEASE_SECONDS', '300')))
    max_attempts = max(1, int(os.getenv('FORENSIC_SHARD_MAX_ATTEMPTS', '4')))
    rows = db.execute(__import__('sqlalchemy').text("""SELECT shard_id, state, attempts
        FROM forensic_shard_overlap WHERE job_id=:jid AND
          ((state='pending' AND updated_at < now()-make_interval(secs=>:lease))
           OR (state='running' AND COALESCE(heartbeat_at,updated_at) < now()-make_interval(secs=>:lease)))
        FOR UPDATE SKIP LOCKED"""), {'jid':job_id,'lease':lease}).mappings().all()
    retry_ids=[]
    exhausted=0
    for row in rows:
        sid=int(row['shard_id'])
        if int(row['attempts']) >= max_attempts:
            execute(db, """UPDATE forensic_shard_overlap SET state='failed', claim_token=NULL,
                error='Early parsing exhausted retry budget; authoritative parse will reconcile',updated_at=now()
                WHERE job_id=:jid AND shard_id=:sid""", {'jid':job_id,'sid':sid})
            exhausted += 1
        else:
            execute(db, """UPDATE forensic_shard_overlap SET state='pending',claim_token=NULL,
                heartbeat_at=NULL,updated_at=now(), error='Requeued after missed heartbeat/publish'
                WHERE job_id=:jid AND shard_id=:sid""", {'jid':job_id,'sid':sid})
            retry_ids.append(sid)
    db.commit()
    if retry_ids and schema_name:
        from app.tasks import forensic_shard_overlap_task
        for sid in retry_ids:
            try:
                forensic_shard_overlap_task.apply_async(args=(schema_name,str(job_id),sid),queue='disk-parse')
            except Exception:
                log.exception('Shard retry publish failed job=%s shard=%s',job_id,sid)
    return {'requeued':len(retry_ids), 'exhausted':exhausted}


def unfinished_shards(db, job_id):
    if not shard_overlap_enabled():
        return 0
    schema = db.execute(__import__('sqlalchemy').text('SELECT current_schema()')).scalar()
    recover_shards(db,job_id,schema)
    return int(fetchone(db, """SELECT count(*) AS c FROM forensic_shard_overlap
        WHERE job_id=:jid AND state IN ('pending','running')""", {'jid':job_id})['c'])


def _heartbeat(schema_name, job_id, shard_id, token, stopped):
    from app.db.session import firm_session
    interval=max(5,int(os.getenv('FORENSIC_SHARD_HEARTBEAT_SECONDS','20')))
    while not stopped.wait(interval):
        try:
            with firm_session(schema_name) as session:
                execute(session,"""UPDATE forensic_shard_overlap SET heartbeat_at=now()
                    WHERE job_id=:jid AND shard_id=:sid AND state='running'
                      AND claim_token=:token""",{'jid':job_id,'sid':shard_id,'token':token})
                session.commit()
        except Exception:
            log.exception('Overlap shard heartbeat failed job=%s shard=%s',job_id,shard_id)


def process_overlap_shard(schema_name, job_id, shard_id):
    from app.db.session import firm_session
    from app.services.stream_phase3 import _shard_index_entries
    from app.services.artifact_materialize import materialize_index_entries
    from app.services.job_control import load_extraction_checkpoint
    from app.services.disk_manifest import build_index_map
    from app.services.artifact_parse import parse_job_artifacts_for_paths
    if not shard_overlap_enabled():
        return {'status':'held','reason':'overlap_disabled'}
    token=uuid.uuid4().hex
    with firm_session(schema_name) as db:
        ensure_overlap_table(db)
        row=fetchone(db, """UPDATE forensic_shard_overlap SET state='running',
           attempts=attempts+1,updated_at=now(),heartbeat_at=now(),claim_token=:token,error=NULL
           WHERE job_id=:jid AND shard_id=:sid AND state IN ('pending','failed')
           RETURNING state""", {'jid':job_id,'sid':shard_id,'token':token})
        if not row:
            db.rollback()
            return {'status':'held','reason':'already_claimed'}
        db.commit()
    stopped=threading.Event()
    monitor=threading.Thread(target=_heartbeat,args=(schema_name,job_id,shard_id,token,stopped),daemon=True)
    monitor.start()
    try:
        with firm_session(schema_name) as db:
            cp=load_extraction_checkpoint(db,job_id) or {}
            entries=_shard_index_entries(cp, int(shard_id))
            if not entries:
                raise RuntimeError('Committed shard index not yet readable')
            job=fetchone(db, 'SELECT disk_source, stop_requested FROM jobs WHERE id=:jid', {'jid':job_id}) or {}
            if job.get('stop_requested'):
                raise RuntimeError('Processing stopped by examiner')
            manifest=job.get('disk_source') or {}
            if isinstance(manifest,str):
                import json
                manifest=json.loads(manifest)
            # Only committed shard contents may enter the preparse path.
            materialize_index_entries(db,job_id,entries,update_status=False,phase1_filter=False)
            paths=[str(x['path']) for x in entries if x.get('path')]
            idx=build_index_map(manifest,extra_entries=entries)
            completed=0
            with stage_context('shard_preparse'):
                for _ in range(max(1, (len(paths)+1999)//2000)+2):
                    result=parse_job_artifacts_for_paths(db,job_id,paths=paths,index_map=idx,
                        update_status=False,batch_limit=2000,forensic_only=False)
                    db.commit()
                    n=int(result.get('parsed') or 0)+int(result.get('skipped') or 0)+int(result.get('failed') or 0)
                    completed+=n
                    if n == 0:
                        break
            # Quality OCR candidates originate from committed artifacts only.
            # The authoritative OCR stage later reconciles late/failed items.
            try:
                from app.services.mobile_quality_ocr import route_forensic_quality_to_ocr
                quality = route_forensic_quality_to_ocr(db,job_id,limit=2000,dispatch=False)
                db.commit()
                if int((quality or {}).get('queued') or 0) > 0:
                    from app.tasks import ocr_drain_task
                    from app.services.forensic_serial_pipeline import queue_for_stage
                    ocr_drain_task.apply_async(args=(schema_name,job_id),queue=queue_for_stage('ocr'))
            except Exception:
                db.rollback()
                log.exception('Early shard OCR scheduling deferred to final OCR job=%s shard=%s',job_id,shard_id)
            execute(db, """UPDATE forensic_shard_overlap SET state='done',updated_at=now()
                WHERE job_id=:jid AND shard_id=:sid AND claim_token=:token""", {'jid':job_id,'sid':shard_id,'token':token})
            db.commit()
            return {'status':'done','shard_id':shard_id,'processed':completed}
    except Exception as exc:
        with firm_session(schema_name) as db:
            execute(db, """UPDATE forensic_shard_overlap SET state='failed',
                error=:error,updated_at=now() WHERE job_id=:jid AND shard_id=:sid AND claim_token=:token""",
                {'jid':job_id,'sid':shard_id,'token':token,'error':str(exc)[:500]})
            db.commit()
        log.exception('Shard preparse failed: job=%s shard=%s',job_id,shard_id)
        # Failed sidecars never imply evidence loss; authoritative parse will retry.
        return {'status':'failed','shard_id':shard_id,'error':str(exc)[:500]}

    finally:
        stopped.set()
        monitor.join(timeout=2)
