"""Tenant-local durable full-traceback outbox. SMTP never changes job outcome."""
from __future__ import annotations
import hashlib
import logging
import os
import traceback
from app.db.sql_helpers import execute, fetchone

log = logging.getLogger(__name__)


def ensure_alert_schema(db):
    execute(db, """CREATE TABLE IF NOT EXISTS forensic_failure_alerts (
        id bigserial PRIMARY KEY, event_key text NOT NULL UNIQUE,
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        stage text NOT NULL, attempt text NOT NULL, recipient text NOT NULL,
        traceback text NOT NULL, status text NOT NULL DEFAULT 'pending',
        delivery_attempts integer NOT NULL DEFAULT 0, delivery_error text,
        next_attempt_at timestamptz NOT NULL DEFAULT NOW(),
        created_at timestamptz NOT NULL DEFAULT NOW(), sent_at timestamptz,
        updated_at timestamptz NOT NULL DEFAULT NOW())""")
    execute(db, """CREATE INDEX IF NOT EXISTS forensic_failure_alert_pending
        ON forensic_failure_alerts(next_attempt_at,id) WHERE status IN ('pending','sending')""")


def record_failure(db, job_id, stage, attempt, exc):
    """Call after rollback, in the transaction persisting the failed state."""
    ensure_alert_schema(db)
    trace = getattr(exc, 'remote_traceback', None) or ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    key = hashlib.sha256(f'{job_id}:{stage}:{attempt}'.encode()).hexdigest()
    execute(db, """INSERT INTO forensic_failure_alerts(event_key,job_id,stage,attempt,recipient,traceback)
        VALUES(:key,:jid,:stage,:attempt,:recipient,:trace) ON CONFLICT(event_key) DO NOTHING""",
        {'key':key,'jid':job_id,'stage':stage,'attempt':str(attempt),
         'recipient':os.getenv('FORENSIC_FAILURE_EMAIL','ndate1976@gmail.com'),'trace':trace})


def deliver_alerts(db, *, limit=1):
    """At-least-once delivery; stale claims retry after a crash, with bounded backoff."""
    from app.services.email_service import EmailService
    ensure_alert_schema(db)
    from app.config import get_settings
    # Alert delivery has its own switch; identity email may be disabled on mobile workers.
    enabled = os.getenv('FORENSIC_FAILURE_MAIL_ENABLED','true').lower() in {'1','true','yes'}
    if not enabled:
        return {'sent':0,'status':'disabled'}
    mail_settings = get_settings().model_copy(update={'mail_send_enabled':True})
    delivered = 0
    for _ in range(min(max(int(limit),1),3)):
        row = fetchone(db, """WITH claim AS (
            SELECT id FROM forensic_failure_alerts WHERE
            (status='pending' AND next_attempt_at<=NOW()) OR
            (status='sending' AND updated_at<NOW()-INTERVAL '10 minutes')
            ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE forensic_failure_alerts a SET status='sending',updated_at=NOW(),
              delivery_attempts=delivery_attempts+1 FROM claim WHERE a.id=claim.id RETURNING a.*""")
        db.commit()
        if not row:
            break
        try:
            accepted = EmailService(mail_settings).send(row['recipient'],
                f"Forensic process failed: {row['stage']} / {row['job_id']}",
                f"Job: {row['job_id']}\nStage: {row['stage']}\nAttempt: {row['attempt']}\n\n{row['traceback']}")
            if not accepted:
                raise RuntimeError('Email sending is disabled')
        except Exception as exc:
            execute(db, """UPDATE forensic_failure_alerts SET status='pending',delivery_error=:err,
                next_attempt_at=NOW()+make_interval(secs=>CAST(:delay AS double precision)),updated_at=NOW()
                WHERE id=:id""", {'id':row['id'],'err':type(exc).__name__,
                    'delay':min(3600,60*2**min(int(row['delivery_attempts']),6))})
        else:
            execute(db, """UPDATE forensic_failure_alerts SET status='sent',sent_at=NOW(),
                updated_at=NOW(),delivery_error=NULL WHERE id=:id""", {'id':row['id']})
            delivered += 1
        db.commit()
    return {'sent':delivered}


def capture_task_failure(sender=None, task_id=None, exception=None, args=None, einfo=None, **kwargs):
    """Catch escaping acquisition/OCR/helper failures in Disk/Mobile tasks."""
    import uuid
    from app.db.session import firm_session
    from app.services.forensic_serial_pipeline import StageWaiting
    if isinstance(exception,StageWaiting):
        return
    values = args or []
    if len(values)<2 or not isinstance(values[0],str) or exception is None:
        return
    try:
        jid = str(uuid.UUID(str(values[1])))
    except (ValueError,TypeError,AttributeError):
        return
    try:
        with firm_session(values[0]) as db:
            if not fetchone(db,'SELECT id FROM jobs WHERE id=:jid',{'jid':jid}):
                return
            ensure_alert_schema(db)
            if not fetchone(db,'SELECT id FROM forensic_failure_alerts WHERE job_id=:jid AND attempt=:tid',
                {'jid':jid,'tid':str(task_id)}):
                if einfo and getattr(einfo,'traceback',None):
                    wrapped=RuntimeError(str(exception))
                    wrapped.remote_traceback=str(einfo.traceback)
                else:
                    wrapped=exception
                record_failure(db,jid,getattr(sender,'name','task'),task_id,wrapped)
            db.commit()
    except Exception:
        log.exception('Could not persist forensic failure alert for task %s',task_id)
