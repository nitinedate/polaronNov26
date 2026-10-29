"""Deleted/residual WhatsApp recovery across live and historical decrypted stores."""
from __future__ import annotations

from app.db.sql_helpers import execute, fetchone


def promote_historical_missing_candidates(db, job_id: str) -> dict:
    """Surface messages present in decrypted historical backups but absent now.

    This is deliberately a *candidate* signal, not proof of deletion.  It runs only
    when both a current allocated WhatsApp message set and historical backup rows
    exist, preventing an old backup alone from being mislabeled as deleted data.
    """
    current = int((fetchone(db, """SELECT count(*)::bigint AS n FROM mobile_normalized_artifacts
        WHERE job_id=:jid AND artifact_type='app_message' AND data->>'application'='whatsapp'
          AND state='allocated'""", {"jid": job_id}) or {}).get("n") or 0)
    historical = int((fetchone(db, """SELECT count(*)::bigint AS n FROM mobile_normalized_artifacts
        WHERE job_id=:jid AND artifact_type='app_message' AND data->>'application'='whatsapp'
          AND state='backup_historical'""", {"jid": job_id}) or {}).get("n") or 0)
    if not current or not historical:
        return {"current_messages": current, "historical_messages": historical, "candidates": 0}

    # Prefer WhatsApp's message/stanza id.  Older schemas without that id fall
    # back to a content identity that includes conversation, timestamp and body.
    identity = """COALESCE(NULLIF(data->>'message_id',''), md5(concat_ws('|',
        COALESCE(data->>'conversation_id',''), COALESCE(timestamp_utc::text,''),
        COALESCE(data->>'sender',''), COALESCE(data->>'body',''), COALESCE(data->>'media_name',''))))"""
    result = execute(db, f"""WITH current_ids AS (
        SELECT DISTINCT {identity} AS ident
        FROM mobile_normalized_artifacts
        WHERE job_id=:jid AND artifact_type='app_message' AND data->>'application'='whatsapp' AND state='allocated'
    ), missing AS (
        SELECT DISTINCT ON ({identity}) h.*,{identity} AS ident
        FROM mobile_normalized_artifacts h
        WHERE h.job_id=:jid AND h.artifact_type='app_message' AND h.data->>'application'='whatsapp'
          AND h.state='backup_historical'
          AND NOT EXISTS (SELECT 1 FROM current_ids c WHERE c.ident={identity})
        ORDER BY {identity}, h.timestamp_utc DESC NULLS LAST, h.artifact_id DESC
    )
    INSERT INTO mobile_normalized_artifacts
      (artifact_id,job_id,artifact_type,source_domain,timestamp_utc,state,ui_label,data,forensic,examiner_status,updated_at)
    SELECT 'MOB-HDIFF-'||substr(md5(artifact_id),1,24),job_id,'app_message','messaging_apps',timestamp_utc,
           'fragment','FRAGMENT',
           data || jsonb_build_object(
             'artifact_family','deleted_whatsapp',
             'is_deleted_candidate',true,
             'recovery_state','historical_missing_candidate',
             'candidate_reason','present_in_historical_backup_absent_from_current_database',
             'historical_source_artifact_id',artifact_id,
             'note','Candidate only: backup divergence can have causes other than deletion; examiner validation required.'),
           forensic || jsonb_build_object(
             'state','fragment','ui_label','FRAGMENT','recovery_source','historical_backup_diff',
             'examiner_status','pending_review','historical_source_artifact_id',artifact_id,
             'confidence',jsonb_build_object('label','LOW','score',0.45,
                 'validation',jsonb_build_array('historical_backup_present','absent_from_current_snapshot'),
                 'contradictions',jsonb_build_array('absence_does_not_prove_user_deletion'))),
           'pending_review',NOW()
    FROM missing
    ON CONFLICT (artifact_id) DO UPDATE SET data=EXCLUDED.data,forensic=EXCLUDED.forensic,state=EXCLUDED.state,
      ui_label=EXCLUDED.ui_label,updated_at=NOW()""", {"jid": job_id})
    try:
        candidates = int(getattr(result, "rowcount", 0) or 0)
    except Exception:
        candidates = 0
    return {"current_messages": current, "historical_messages": historical, "candidates": candidates}
