"""Persisted producer barrier shared by final validation and report entry."""
from app.db.sql_helpers import fetchone


def assert_no_active_producers(db, job_id, *, exclude_stage=None):
    from app.services.forensic_serial_pipeline import StageWaiting
    try:
        from app.services.safe_parallel import reap_stale_sidecars
        reap_stale_sidecars(db)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if (fetchone(db, "SELECT to_regclass('pipeline_sidecar_runs') AS t") or {}).get('t'):
        row = fetchone(db, """SELECT count(*) AS c FROM pipeline_sidecar_runs
            WHERE job_id=:jid AND status IN ('queued','running')""", {'jid':job_id}) or {}
        if int(row.get('c') or 0):
            raise StageWaiting(f"Writing in: {row['c']} independent producers have not finished")
    row = fetchone(db, """SELECT count(*) AS c FROM pipeline_work_items w
        JOIN pipeline_stage_runs s ON s.id=w.stage_run_id
        WHERE s.job_id=:jid AND w.status IN ('pending','running')
        AND (:exclude IS NULL OR s.stage<>:exclude)""", {'jid':job_id,'exclude':exclude_stage}) or {}
    if int(row.get('c') or 0):
        raise StageWaiting(f"Writing in: {row['c']} work units have not finished")


def assert_report_ready(db, job_id):
    from app.services.forensic_serial_pipeline import StageWaiting, stage_rows, STAGES, TERMINAL
    rows = stage_rows(db, job_id)
    if [r['stage'] for r in rows] != [s[0] for s in STAGES] or any(r['status'] not in TERMINAL for r in rows):
        raise StageWaiting('Writing in: process agent has not sealed all evidence stages')
    assert_no_active_producers(db, job_id)
