"""V1.10.3: explain why a forensic pipeline stage stopped.

Prints, for one job (or the most recent jobs with a waiting/failed stage):
the stage rows, the job status, progressAgent decisions and the build-log lines
about stops, pauses, signals and directories, newest first.

Run inside the api or worker container:
    python scripts/diagnose_stage_cancel.py [JOB_ID]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import firm_session  # noqa: E402
from app.db.sql_helpers import fetchall, fetchone  # noqa: E402

KEYWORDS = ("stage", "pause", "stop", "cancel", "interrupt", "sigterm", "thermal", "directory",
            "progressagent", "budget", "restart", "resum")


def _schemas() -> list[str]:
    with firm_session("public") as db:
        rows = fetchall(db, """SELECT DISTINCT table_schema AS s FROM information_schema.tables
                                WHERE table_name='pipeline_stage_runs'""")
    return [str(r["s"]) for r in rows]


def _when(row: dict) -> str:
    for key in ("created_at", "ts", "updated_at", "logged_at"):
        if row.get(key):
            return str(row[key])[:19]
    return "?"


def report(schema: str, job_id: str) -> None:
    with firm_session(schema) as db:
        job = fetchone(db, "SELECT id,status,stop_requested,error,updated_at FROM jobs WHERE id=CAST(:j AS uuid)",
                       {"j": job_id})
        if not job:
            return
        print(f"\n=== {schema} job {job_id} status={job['status']} stop_requested={job['stop_requested']}")
        print(f"    job error: {job.get('error')}")
        for s in fetchall(db, """SELECT stage,status,attempt,recovery_dispatches,started_at,heartbeat_at,
                                        progress_at,cancel_requested_at,completed_items,total_items,error
                                   FROM pipeline_stage_runs WHERE job_id=CAST(:j AS uuid)
                                   ORDER BY sequence_no""", {"j": job_id}):
            if s["status"] in {"done", "skipped", "pending"} and not s.get("error"):
                continue
            print(f"  stage {s['stage']:<12} {s['status']:<8} attempt={s['attempt']} "
                  f"recoveries={s['recovery_dispatches']} items={s['completed_items']}/{s['total_items']}")
            print(f"      started={s['started_at']} heartbeat={s['heartbeat_at']} progress={s['progress_at']} "
                  f"cancel_requested={s['cancel_requested_at']}")
            if s.get("error"):
                print(f"      error: {str(s['error'])[:300]}")
        if fetchone(db, "SELECT to_regclass('pipeline_progress_events') AS t")["t"]:
            print("  progressAgent decisions (newest first):")
            for e in fetchall(db, """SELECT created_at,stage,decision,reason FROM pipeline_progress_events
                                      WHERE job_id=CAST(:j AS uuid) ORDER BY id DESC LIMIT 25""", {"j": job_id}):
                print(f"    {str(e['created_at'])[:19]} {e['stage'] or '-':<10} {e['decision']:<16} {str(e['reason'])[:150]}")
        print("  build log lines about stops / pauses / signals / directories (newest first):")
        shown = 0
        for r in fetchall(db, "SELECT * FROM disk_build_logs WHERE job_id=CAST(:j AS uuid) ORDER BY id DESC LIMIT 3000",
                          {"j": job_id}):
            msg = str(r.get("message") or "")
            if any(k in msg.lower() for k in KEYWORDS):
                print(f"    {_when(r)} [{r.get('stage') or '-'}] {r.get('level') or ''} {msg[:200]}")
                shown += 1
                if shown >= 60:
                    break


def main() -> None:
    wanted = sys.argv[1] if len(sys.argv) > 1 else None
    for schema in _schemas():
        if wanted:
            report(schema, wanted)
            continue
        with firm_session(schema) as db:
            rows = fetchall(db, """SELECT DISTINCT job_id, max(updated_at) AS u FROM pipeline_stage_runs
                                    WHERE status IN ('waiting','failed') GROUP BY job_id ORDER BY u DESC LIMIT 3""")
        for row in rows:
            report(schema, str(row["job_id"]))


if __name__ == "__main__":
    main()
