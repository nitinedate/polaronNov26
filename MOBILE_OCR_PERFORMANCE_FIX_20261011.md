# Mobile processing hotfix — 2026-10-11

## Verified root cause
The reported SQLAlchemy `bind parameter 'true'` failure is caused by a stale SQL expression containing a JSON literal with `:true`. The attached archive already uses `jsonb_build_object('early_ocr_dispatched', true)` at `backend/app/tasks.py`, which avoids the bind parser error. If the traceback persists, inspect the code **inside the running Celery container**: the server is likely running an older image or an alternate mounted task file.

## Changes in this package
- Default parser parallelism: six workers in Compose and `.env.example`; source-read semaphore default six. Existing `.env` values override these defaults, so review before deployment.
- Reduced OCR quality-triage self-rescheduling frequency from 0.2 s to 1.0 s when backlog remains; reduces queue churn, not a measured speed improvement.
- Per-stage elapsed/total wall time shown in the serial forensic progress cards, from server-supplied `started_at`/`completed_at` timestamps.
- Mobile host-acquisition default output directory is scoped to a sanitized job identifier, not a shared case folder. New job IDs require new job creation at the API/UI layer; importing multiple devices into an existing job is still subject to server-side acquisition rules.
- Existing JSON SQL fix and existing OCR quality bucket mechanisms retained.

## Confirm running image contains SQL fix
From the host running Docker Compose:

```powershell
docker compose exec -T worker python -c "import inspect, app.tasks; print(inspect.getsource(app.tasks.quality_ocr_triage_task))"
```

Use the actual Celery service name from `docker compose ps --services` if `worker` is not defined. Look for `jsonb_build_object('early_ocr_dispatched', true)`. Rebuild/recreate affected workers in a maintenance window; **do not terminate evidence writes without a verified checkpoint**.

## Follow-up integration gates
- Compare pending, claimed, completed, failed, retried, and committed database records every 5 minutes. The 99% display can represent writer finalization, rather than parser throughput.
- Confirm writer queue drains concurrently with extraction/parse using PostgreSQL `pg_stat_activity`, Celery task counts and DB table counters. No independent continuous DB-writer service is added by this patch.
- Confirm OCR enqueue/claim immediately after each committed quality-bucket item on real GPU hardware. Original image quality gate and final OCR reconciliation remain authoritative.
- Reconcile counts per `job_id`, `evidence_id`, and source acquisition, with an untouched second case and an explicit process-agent end-state assertion.
- Perform the 85 GB throughput benchmark on HDD and SSD separately. No 90-minute end-to-end SLA is claimed.

## Tests
Focused `backend/tests/test_early_ocr_overlap_20261010.py`: 3 passed. Python syntax compilation passed. Broad test suite collection blocked by an unrelated `ImportError` from `test_agent_duties.py` (`collect_action_votes`). React build, database integration and live GPU performance untested.
