# Process Agent immediate handoff update

## Scope
- `backend/app/services/progress_agent.py`: if the first eligible serial stage is `pending`, dispatch it immediately using the existing authoritative dispatcher. The dispatcher locks the job row, persists `queued`, and publishes a single Celery task. It preserves pause/stop and product ownership controls.
- `backend/app/services/forensic_serial_stages.py`: speculative OCR dispatch failure is logged as a warning; recovery remains independent and the serial OCR stage performs authoritative work and retry.
- `backend/tests/test_immediate_stage_handoff_static.py`: focused static regression checks.

## Limits
- This is not a general parallel DAG conversion. Only existing safe sidecars overlap stages. Global PostgreSQL stage exclusivity remains in place. Do not remove serial barriers until independent output tables, dependency states, and race-safe writers have end-to-end tests.
- Does not fix unavailable GPU/Celery consumers. Queued stages remain queued until a consumer claims them, and the existing watchdog inspects stale delivery.
- Ensure old case workers are checkpointed before deploying. Run integration tests with PostgreSQL, Celery, OCR worker and MinIO on the production-like environment.
- The general backend pytest suite may fail to collect without psycopg2 and runtime services; this is not a successful end-to-end test.
