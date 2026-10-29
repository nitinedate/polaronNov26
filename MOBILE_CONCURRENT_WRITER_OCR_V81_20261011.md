# Polaron V81: concurrent normalized-artifact writer and repeatable OCR dispatch

## Implemented

- `backend/app/services/mobile_forensic/async_writer.py` is a bounded, per-job producer/consumer writer. Parsing adds immutable artifact batches while a dedicated thread commits each batch using a fresh firm-scoped SQLAlchemy session. Queue length defaults to six, applying backpressure. Failed commits are surfaced at the next checkpoint and stop further writes; they are not marked complete.
- `backend/app/services/mobile_forensic/pipeline.py` enables the writer during structured parsing and recovery, and waits for all committed batches at each authoritative progress checkpoint and before correlation. Without a firm-scoped schema, it falls back to existing same-session writes.
- `backend/app/tasks.py` rechecks *pending* OCR quality-bucket records and permits early GPU OCR dispatch every 30 seconds while parsing is running. Existing GPU job locking is kept. Uses `jsonb_build_object` (avoids SQLAlchemy's `:true` misbinding).
- `docker-compose.https.yml` parser transaction batch default matches the 250-record default used in the main Compose file.
- Four focused tests added in `backend/tests/test_mobile_async_writer_v81.py`.

## Staging settings

```
MOBILE_ASYNC_DB_WRITER=1
MOBILE_ARTIFACT_DB_BATCH=1000
MOBILE_FILE_CHECKPOINT=500
PARSE_WORKERS=6
PARSE_DB_COMMIT_BATCH=250
```

## Important safety and operational cautions

- This is a targeted performance patch, not evidence that the 85 GB / 90-minute goal has been achieved. Benchmark actual storage and GPU utilization.
- The async normalized-artifact writer is **not** a replacement for the separate `job_artifacts` native parser or Celery task broker. Native parse already batches commits during parsing; its backlog must be diagnosed by queue depth, retries, IO wait, and DB locks.
- OCR classification/routing still depends on supported image/video/document decoders; unrecognized proprietary formats cannot be guaranteed readable.
- Process-agent orchestration appears to gate terminal transitions via job state, but **no reproducible unexpected stop was established from the provided screenshot or traceback**. Inspect runtime `stop_requested`, task cancellation and supervisor logs before editing stop semantics.
- Use `docker compose` with the exact production files, volumes and environment; rebuild/recreate **all** Celery/API services on the same source revision to eliminate stale code. Never restart workers mid-transaction without a verified resume checkpoint.
- A Docker/Celery/PostgreSQL/GPU end-to-end run, lost-worker recovery drill, and full React build have **not** been executed in this environment. Stage against a cloned case, verify pre/post item counts and hashes, and preserve coverage exceptions before production rollout.
