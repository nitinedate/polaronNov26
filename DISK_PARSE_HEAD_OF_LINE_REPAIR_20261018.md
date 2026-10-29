# Polaron disk native parsing: 4-minute quiet window / rolling parse improvement

## What was observed

A screenshot at 06:42:55 on 2026-10-18 shows `Native forensic parsing — 31,291 / 184,413 (8 workers)`. Four minutes with no new UI log is not proof that processing is stopped: source shards may still be streaming, expensive parsers may be running, and the log previously counted only `parse_status='parsed'` rows (not skipped/no-parser/failed).

## Code findings

- `backend/app/services/artifact_parse.py`: parallel small-file parsing sent work in fixed chunks (at least 48, normally `workers*12`) and waited for every parser in the chunk before submitting the next chunk. A single long-running parser creates a head-of-line barrier.
- The reader buffered an entire 384-MiB parse work batch before processing, regardless of source count. Thousands of tiny files could accumulate without any parse results being persisted.
- The stage log showed only `parsed/total`, while the stage also classified and finalized artifacts as `skipped`, `no_parser`, or `failed`.
- `backend/app/config.py` defaults to a disabled per-file parser timeout, and `.env.example` also has `PARSE_FILE_TIMEOUT_SEC=0`. The actual production value must be measured. A positive timeout does **not** safely kill a native parser in the existing code, because its ThreadPoolExecutor context manager waits for shutdown; do not rely on that setting as a hard kill switch.

## Changes

1. Rolling, bounded future submission. Complete each available future, persist its result on the single owning DB connection, and replenish the in-flight queue immediately. The maximum queue is `max(workers*4,16)`; unrelated files are no longer blocked at a fixed chunk boundary.
2. Bound the number of buffered source items with `PARSE_STREAM_MAX_FILES` (default `96`) in addition to the existing 384-MiB byte limit, so committed progress appears sooner.
3. Display `accounted / total` as well as the genuinely parsed, skipped/no-parser, and failed counts in the disk build log. Parsing claims in progress are not counted as completed.
4. After 45s with no completed parser future, record a diagnostic to worker and case logs and call progressAgent with `advanced=False`. No duplicate task is launched, no source is marked complete, and no parser is forcibly killed.
5. Preserve all file records, evidence source identifiers, parsing results, and status checkpoints. No change to extracted image bytes or raw E01 traversal.

## Tested

- 4 focused, dependency-free regression tests passed (`test_disk_parse_priority_v20261017.py` and new `test_disk_parse_rolling_window_20261018.py`).
- The 120-file regression test deliberately delays one file and confirms later files (beyond the old 48-file chunk barrier) complete while the slow parser is still running.
- Compile check passed for modified Python modules.
- A broader integration test could not collect in this runtime because `zstandard` is not installed. No claim is made about runtime on the live 42-segment E01 evidence, real PostgreSQL, or real MinIO.

## Production diagnostics (PowerShell, before deploying)

From the project's root (using the same `-f` Compose files used by your startup scripts, if applicable):

```powershell
docker compose logs --since 15m worker-parse worker-disk | Select-String -Pattern 'Native forensic parsing|Parse streaming shard|parse: streaming|timeout|Traceback|error|warning'
docker stats --no-stream
docker compose exec -T worker-parse python -c "from app.config import get_settings; s=get_settings(); print('parse_workers=',s.parse_workers,'file_timeout=',s.parse_file_timeout_sec,'commit_batch=',s.parse_db_commit_batch,'stream_max_files=',getattr(s,'parse_stream_max_files',None))"
```

For accurate queue-status counts, inspect the correct tenant schema in pgAdmin (replace the job UUID):

```sql
SELECT parse_status, count(*)
FROM job_artifacts
WHERE job_id = '<JOB_UUID>'
GROUP BY parse_status ORDER BY parse_status;

SELECT pid, state, wait_event_type, wait_event, now() - query_start AS elapsed,
       left(query, 120) AS sql_preview
FROM pg_stat_activity
WHERE datname = current_database() AND state <> 'idle'
ORDER BY query_start;
```

If CPU is active and 'parse_status' counts change, do not treat a four-minute log gap as an automatic deadlock. If all counters are stationary and worker CPU is near zero, diagnose blocked MinIO I/O/DB waits. If CPU remains fully utilized on one parser for too long, inspect that parser/source. Do not increase both Celery concurrency and per-task thread count blindly.

## Deployment

1. Back up the current source and database. Keep all evidence and extracted shards.
2. Safely pause this **case** in the UI, then verify its active parse writer has stopped and committed or released claims. Do not abruptly stop an active forensic write.
3. Replace the three modified files (or deploy the ZIP) while preserving the actual `.env` and data volumes. Optional `.env`: `PARSE_STREAM_MAX_FILES=96`.
4. Since the Compose workers bind-mount `./backend:/app`, restart the affected parse worker only after it has stopped its case safely. Example: `docker compose up -d --no-deps --force-recreate worker-parse` (use the same override files as in production).
5. Resume the existing case through its checkpoint mechanism, without recreating the job or deleting evidence.
6. Compare count-by-status, parser result counts, recovered evidence, source hashes, and provenance against the prior run before considering this production approved.

## Limitations

This improves head-of-line blocking, batching visibility, and logging; it cannot terminate a native C extension blocked forever in a Python thread. That requires separate process isolation and controlled IPC with crash-safe claim recovery. The change is not a guarantee of a 30–45-minute end-to-end processing SLA. GPU OCR acceleration has no direct effect on CPU native parsing.
