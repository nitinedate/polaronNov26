# Committed-shard extraction / parsing overlap (experimental)

This patch adds a bounded per-shard pre-parser to the existing authoritative serial workflow. It **does not certify full production concurrency**, which still requires live database/Celery integration testing.

## Enable only in a staging deployment

Set `FORENSIC_STREAM_SHARD_OVERLAP=true` on the extraction worker and the `disk-parse` Celery worker. Default remains `false`. Restart those services to apply the flag. Ensure the worker importing `app.tasks` can reach the tenant PostgreSQL schema, MinIO, and the same evidence source.

For each fully committed extraction shard: persist the index/checkpoint, create the `forensic_shard_overlap` row, and dispatch a separate Celery task. The task materializes the shard and processes pending parser rows using its own session. Final materialization refuses to proceed while these tasks are pending/running. Failures are recorded as `failed` for authoritative reprocessing. The existing extraction-complete barrier and final parser and OCR stages remain in place.

## Known release blockers

1. Full extraction / parsing / OCR overlap is **not complete**: OCR presently overlaps native parse for eligible items, but extraction-time OCR is not automatically dispatched by this sidecar.
2. Celery lost-publish and worker-kill recovery of `pending/running` `forensic_shard_overlap` rows needs an operational watchdog, otherwise the final barrier can wait indefinitely. Do not enable this in production before testing worker loss and replay.
3. Validate provenance, exact counts, parser idempotency, stop/resume, extraction restore, mobile and disk sources, and decrypt-key paths with real PostgreSQL and MinIO.
4. The client-upload completeness gate and the authoritative 13-stage chain must remain enforced; no source coverage should be claimed from partial acquisition.
5. The 85 GB / 90-minute performance target has **not** been benchmarked or established.

## Staging check

Run `PYTHONPATH=backend pytest -q backend/tests/test_shard_overlap_20261010.py` from the project root after dependencies are installed. Test killing the Celery worker mid-shard, job stop/resume, and corrupted index recovery. Only then consider enabling on live evidence.
