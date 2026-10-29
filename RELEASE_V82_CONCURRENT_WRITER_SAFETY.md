# V82: committed-write checkpoints and stage-safety review

This update builds on the supplied V81 archive.

## Implemented
- Independent database session in the mobile artifact writer retained.
- Per-job thread naming, committed batch/artifact counters and failure latching.
- Progress checkpoint in mobile normalized parsing now waits for the writer commit barrier BEFORE updating the UI's `artifacts_written` count.
- A failed commit does not count as a successful write, and raises to the owning parser.
- Queued batches are drained on writer failure without representing success.
- Bounded queue retained for backpressure.
- Added tests for commit acknowledgements and rejected commits.
- Existing safe JSONB early OCR statement preserved.

## Process agent finding
The progress agent's retry-budget path sets the stage to `failed` and records an alert; it does not itself set `jobs.stop_requested = TRUE`. Do not conflate `blocked`/`failed` with an explicit user Stop. Investigate live `jobs.status`, `stop_requested`, stage errors and Celery task failures before changing cancellation semantics.

## Existing OCR overlap
The early-parse quality triage dispatch and per-shard OCR code from the uploaded project are retained, not independently proven on a live 85GB case. Verify the GPU worker queue, unique candidate claim and completion counts on staging.

## Unverified / no SLA
No live PostgreSQL/Celery, GPU utilization, hard-kill recovery, or 85GB/90min benchmark was available. An 85GB/90min SLA or comprehensive production completion cannot be certified. Crash/retry and multi-job isolation require deployment integration tests.

## Deployment
Back up case database and evidence. Do not replace workers during in-flight writes. Build/recreate worker images together; inspect loaded `quality_ocr_triage_task` source so stale workers do not run an old `:true` SQL literal. Run copied-evidence reconciliation before enabling shard overlap in production.
