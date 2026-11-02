# Multi-directory extraction: stalled owner / duplicate resume repair

## Scope

Corrects a race observed on 2026-11-02 with a single job containing two forensic EWF image sources (112 + 31 segments). The UI showed `extraction has no active owner`, followed by `Extract lock held — ignoring duplicate resume` and repeated `Registration complete — 31 segment(s)` entries. No evidence file or prior MinIO snapshot should be deleted to apply this repair.

## Cause found in the reviewed source

1. `host_evidence.register_segments()` unconditionally updated `jobs.status='registered'` even when a worker had already moved the same job to `processing`/`building_disk`. In addition, registration progress could rewind `pipeline_progress` to the Get Segments stage. This produced misleading `no active owner` recommendations and duplicate dispatches.
2. The registered-job supervisor published Celery work *before* updating the database status to `processing`. Concurrent supervisors could both send a task. The second task would observe the first worker's Redis lock and report `already running` rather than advancing the pipeline.
3. `extract_celery_work_active()` counted reserved tasks as live extraction owners. A queued task is not proof that a worker currently owns a filesystem reader. Furthermore, a resumed task could count *itself* as the prior active owner while checking a stale Redis lock.
4. A repeated registration re-ran the listing path and committed progress for already-registered segments, creating unnecessary expensive API work and additional logs.

## Changes

- Re-registration of an identical already-committed folder returns idempotently without rescanning or rehashing its E01/E02 fragments. The returned file registration is preserved and other image directories remain registered.
- New registrations preserve statuses beyond registration (`processing`, `building_disk`, indexing, completed). Active extraction and downstream progress cannot be rewound by Get Segments.
- The registered-state supervisor uses a single atomic PostgreSQL `UPDATE ... WHERE status='registered' RETURNING id` claim, commits the claim, and only then submits a Celery task. A failure to publish restores `registered` where safe.
- Celery inspection now checks active tasks, *not* reserved tasks, and can exclude the current task ID. Missing worker inspection results are treated as unknown rather than as proof of worker death.
- The Resume endpoint repairs a legacy `registered` status if Redis/Celery evidence shows a live extractor, without issuing another task.
- The existing per-job Redis lease, CPU-heavy exclusive slot, heartbeat refresh, stale-lease reclamation checks and extraction checkpoints remain intact. Locks are not blindly cleared.

## Verify the current job (do not force-clear Redis locks)

From the Polaron project root on the Docker host:

```sh
docker compose ps api worker-disk worker-progress
docker compose logs --tail=120 worker-disk worker-progress api
docker compose exec worker-disk celery -A app.celery_app.celery inspect active
```

Look for any active `build_extracted_disk_task` for the affected UUID. If an active task is extracting data, **do not restart its container**. Back up the database and keep the job's saved MinIO objects. If no active worker is copying data and the job has been stalled, deploy the patched code and perform a planned restart of these services, for example:

```sh
docker compose up -d --no-deps --build api
docker compose up -d --no-deps --force-recreate worker-disk worker-progress
```

The API/worker image and code are mounted from `./backend`; a restart is required for worker Python imports to reload. Use your deployment's existing `docker compose -f ...` flags if it runs multiple override files. **Do not stop PostgreSQL, Redis, or MinIO to repair this issue.** Avoid restarting during an active E01 read; if you must restart, keep checkpoints and allow the Redis lease watchdog to reclaim a stale lock before resuming.

Open the existing job, refresh, and click **Resume once** if automatic recovery has not queued it. Do not re-create the job or re-register its evidence directories. Retained source directories are processed separately and all saved artifacts are combined before Phase 3/RAG.

Expected new events include:

```
Registered evidence queued exactly once for extraction on disk-build task=<uuid>
Opening N segment(s) and extracting complete filesystem to MinIO
Directory 1 of 2: extracting only <source-1> (112 segment file(s)) ...
Directory 1 extraction saved ... waiting for remaining source directories
Directory 2 of 2: previous extraction is saved. Switching to source directory: <source-2> ...
Directory 2 of 2 saved ... Combined index now contains ...
Combined 2 images. Extraction of every image is saved.
All evidence directories saved and registered. Starting shared parse, OCR, artifact inventory, RAG, graph, and validation on the combined index.
```

The first line may not appear when a task was already queued or is recovering. The exact source order follows the `disk_source.evidence_folders` list. Each image has its own namespace, even if a later image contains identical filenames/content. A single-directory job continues down the original path.

## Verification limitations

The regression tests include extraction-lock ownership and repeated-register behavior. They run with mocks and do not prove that this specific job currently has a healthy Celery worker or an accessible EWF filesystem. This environment has no production PostgreSQL/Redis/MinIO/Windows E01 mount, so end-to-end recovery must be verified on the Docker host. The complete legacy test suite also has unrelated test-collection blockers (including missing `zstandard` and outdated imports of `_progress_pct`, `_canon`, `_find_exact_section_item`).

## Tests

From `backend`:

```sh
python -m pytest -q tests/test_extraction_owner_recovery_20261102.py tests/test_job_locks_stale.py tests/test_multi_directory_identity_20261102.py tests/test_multi_directory_extract_20261023.py tests/test_v68_resume_rag_ocr_performance.py tests/test_v67_resume_parallel_leakage.py
```

Expected: 49 passing tests (as run in this delivery environment).
