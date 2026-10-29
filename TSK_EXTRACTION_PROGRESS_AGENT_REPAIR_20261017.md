# Polaron — E01 / TSK extraction stall and progressAgent repair (2026-10-17)

## Observation versus conclusion

Screenshots show 42 registered E01 parts at 22:53, mounted filesystem at 22:53:51,
then `Starting TSK filesystem walk...`. At ~3m42s, extraction reports 1% and its
file total is still unknown. The screenshots cannot prove an OS-level native-reader
deadlock. The source shows this is a previously unbounded C-extension operation,
and artificial heartbeats can conceal lack of meaningful progress.

## Root causes found in repository

- `backend/app/services/virtual_disk.py:enumerate_all_files`: recursively walked
  TSK directories, no visited-inode protection, and swallowed nested directory
  errors. Regular-file count could remain zero while metadata traversal was active.
- `backend/app/services/disk_build_log.py:disk_log_heartbeat`: touches
  `jobs.updated_at` every 15 seconds. This is liveness, *not* progress.
- `backend/app/services/progress_agent.py:_monitor_acquisition`: previously
  returned `progressing` on fresh `jobs.updated_at`, skipping a useful-progress
  diagnostic; extraction had no persisted fingerprint analysis.
- `backend/app/services/pipeline_orchestrator.py` only showed file counts during
  enumeration. Directory/entry activity could not be seen on the card.

## Changes

1. Replace recursive TSK walk with bounded iterative traversal, directory-inode
   loop protection and explicit unreadable-entry/alias counters. Emit file,
   directory, entry and last-path telemetry. Never swallow root open errors.
2. Run E01/RAW TSK enumeration in a *separate, disposable native-reader process*,
   using `python -m app.services.tsk_walk_isolated`. It reopens the evidence read-
   only, streams progress, and writes a temporary node plan. The parent validates
   that the entire node plan matches the worker's declared count before accepting
   anything. The filesystem enumeration makes no MinIO writes.
3. If the subprocess does not advance useful file/directory/entry counters for
   420s (configurable), only that owned child is terminated. A second clean
   read-only attempt is made (configurable), then extraction fails visibly with
   a source limitation/failure notification rather than looping indefinitely.
   Examiner pause cancels the reader, preserving the existing checkpoint.
4. `progressAgent` fingerprints useful acquisition work separately from job
   heartbeats and records clear extract-stage diagnostics in the already existing
   `pipeline_progress_events`. The agent diagnoses source I/O, TSK walk and
   MinIO-copy stalls, and only considers requeue when Celery inspection confirms
   the original task absent **and** its extraction lease is absent. Celery
   uncertainty or an active lease is a safe wait, not a duplicate delivery.
   Checkpoint redispatch has a 120s grace and at most 3 attempts per unchanged
   useful-progress fingerprint.
5. UI extraction stage description now shows directory and entry counts. If
   aliases or unreadable entries were skipped, `filter_stats` and logs preserve
   that source coverage limitation. `progressAgent` events already display in
   the existing UI panel; no new competing agent or autonomous LLM is added.
6. GPU OCR/RAG workers remain unchanged. They are not the bottleneck during
   metadata enumeration; aggressively raising GPU concurrency would not help.

## Configuration (.env)

Defaults are coded into the modified modules and documented in `.env.example`:

```dotenv
EXTRACT_TSK_ISOLATED_WALK=true
EXTRACT_TSK_IDLE_TIMEOUT_SEC=420
EXTRACT_TSK_WALK_ATTEMPTS=2
PROGRESS_AGENT_EXTRACT_WARN_SECONDS=90
PROGRESS_AGENT_INTERVAL_SECONDS=15
```

Avoid excessively short I/O timeouts on mechanically slow disks or damaged media;
they can convert slow readable metadata into repeated failures. The 420-second
idle timer resets on *useful counters*, not the periodic database heartbeat.

## Safe deployment (Windows PowerShell, project root)

1. Keep a complete backup of the current project, `.env`, persistent database,
   storage manifests and evidence. Do **not** overwrite the active application's
   directory while a filesystem walk is running. Pause that case with the UI
   (stop_requested) and wait for its owner to exit; if pause cannot be honored
   due to a stuck old native call, arrange a maintenance window and stop only the
   `worker-disk` service before replacement, preserving the case checkpoint.
2. Copy changed files into the project (or apply the provided patch). Preserve
   production `.env`, evidence and PostgreSQL/MinIO volumes.
3. Confirm services and file mounts:

   ```powershell
   docker compose ps worker-disk worker-progress worker-beat api
   docker compose exec -T worker-disk python -m compileall -q app/services/virtual_disk.py app/services/tsk_walk_isolated.py app/services/extracted_disk.py app/services/progress_agent.py
   docker compose exec -T worker-disk python -c "import pytsk3, pyewf; print('Native E01 readers available')"
   ```
4. When the active worker has exited, recreate the affected code consumers:

   ```powershell
   docker compose up -d --no-deps --force-recreate worker-disk worker-progress worker-beat api
   ```

   If the backend code is packaged into an image rather than the Compose bind
   mount, rebuild the affected image before recreating services.
5. Verify progressAgent is enabled, its `worker-progress` worker consumes
   `disk-progress`, and `worker-beat` schedules its task. Run the focused tests
   inside the backend test environment when pytest is installed:

   ```powershell
   docker compose exec -T worker-disk python -m pytest -q tests/test_tsk_walk_recovery_20261017.py tests/test_progress_agent_v54.py
   ```
6. Resume the case via the job UI. Do **not** clear the checkpoint, delete
   evidence, delete shard indexes or re-register 42 segments. Check the
   `progressAgent` panel: `investigate` = a live owner slowed/blocked;
   `recover` = abandoned worker/lease, bounded checkpoint redelivery;
   `blocked` = exhausted attempts or source requires examiner correction.

### Diagnostic commands

```powershell
docker compose logs --since 20m worker-disk worker-progress worker-beat | Select-String -Pattern 'TSK|progressAgent|extract|traceback|timeout|stale' -CaseSensitive:$false
docker compose exec -T worker-disk python -c "import os; print('Isolation:',os.getenv('EXTRACT_TSK_ISOLATED_WALK','true'))"
```

The exact case stage can also be inspected in the `progressAgent` and Extraction
Log panels; disk worker logs are especially important for native TSK exceptions.

## Regression results in the limited test environment

- 14 targeted tests PASSED (TSK directory cycle protection, error disclosure,
  complete-plan count validation, single-process retry, useful-work fingerprint,
  no duplicate when Celery owner active, bounded recovery and previous parsing
  regressions). Python syntax compilation PASSED.
- A broader suite was attempted. Some unmodified integration modules could
  not be collected without `zstandard` (not installed here), and earlier tests
  required Celery and stale frontend banner text. These are **not** proof of a
  fully green regression suite; run project CI in the Docker dependency image.
- The actual 42-segment E01, PostgreSQL, MinIO, CPU/drive telemetry and GPU are
  not available in this environment. Therefore **no 30-45 minute full-case SLA
  or byte-for-byte artifact equivalence has been measured or certified**.

## Forensic acceptance checklist

- Preserve original 42 segment names, sizes, acquisition hashes and source path.
- Measure total TSK walk time, files/directories/entries scanned, unreadable
  entries and repeated directory aliases. Document any source limitations.
- Validate the extracted plan counts, shard completion and all job checkpoints.
- Compare previous versus repaired source SHA-256s, artifact counts, filenames,
  inode/source mappings, deleted recovery results, image/video and emails.
- Validate no duplicate jobs/processes or repeated MinIO parts on resume.
- Time extraction + registration + native parse + OCR + RAG + final report,
  including correct GPU usage for OCR/embeddings.

This patch improves progress visibility, bounded recovery and native read safety,
not the physical seek rate of an E01 image on slow storage. A 30-45 minute total
must be demonstrated on the actual evidence and hardware before setting the SLA.
