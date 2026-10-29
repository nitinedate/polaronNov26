# Polaron disk-only TSK root-open stall repair — 18 October 2026

## What the provided logs prove

At 08:37:38, Polaron began a parallel directory inventory of the 42-part E01 disk. At 08:41:43, it terminated the initial read-only reader after 240 seconds with no TSK entry returned from root-opening through `path=/`. It then restarted with `root=inode`. At 08:43:38, the progress agent reported 360 seconds, but that age covered BOTH attempts: attempt 2 had actually been running for approximately 115 seconds. Thus the global monitoring clock was misleading. The logs do not establish whether the source drive, Docker bind mount, pyewf, or TSK directory I/O is the underlying physical cause.

The current code used the PARALLEL directory walker on both attempts, merely switching inode/path root parameters. The prior successful job had opened a root using the serial inventory method, so a serial fallback was missing.

## Code repairs

1. Isolated reader execution now uses `parallel, preferred root` on attempt 1; `serial, preferred root` on attempt 2; and `serial, alternate root` on attempt 3. On `EXTRACT_TSK_ENUM_WORKERS=1`, it retains the original two-method serial sequence. `EXTRACT_TSK_WALK_ATTEMPTS` caps all attempts (maximum 3). Each retry owns a fresh isolated process and does not share a mutable EWF/TSK handle with other workers.
2. Every child attempt produces a start record containing attempt number, reader PID, chosen method, serial/parallel mode and an UTC start timestamp. These fields are carried on every child progress event. The progress agent now bases each root-stall warning's age on the newer of actual evidence progress and the attempt start; it does not report the previous attempt's cumulative idle age as the new reader's. It deliberately DOES NOT count restarting the reader as useful forensic work in the durable progress fingerprint or reset the job-wide acquisition retry budget.
3. For E01 images, when `EXTRACT_TSK_EWF_READ_TRACE_SEC` is set (default 20), the disposable reader emits rate-limited information about source byte offsets and sizes BEFORE calling into libewf. This helps distinguish a TSK metadata traversal from a native read blocked at a particular source offset. Diagnostic failures do not break extraction. These trace messages are not evidence progress and cannot suppress the watchdog.
4. The existing watchdog still terminates only its owned isolated reader after a bounded timeout and fails closed if the complete node inventory cannot be produced and counted. It does not delete source evidence or mark incomplete recovery as 100%.

## Immediate safe workaround — without a code change

If the live job still has zero files and the isolated child has exhausted its retries, use the application's Pause/Stop action and WAIT for `worker-disk` to confirm the extractor has exited; do not kill Docker during a shard write. Keep all existing PostgreSQL and MinIO volumes, the original E01 files and any completed extraction checkpoint. On the next controlled resume, set:

```dotenv
EXTRACT_TSK_ISOLATED_WALK=true
EXTRACT_TSK_ENUM_WORKERS=1
EXTRACT_TSK_ROOT_PREFERRED=path
EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC=240
EXTRACT_TSK_IDLE_TIMEOUT_SEC=420
EXTRACT_TSK_WALK_ATTEMPTS=2
```

This routes the next inventory through the previously successful serial/path strategy; it does NOT require replacing already successful downstream extraction logic. This is the preferred quick mitigation if the new parallel path is repeatedly failing. For the adaptive fallback release, use `EXTRACT_TSK_ENUM_WORKERS=2`, `EXTRACT_TSK_WALK_ATTEMPTS=3`, and `EXTRACT_TSK_ROOT_PREFERRED=path` for the known image. Only raise worker counts after root opening is stable.

## Controlled deployment

Merge this patch or use the enclosed full project after creating backups. The full archive is based on the last disk I/O-optimized Polaron project, not the old rag_new2 project. The provided Compose has `worker-disk`, `api`, and `worker-progress` using the same `rag_new2-api` image and bind-mounted `./backend:/app` source.

From the project directory in PowerShell, after the active extraction writer has exited:

```powershell
docker compose ps worker-disk worker-progress
docker compose build api
docker compose up -d --no-deps --force-recreate worker-disk worker-progress
```

If your startup uses `docker-compose.drives.generated.yml`, apply the SAME set of `-f` files as your startup script. Do not use `docker compose down -v`, wipe the database, delete evidence, or reinitialize MinIO.

Confirm the effective environment:

```powershell
docker compose exec -T worker-disk python -c "import os; print({k:os.getenv(k) for k in ['EXTRACT_TSK_ENUM_WORKERS','EXTRACT_TSK_ROOT_PREFERRED','EXTRACT_TSK_WALK_ATTEMPTS']})"
docker compose logs --since 15m worker-disk worker-progress | Select-String -Pattern 'TSK reader attempt|TSK root|EWF/TSK source read|filesystem walk|watchdog|Traceback'
docker stats --no-stream
```

## Performance and root-cause validation

If serial/root path ALSO blocks, the real bottleneck is beneath the directory-task scheduler. Next examine the physical storage of `G:` (USB HDD/SSD/network), Windows Docker bind-mount latency, sustained physical disk active time, 42-segment readability, EWF segment ordering and libewf/TSK source read offsets. The trace identifies the last requested logical image offset, NOT a failing physical drive sector.

The live 42-segment E01 image was not provided, so an actual end-to-end runtime, root-open speedup, filesystem integrity or 30–45 minute completion CANNOT be certified here. No missing metadata entries should be reclassified as successful evidence automatically.

## Validation performed locally

`PYTHONPATH=backend pytest -q backend/tests/test_tsk_parallel_inventory_20261018.py backend/tests/test_tsk_walk_recovery_20261017.py backend/tests/test_tsk_root_stall_recovery_20261018.py backend/tests/test_progress_agent_v54.py`

**27 focused tests passed**, covering serial fallback, alternate-root third attempt, distinct per-attempt metadata, checkpoint count validation, no duplicate parent job and recovery budget preservation. The unrelated `backend/tests/test_progress_agent.py::test_queue_inspection_is_cached_and_missing_worker_is_a_valid_dependency` cannot run in this validation container because `celery` is not installed. All other tests in that extended run passed. Synthetic tests do not replace performance testing against production evidence.
