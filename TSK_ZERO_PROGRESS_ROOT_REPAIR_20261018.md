# Polaron: Zero-progress TSK root filesystem walk (18 Oct 2026)

## Observed evidence
- The case's 42 E01 evidence segments registered and the image mounted successfully in the prior screenshots.
- At 05:16:19, 05:17:39, and 05:19:04 the progress agent recorded 90/180/270 seconds without a single file, directory or entry (`files=0, dirs=0, entries=0`).
- In `app/services/virtual_disk.py`, the old `Starting TSK filesystem walk` message immediately precedes `fs.open_dir(path='/')`. A zero-counter hang therefore lies at root-directory opening or in the first native TSK iteration (assuming the current isolated-walk setting is enabled). This is not evidence of stalled GPU, RAG, or PostgreSQL writes.
- The original isolated reader had a 420-second idle timeout and retried identical `path='/'` root opens; the monitoring agent was advisory, not the native-call owner.

## Code changes
1. Root open uses `fs.info.root_inum` by default (`FS_Info.open_dir(inode=...)`) to avoid TSK's potentially expensive root pathname resolution. When the first disposable reader fails, the **next** isolated reader tries `FS_Info.open_dir(path='/')`. If no root inode is reported, path mode is retained. The mode is never switched inside a hanging native call.
2. Explicit progress milestones: `reopening_evidence`, `root_open`, `root_first_entry`, `walking`, `failed`. Each milestone is emitted with a root method and, where available, root inode. The service additionally reports elapsed root-open time.
3. New `EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC=240` applies while no first file/directory/entry appears. The existing `EXTRACT_TSK_IDLE_TIMEOUT_SEC=420` remains for a walk that *has begun*. The parent terminates its owned native process, refuses its partial file list, then makes at most `EXTRACT_TSK_WALK_ATTEMPTS=2` total attempts. A stuck native child cannot be fixed by GPU parallelism or extra worker threads.
4. ProgressAgent displays the precise native phase and root method. It **does not** reset the useful-progress fingerprint just because a diagnostic milestone is reported, and it will not queue a duplicate job while an owner is alive.
5. No source evidence deletion, filter relaxation, schema change, image modification, OCR/RAG changes, or guessed completion state.

## Validation
- `PYTHONPATH=. pytest -q tests/test_tsk_walk_recovery_20261017.py`: **12 passed** in the available local Python test environment.
- Coverage includes inode-root traversal, path fallback after a reader crash, root idle timeout and owned-child termination, no partial inventory acceptance, unreadable entries, no duplicate acquisition, and exact phase diagnostics.
- `python -m compileall`: passed for modified services.
- Integration with actual E01 media, libewf/pytsk3, production Docker, Windows drive mounting and PostgreSQL has **not** been performed in this environment. The true cause might be an NTFS metadata defect, a slow HDD/USB/G: mount, or a native I/O call blocked below Python. If both root strategies fail, manual media/TSK diagnostics are required; do not claim extraction finished.

## Inspect the running system first (PowerShell in project root)
```powershell
docker compose ps worker-disk worker-progress worker-beat

docker compose logs --since 20m worker-disk worker-progress worker-beat |
  Select-String -Pattern 'TSK|root|reader|watchdog|timeout|Traceback|stall' -CaseSensitive:$false

docker compose exec -T worker-disk python -c "import os; print('isolated=',os.getenv('EXTRACT_TSK_ISOLATED_WALK','true')); print('root_idle=',os.getenv('EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC','240')); print('walk_idle=',os.getenv('EXTRACT_TSK_IDLE_TIMEOUT_SEC','420')); print('attempts=',os.getenv('EXTRACT_TSK_WALK_ATTEMPTS','2'))"

docker compose exec -T worker-disk python -c "import pytsk3, pyewf; print('TSK/EWF extensions available')"
```
If `EXTRACT_TSK_ISOLATED_WALK=false`, the watchdog cannot interrupt the in-process native call; configure `true` and restart safely. Review the entire 15-20 minute extraction log: the original 420-second watchdog could have already attempted a restart after the reported 270-second interval. Confirm whether the reader timed out, crashed, or changed stages. These commands read status and logs only.

## Safe deployment and resume
1. Make a backup of the source and production `.env`, and retain the original evidence, database/MinIO volumes and acquisition checkpoints.
2. Pause the case using the product UI, then wait for the `worker-disk` owner to finish/release its extraction lease. Do not overwrite active Python code or kill unrelated workers during live evidence writes. If a native I/O process will not stop (Docker reports uninterruptible I/O), correct the underlying mount/drive fault at a maintenance window instead of forcing duplicate extraction.
3. Copy the updated ZIP source over the backed-up project, keeping the production `.env` and evidence storage intact. In `.env` set:
```dotenv
EXTRACT_TSK_ISOLATED_WALK=true
EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC=240
EXTRACT_TSK_IDLE_TIMEOUT_SEC=420
EXTRACT_TSK_WALK_ATTEMPTS=2
PROGRESS_AGENT_EXTRACT_WARN_SECONDS=90
```
4. Validate the Compose config and rebuild the shared backend image used by `api`, `worker-disk` and `worker-progress`:
```powershell
docker compose config --quiet
docker compose build api
docker compose up -d --no-deps --force-recreate api worker-disk worker-progress worker-beat
```
In this repository `api` and `worker-disk` bind-mount `./backend:/app`, while `worker-progress` uses the shared `rag_new2-api` image. Building/recreating is therefore important to avoid mismatched agent logic.
5. Resume the existing case using its persisted checkpoint. Do **not** erase the case, source segments or extraction manifest.
6. Verify 1) root open milestone (with inode method), 2) first TSK entry, 3) increasing directory/file/entry counts, 4) complete plan committed only after the child exits successfully; verify recorded source limitations and hashes before accepting completeness.

## Escalation if zero entries persist on both methods
- Collect the child stderr, the `TSK native reader attempt N/N failed` message, E01 segment accessibility and Docker mount type (`/host/g`, SMB, USB, WSL, 9p), disk I/O latency and system/kernel error logs. Do not infer disk corruption from this symptom alone.
- Check whether mounting the 42 segments from a **local SSD** (read-only verified copy, with original hashes retained) changes root-open time. A Windows host drive exposed through Docker Desktop may introduce much more random-I/O latency than locally resident Linux volume storage.
- Compare pytsk3/libtsk versions and root inode/partition offset with a trusted forensic viewer. Examine alternate partitions explicitly if TSK chose a non-primary filesystem. No automated skip to a different filesystem or silent partial inventory is permitted.
- If the native reader remains stuck in uninterruptible kernel I/O, a Python watchdog cannot guarantee termination until the underlying I/O returns; resolve storage rather than spinning more workers.

This repair addresses the **zero-entry TSK root-open stall**. It does not certify a 30-45 minute end-to-end case-processing SLA; measure that separately on the actual E01 image.
