# Polaron disk-only TSK parallel inventory — 18 October 2026

## Why the screen remains at 1%

The log/screenshot is **filesystem discovery**, not yet copying evidence to MinIO. After about 19m 44s it reports 299,338 file paths, 97,443 directories and 619,271 TSK entries. This is not an extracted-file count. The original `build_extracted_disk_to_minio` waits until `enumerate_all_files()` returns a complete plan before its existing parallel shard-copy stage starts. The 16 folder scanners only locate the E01 segment files; they do not walk NTFS in parallel. Hence raising `EXTRACT_DISK_WORKERS` alone does nothing for the current screen.

## Code changes — disk only

1. **New `backend/app/services/tsk_parallel_inventory.py`:** bounded directory-task scheduling using `ThreadPoolExecutor`. The root is opened once on the existing isolated-reader filesystem; each directory worker opens a completely independent libewf + TSK filesystem handle. NO pyewf handle is shared between worker threads. Concurrency is capped to 4; HDD/network is capped to 2. Two workers is the conservative default for a Docker Desktop drive mount or unknown source. A stream of completed directories replenishes the queue without waiting for the slowest directory.
2. **Deferred native directory opening:** the old serial walker calls `entry.as_directory()` as soon as it encounters every subdirectory. The new path records directory inode/path pairs, defers `open_dir(inode=...)` until a worker is ready, and falls back to `open_dir(path=...)` for a directory whose inode cannot be opened. This prevents retaining many native directory handles while processing an NTFS image with tens of thousands of directories.
3. **Integrity and boundedness:** global visited-inode/path tracking stops loops; distinct regular-file hardlink paths are still retained. Results are sorted by path and inode before writing the full inventory. Source limitations (unreadable directory, alias, missing metadata) remain explicit. A million pending directories is treated as a hard error rather than silently truncated. No incomplete file plan is accepted by the existing isolated-process watchdog.
4. **Progress:** report `inventory_workers`, files, directories, entries, pending and active directory tasks, missing metadata, and actual entries/directories-per-second. The progress agent can distinguish useful movement from a heartbeat. The native reader remains a child process; if its native calls stall, the existing parent watchdog can terminate that child only.
5. **Root open strategy:** `EXTRACT_TSK_ROOT_PREFERRED=path` avoids wasting 240 seconds trying root inode FIRST for the specific evidence which previously stalled in inode-open but succeeded with path-open. On failure the existing isolated parent switches to inode for attempt two. Default remains `inode` for other images.
6. **Existing extraction retained:** after complete inventory and OS-aware filtering, the pre-existing source-aware `extract_shard_v45` readers write tar.zst parts to MinIO using resumable shard checkpoints; DB writes remain single-owned. No OCR, RAG, mobile, or vulnerability processing changes.

## Validated locally

```
PYTHONPATH=backend pytest -q backend/tests/test_tsk_parallel_inventory_20261018.py
8 passed
```

Validated by independent synthetic tests: parallel directory scanning with two simultaneous workers, no duplicate directory aliases, hardlink path retention, accurate missing-metadata count, inode-to-path fallback, fail-closed worker setup, media concurrency cap and serial opt-out, default dispatcher, and configurable root retry. The test environment does not contain libewf/pytsk3, a live 42-part E01, PostgreSQL/MinIO workload, or Windows Docker host; therefore production completeness/latency is **not** certified.

Synthetic timing (240 fake directories, 3ms simulated I/O each): 2 readers **0.376 s**, 4 readers **0.194 s** (~1.94x at 4 vs 2); **this is scheduling only, NOT an observed forensic-E01 speedup**. For an HDD, 4 readers are deliberately capped to 2 because random seeks can reduce throughput.

## Live job — do NOT restart immediately

The on-screen job is still walking directories and likely has not saved an inventory checkpoint. Replacing the `worker-disk` container while this inventory runs can throw away 20+ minutes of uncommitted enumeration progress. Let it finish and start the parallel shard-copy stage unless it is genuinely unresponsive. The new code affects only a **fresh or controlled-resume enumeration** after containers reload source.

## Next controlled deployment (PowerShell, project root)

1. Back up project source, PostgreSQL, MinIO, `.env`, extraction checkpoints and evidence manifest. Retain `.env` and evidence paths from your existing installation; none is included in this package.
2. Pause scheduling new cases. Wait until the current E01 inventory has finished **and** the extract plan is persisted, or use the application's pause/stop control and wait for the owning worker to exit. Do not use `docker compose down -v` and do not terminate an active evidence-writing shard.
3. Merge changed disk-only files from this package, then set in the EXISTING production `.env`:

```dotenv
EXTRACT_TSK_ISOLATED_WALK=true
EXTRACT_TSK_ENUM_WORKERS=2
# For this SAME E01 case: inode root opening timed out, path opening worked.
EXTRACT_TSK_ROOT_PREFERRED=path
EXTRACT_TSK_IDLE_TIMEOUT_SEC=420
EXTRACT_TSK_ROOT_IDLE_TIMEOUT_SEC=240
EXTRACT_TSK_WALK_ATTEMPTS=2
# Set only if known; otherwise media detection is conservative.
# DISK_SOURCE_MEDIA=hdd
```

4. Recreate services only AFTER current shard/inventory owner finishes:

```powershell
docker compose build api
docker compose up -d --no-deps --force-recreate worker-disk
```

5. Validate code inside running worker, then watch progress:

```powershell
docker compose exec -T worker-disk python -c "import os; from app.services.tsk_parallel_inventory import inventory_readers; print('configured workers',os.environ.get('EXTRACT_TSK_ENUM_WORKERS'),'root',os.environ.get('EXTRACT_TSK_ROOT_PREFERRED'))"
docker compose logs -f worker-disk
```

The `worker-disk` service bind-mounts `./backend:/app` in the provided Compose, but process restart is still required to load newly imported modules.

## Production acceptance checklist

- Same 42-segment source, same OS/mount and disk (HDD/SSD), and reproducible settings.
- Measure root opening, inventory wall time, directory throughput, MinIO part writes, hash validation and final pipeline wall time **separately**.
- Compare identical source path+inode/size counts between serial and parallel inventory; investigate all missing metadata and unreadable directories, and report alias handling. Preserve chain of custody and original E01 source.
- Validate full extracted-file manifests, part hashes, SHA-256 for sampled recovered evidence and completeness checkpoints; check no duplicate part IDs or DB writers.
- Compare `EXTRACT_TSK_ENUM_WORKERS=1` against `=2`; only test `=4` on genuinely SSD/NVMe storage. If throughput gets worse, return to 1. Config changes require a new inventory attempt, not mid-stream modification.
- Do NOT claim the 30–45-minute end-to-end SLA is met until the same real E01 image completes the full disk forensic pipeline including parsing/OCR/RAG and coverage validation.

## Known limitations

This patch parallelizes **directory enumeration**, which was the current blocking phase. It does not begin MinIO shard uploads before the entire inventory/filter plan is validated and does not make the native NTFS root-directory opening parallel; one root must first be opened. A future release could add durable, incremental inventory+streaming shard planning, but that requires redesigning checkpoint/OS-filter/manifest semantics and must not be substituted without forensic parity tests.
