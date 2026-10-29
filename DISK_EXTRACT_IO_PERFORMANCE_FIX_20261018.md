# Polaron disk-only E01 extraction I/O repair — 18 October 2026

## Evidence / scope

The user's screen shows 72,480/184,413 selected files packed in ~22 min, 11.5 GB of *source bytes* processed, and a calculated rate of 13.3 MiB/s. The target in the code is `EXTRACT_TARGET_GB=60`, `EXTRACT_TARGET_MINUTES=35` (~29.3 MiB/s). The actual 42-part E01, MinIO database, source drive, and production metrics were not supplied, so root cause and SLA are not verified on the host. The source drive appears under G: in the UI; do not assume it is rotational without inspecting the Windows hardware.

**Source/coverage warning:** 45,607 TSK entries lacked metadata, 0 unreadable directories, 0 repeated-directory aliases; `forensic_mode_selective_include` selected 184,413 items and skipped 205,616. Review what those entries and exclusions represent; fast selective extraction cannot be described as exhaustive evidence recovery.

## Confirmed code defects

1. `docker-compose.yml` already mounted `${EXTRACT_SCRATCH_HOST_DIR:-.../scratch}:/scratch` for `worker-disk`, but did NOT provide `EXTRACT_SCRATCH_DIR=/scratch`. `extract_shard_v45.py` reads that variable and otherwise passes `dir=None` to `tempfile.mkstemp`, so full compressed TAR shard files went to the global `TMPDIR=/app/data/tmp`, usually the backup bind mount. This increases contention if backup or original E01 are on slow/shared media.
2. The stage's `progress.record_extracted()` is called *before* the shard uploads its compressed file to MinIO. Until upload and checkpoint commit, those files are only staged locally. The historical progress UI labeled the source-byte count **Transferred**, which was inaccurate. Uncommitted shard data must not be treated as durable.
3. Each ordinary E01 file was read to a `SpooledTemporaryFile` and then copied a second time into the compressed TAR shard. For known-size regular files it is possible to avoid that extra spool, provided a size mismatch fails the *entire uncommitted shard* and never writes an invalid tar member to MinIO.
4. A combined MiB/s and ETA cannot separate E01 decompression/random-seek wait, Python/TAR/compression, temporary storage, and MinIO upload latency.

## Repair shipped (disk extraction + truthful UI)

- `docker-compose.yml`: set `EXTRACT_SCRATCH_DIR: /scratch` only for `worker-disk`. Use `EXTRACT_SCRATCH_HOST_DIR` in the host `.env` to locate dedicated scratch on fast SSD/NVMe. Verify `/scratch` is writable and has capacity for all in-flight shards before starting extraction. The patch does not touch E01 evidence and retains complete-shard checkpoints.
- `extract_shard_v45.py`: optional `EXTRACT_DIRECT_TAR_STREAM=true` for **known-size E01/raw inode files only**. Stream once into TAR, count bytes, optionally compute SHA-256 during that read, reject short/oversize records without uploading the part; unknown-size and other file modes use the original spool. This is OFF by default until a representative production parity benchmark is run. Native/slow disk reads remain under the existing semaphore. No increase in read workers is imposed.
- Shard completion emits source/spool time, TAR time, upload time, count of directly streamed files, and total shard elapsed time. This split identifies which subsystem is actually slow; the source/spool and TAR times for direct-streaming are approximate partitions of a combined stream.
- `extracted_disk.py`: expose `files_uploaded`/`bytes_uploaded` only once the MinIO upload and database checkpoint commit succeed. Preserve existing packed-file counters for legacy stages, but label them as **packing/source bytes**, and mark ETA as packing-only.
- React progress banner and log viewer: show packed source bytes separately from uploaded-and-checkpointed bytes; eliminate misleading **Transferred** label on packing progress. Backward compatibility with older logs retained.
- Existing parallel TSK inventory and disk workers remain intact. Database writes stay with the owning thread. No updates to mobile, vulnerability scanner, or RAG code.

## Test evidence

```
PYTHONPATH=backend python -m pytest -q backend/tests/test_extract_direct_tar_20261018.py
8 passed
```

Includes the actual `shard_worker_v45` function with synthetic E01 reads and a simulated MinIO writer: validates byte-for-byte TAR extraction, SHA-256, bounded-known-length enforcement, and fail-closed behavior on mismatched size. Covers staged versus uploaded counters. `py_compile` passes.

A small-file **Python-only** TAR benchmark on this container processed 2,500 x 4 KiB files: spool ~0.057 s vs direct ~0.054 s (run noise and CPU cache may dominate). **Do not treat this as a projected E01 throughput gain.** The production E01, EWF/TSK library, real MinIO, and React dependency tree were unavailable. No full end-to-end production test or React build was possible.

## Immediate production checks — do NOT stop the active 39% extraction

From PowerShell in the exact Compose root (append your normal `-f docker-compose.drives.generated.yml` if that is how the stack starts):

```powershell
docker compose logs --since 30m worker-disk |
  Select-String -Pattern 'Extract I/O plan|Shard .* started|Shard .* complete|processed #|failed|read skips|SLA'
docker stats --no-stream
docker compose exec -T worker-disk sh -lc 'printf "scratch_var=%s TMPDIR=%s\n" "$EXTRACT_SCRATCH_DIR" "$TMPDIR"; df -h /scratch /app/data/tmp; test -w /scratch && echo scratch_writable || echo scratch_not_writable'
Get-Partition -DriveLetter G | Get-Disk | Select-Object Number,FriendlyName,BusType,MediaType
```

If the source is a USB/HDD and MinIO/scratch are on the same physical disk, the highest-impact intervention may be moving scratch to NVMe and/or working from a verified read-only evidence copy on a faster source (hash-match original). Increasing reader count against HDD can **reduce** throughput due to seeks. If source is NVMe, test 2 vs 4 vs 8 readers with the same case data; run only one extraction job during the benchmark.

## Controlled deployment after the current shard is safely checkpointed

1. Back up the existing source, `.env`, PostgreSQL and MinIO data; do not modify the original E01 files. Ensure the current shard is uploaded and its checkpoint persisted. If using the application's pause control, wait for the worker to acknowledge it. Do NOT force-restart a writer mid-shard.
2. Merge the code changes, retaining production `.env`. Pick a **fast, capacious** scratch host path, for example `D:/PolaronScratch` **only if D: is a fast SSD with sufficient free capacity**. Add to `.env`:

```dotenv
EXTRACT_SCRATCH_HOST_DIR=D:/PolaronScratch
EXTRACT_DIRECT_TAR_STREAM=false
# Set DISK_SOURCE_MEDIA only after checking the actual host disk: hdd / ssd / nvme
# DISK_SOURCE_MEDIA=hdd
```

3. Rebuild/recreate affected services after the case is safely paused or finished. The Compose `worker-disk` environment now maps its scratch directory to `/scratch`. With the UI changes, rebuild the frontend too. Use the same Compose override file(s) as normal startup.

```powershell
docker compose config --quiet
docker compose build api frontend
docker compose up -d --no-deps --force-recreate worker-disk frontend
```

4. Confirm `docker compose exec -T worker-disk sh -lc 'echo "$EXTRACT_SCRATCH_DIR"; df -h /scratch; test -w /scratch'` prints `/scratch` and succeeds.
5. On a **new controlled test case** with source coverage comparisons, enable `EXTRACT_DIRECT_TAR_STREAM=true`, run only disk extraction, and measure logs of completed shard `source/spool=`, `tar=`, `upload=`. If direct streaming is not faster or repeatedly fails on mismatched metadata, revert to `false`. Do not change active shard layouts or enable `EXTRACT_REPLAN_ON_RESUME` just for performance.
6. Compare selected source paths/inodes, file sizes, archive byte streams, hashes, read skips, MinIO object checksums, DB shard checkpoints, and case limitations to the original workflow. Use a separate job ID for A/B tests; do not overwrite original evidence parts.

## Interpretation of new timings

- High `source/spool` seconds: E01 compressed random-seek, USB/Windows Docker Desktop mount, limited physical IOPS, or source-read contention. Verify drive media, reduce readers on HDD, or test verified SSD copy.
- High `tar` seconds: compression/CPU, slow shard scratch volume. Keep zstd at level 1, ensure scratch on fast SSD and no antivirus contention against temporary files.
- High `upload` seconds: MinIO storage or network; check MinIO bind mount, host disk write latency, object upload pool, and concurrent disk consumers. Blindly increasing MinIO parallel uploads may worsen contention on HDD.
- If files packed greatly exceed files uploaded: large incomplete shard awaits upload/checkpoint; counts can regress after failed shard retry. This is not a completed evidence extraction.

## Limitations

The observed ~13.3 MiB/s is evidence *packing*, not MinIO transfer. The new code provides an opt-in optimization and instrumentation, plus fixes an unused scratch mount and progress mislabeling; a 30–45-minute full forensic/RAG SLA is **not verified** without the user's actual 42-part E01/host and live metrics.
