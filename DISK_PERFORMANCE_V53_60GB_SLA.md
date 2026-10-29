# Disk Performance V53 - 60 GB / 30-35 minute evidence-ready profile

## Goal
Target **60 GB evidence extraction in 30-35 minutes** without dropping evidence types, lowering parser coverage, reducing recovery scope, or weakening artifact quality.

The target means an end-to-end effective extraction rate of about **29.3 MiB/s** for 35 minutes, or **34.1 MiB/s** for 30 minutes. Because TAR/Zstd, MinIO, filesystem metadata and many-small-file overhead consume bandwidth, the source and scratch/destination path should normally sustain at least **~44-55 MiB/s** sequentially.

## V53 changes
- Removed the legacy global 4-reader ceiling. Fast SSD/NVMe sources can now use up to 12 EWF readers; mobile/folder sources can use up to 16 where appropriate.
- HDD/network sources remain capped at 1-2 source readers, preserving sequential locality and avoiding seek collapse.
- Read semaphore raised from 4 to 8 by default (max 12), but the source-media planner still lowers it for HDD/network/single ZIP-on-host-mount cases.
- New `byte_range_v53` sharding keeps inode/path locality while balancing estimated bytes and small-file overhead. Existing jobs with completed shards keep their saved old strategy so resume correctness is preserved.
- Extraction executor can run more shard work units than source-read slots on fast media. This overlaps source reading with TAR/Zstd packing and MinIO upload while the read semaphore still controls source pressure.
- Stream chunk defaults raised to 8 MiB for fast media and 16 MiB for HDD sequential reads.
- Spooled in-memory threshold raised to 128 MiB, reducing scratch write/read churn for medium files without changing evidence bytes.
- MinIO shard upload uses multipart `fput_object` for large parts with parallel uploads (`MINIO_UPLOAD_PARALLEL=6`, 64 MiB parts by default).
- Local object-store fallback now streams copies instead of `read_bytes()` to avoid multi-GB RAM duplication.
- Desktop/workstation capacity plans expose more SSD/NVMe extraction headroom; physical-media safeguards are applied afterward.
- UI/backend extraction progress now reports live MiB/s, target MiB/s and ETA.

## Quality / forensic integrity preserved
No evidence category, parser, deleted-data recovery path, hashing option, artifact registration, OCR quality rule, or report evidence rule was removed to obtain performance. Evidence-focused noise filtering remains enabled; `EXTRACT_MAX_FILE_BYTES=0` prevents large evidentiary media/documents from being discarded by a generic size ceiling. V53 changes scheduling, buffering, shard balance and transport only.

`EXTRACT_THEN_PROCESS=true` remains the default, so downstream parsing does not cause repeated source-image reads. OCR/RAG/report enrichment remain separate phases after the immutable extracted-image manifest is complete.

## Recommended profile
```env
EXTRACT_DISK_WORKERS=8
EXTRACT_SHARD_COUNT=12
EXTRACT_UPLOAD_CONCURRENCY=8
EXTRACT_READ_SEMAPHORE=8
EXTRACT_READ_CHUNK_BYTES=8388608
EXTRACT_HDD_CHUNK_BYTES=16777216
EXTRACT_SPOOL_MAX_BYTES=134217728
EXTRACT_TAR_BUFSIZE=8388608
EXTRACT_ZSTD_LEVEL=1
EXTRACT_MODE=forensic
EXTRACT_MAX_FILE_BYTES=0
MINIO_UPLOAD_PARALLEL=6
MINIO_UPLOAD_PART_MB=64
EXTRACT_TARGET_GB=60
EXTRACT_TARGET_MINUTES=35
EXTRACT_THEN_PROCESS=true
PHASE3_STREAM_RAG_DURING_EXTRACT=false
```

For a known rotational source, keep `DISK_SOURCE_MEDIA=hdd`; the software will use at most two read slots. For a known SSD/NVMe source hidden by Docker Desktop, explicitly setting `DISK_SOURCE_MEDIA=ssd` or `nvme` allows the fast-media lane.

## Preflight
Run:
```bash
python backend/scripts/verify_60gb_sla_v53.py --source /host/e/path/to/evidence.E01 --scratch /scratch
```
The source probe is read-only. The scratch probe writes and deletes only its own temporary benchmark file.
