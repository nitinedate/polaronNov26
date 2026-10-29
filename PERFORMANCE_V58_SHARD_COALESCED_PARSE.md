# Polaron V58 - High Throughput Native Parse / OCR Quality Triage

## Problem observed
A 184k-artifact case remained in Native forensic parsing for ~45 minutes at only ~50% completion. The main code-level bottlenecks found were:

1. PostgreSQL commit/heartbeat path flushed the parse transaction after each artifact, defeating `PARSE_DB_COMMIT_BATCH` and creating high fsync/transaction overhead.
2. OCR quality triage called the artifact reader per image/document. For serialized extracted evidence this can stream/decompress the same multi-GB tar.zst part repeatedly.
3. The authoritative serial parser was draining all registered artifacts instead of the existing forensic evidence keep-set, spending parser time on media/no-parser/noise rows that belong to OCR/media stages.
4. Static `.env` locks kept the dynamic performance planner from raising parse concurrency on capable workstations.
5. Deleted/recovery tagging performed per-artifact UPDATE statements.

## V58 changes

### 1. Batched parser persistence
`artifact_parse.py` now keeps parser result writes in the configured transaction batch and only heartbeats after a batch commit. Large forensic blobs still force a commit/heartbeat individually to retain liveness.

Defaults:
- `PARSE_DB_COMMIT_BATCH=250`
- `PARSE_WORKERS=12` baseline, host capacity planner may adapt higher/lower.
- `PARSE_DRAIN_BATCH_LIMIT=1200` local baseline.

### 2. Evidence-focused native parse queue
The serial Native forensic parsing stage calls `prepare_forensic_parse_queue()` and drains with `forensic_only=True`.

This does **not** delete or omit evidence. All files stay registered in `job_artifacts`. It only avoids running native parsers on rows that are known media/no-parser/noise items. Poor media remains visible to quality triage and can be routed to GPU OCR.

### 3. Shard-coalesced OCR quality reads
`mobile_quality_ocr.py` now groups quality candidates by `metadata.extracted_part_uri`.

- Images/documents: `iter_files_from_part()` reads all wanted members in one streamed shard pass.
- Videos: `iter_spilled_files_from_part()` extracts selected candidate videos in one shard pass, samples frames, then deletes temporary files.
- Legacy/direct MinIO evidence keeps the existing fallback reader.

This applies to Disk, Android, and iPhone because V57 unified the quality triage entrypoint.

### 4. Larger quality batches and set-based DB update
- `QUALITY_TRIAGE_BATCH=800`
- `QUALITY_TRIAGE_CPU_WORKERS=4`
- Quality metadata/ocr status is persisted with one `execute_values` batch rather than one UPDATE statement per item.

### 5. Dynamic host adaptation unlocked
`PARSE_WORKERS` and parse-bucket settings were removed from `DYNAMIC_PERF_LOCK`. The host capacity planner can now raise/lower parse concurrency according to CPU/RAM/temperature instead of being permanently pinned to the static `.env` value.

### 6. Recovery batch persistence
Deleted/recovered path tagging now scans 5,000 rows per batch and writes metadata with `execute_values`, replacing per-artifact UPDATE statements.

## Expected architecture

```
Extracted evidence shards
       |
       +--> Native parse keep-set --> 12+ adaptive parser workers --> batched PostgreSQL writes
       |
       +--> Quality candidates ----> shard-coalesced read ----------> CPU quality workers
                                                               |
                                                               +--> OCR bucket
                                                                        |
Deleted/recovery starts ------------------------------------------------+--> GPU OCR in parallel
```

## Quality guarantees
- All extracted files remain registered and available to artifact inventory.
- Native parser filtering uses the existing forensic keep-set and parser sidecar rules.
- Media is not discarded; poor images/documents/video samples are independently quality-triaged.
- Original evidence is unchanged.
- Large/critical forensic files still get explicit liveness commits and full evidence handling.

## Validation
- Python compile checks passed for modified modules.
- Docker Compose YAML parses for central, Android, and iPhone stacks.
- V58/V57 focused regression tests: 10/10 passed.

## Important benchmark note
These changes remove major code-level overheads, but exact 60 GB wall-clock time still depends on source media throughput, number of tiny files, compressed shard ratio, PostgreSQL/MinIO disk placement, CPU model, and parser mix. Benchmark on the actual workstation after deployment and inspect per-stage MiB/s / files/s before further tuning.
