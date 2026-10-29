# Disk native parsing: targeted progress-overhead reduction

## Changed
- Native parse no longer runs a full-case OCR status aggregation every 15 seconds while streaming compressed tar shards. The previous aggregation counted all `ocr_status=pending` artifacts as GPU-queued, even though quality/eligibility triage had not completed.
- Native parse per-shard PostgreSQL status writes are throttled from 2 seconds to 10 seconds. The operation deadline remains 900 seconds and worker checkpoints are unchanged.
- React's parse-stage card shows shard progress only; actual GPU OCR progress remains in the dedicated OCR stage.

## Limits
- This is a narrow performance and correctness patch; does NOT repair slow MinIO download, shard decompression, network throughput, or missing parser checkpoints.
- Don't infer true GPU queue size from `ocr_status=pending`; use eligible OCR candidate metrics in the OCR stage.
- A single compressed shard may still take a long time and the 99% indicator does not mean that only 1% of I/O remains.
- Validation: Python syntax compilation and static checks only. Full Windows Docker, real-case PostgreSQL, MinIO and UI build have not been run.

## Next profiling work
- Record per-shard compressed size, time-to-first-member, read MB/s, TSK parse time, DB commit wait, and heartbeat ages.
- Verify random reads and seek behavior in tar_cache, and that shard data is streamed only once.
- Only add independent shard concurrency when it cannot increase drive contention or compromise deterministic checkpoint accounting.
