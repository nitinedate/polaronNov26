# Streaming inventory-to-MinIO: implementation boundary

This archive adds a tested, bounded, deduplicating producer-consumer handoff. It is **not yet wired into the production forensic extraction path** and should not be deployed as a throughput fix by itself.

## Verified from current source

1. `virtual_disk.enumerate_all_files` and the isolated `tsk_walk_isolated` child build the entire metadata list first.
2. `extracted_disk.py` detects OS and applies `_filter_nodes` **after** enumeration.
3. `extract_shard_v45.shard_worker_v45` rereads the selected file's **contents**, then compresses and uploads a shard; this content read is necessary, not a duplicate payload read from inventory.
4. Uploads are shard archives; do not switch to one MinIO object per small file without benchmarking object count and metadata overhead.

## Required end-to-end follow-up

- Extend isolated TSK walker and parallel inventory with acknowledged bounded *node batches* (not a huge final JSON list). Preserve watchdog, stop and resume semantics.
- Resolve OS-aware filtering *before* issuing upload commands; where OS unknown, spool metadata batches to bounded disk-backed storage and apply filters when policy is known.
- Assign `(job_id, source_id, path, inode)` to every inventory entry. Use immutable source IDs under the same job.
- Route selected entries through bounded disk-reader workers; batch sequential/inode-nearby files into immutable zstd tar shards, then upload completed shards asynchronously with separate MinIO threads. Do not have multiple threads operate on a shared pytsk3 handle.
- Persist durable shard index and checksum before checkpoint acknowledgment. Restart only uncommitted batches; use stable keys for idempotent retries and manifest reconciliation.
- Count separately: discovered, filtered, accepted, read, uploaded, committed, failed/unreadable. **Never claim 100% coverage for missing entries.**
- Benchmark USB HDD, SSD, and EWF separately: the best number of readers depends on seeks and throughput; typically keep HDD source readers low and decouple network uploads.

Run unit tests with `PYTHONPATH=backend pytest -q backend/tests/test_inventory_upload_pipeline.py` from the project root with pytest installed.
