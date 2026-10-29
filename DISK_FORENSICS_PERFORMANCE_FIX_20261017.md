# Polaron disk-image performance patch — 17 October 2026

## Finding from the supplied screenshot and source audit

At 1h43m elapsed, UI shows overall 38% and native parsing 99%; 184,413/184,413 native artifact rows are accounted for. This is **not** proof that every stage is complete. `execute_stage('parse')` runs `run_disk_priority_evidence()` AFTER `_parse()` has completed its artifact counter. In the old priority pass, each eligible file triggered a transaction commit and a progress-table update, and unrecognized files triggered `_read_artifact_bytes()`; that routine reopens the compressed tar.zst and reads/verifies an entire file, even when the fallback classifier only needs its first 4 KiB. This can cause severe repetitive decompression and database write amplification. These observations are source-code diagnoses, not a measured profile of the user's 42-segment case.

The native parser also recreated its thread pool for each work chunk and held *all* completed records in memory until the slowest parser finished. It could not commit fast files or advance their counts while waiting for one slow task.

## Changes included

- `backend/app/services/forensic_priority_evidence.py`: route once; group fallback-signature reads by extracted part URI; stream each grouped part once; keep full-byte readers for all non-fallback parsers and for source material that needs more than the verified prefix. Bulk UPSERT normalized evidence records (up to 2,500 at a time), bulk mark up to 250 source checkpoint rows per transaction, keep errors and idempotent `priority_parsed_v4` markers. Periodic progress shows source count and record count, not just the last path.
- `backend/app/services/tar_cache.py`: optional full-object SHA-256 and byte-count verification for streamed header reads; reject corrupted/missing evidence (`None`) and allow its error annotation, rather than treating a prefix as a fully checked source. Per-file caps are honored for cached full files.
- `backend/app/services/artifact_parse.py`: reuse a bounded parser executor and persist finished results while other work continues. One DB writer thread remains authoritative; no parallel SQL sessions are introduced by this change.
- `backend/tests/test_disk_parse_priority_v20261017.py`: tests the edited functions with mocked adapters for early durable commits, checkpoint batching/idempotency, complete-source safety for nonfallback parsers, and corrupt/missing tar members.

No deletion of evidence or original E01 segments, no change to OCR/embedding model choice, parser version, chunking policy, or output artifact schema.

## Test evidence

Run from `backend`:

```bash
python -m pytest -q tests/test_disk_parse_priority_v20261017.py
```

On the test sandbox: **3 passed**. The 520-source synthetic case, in which headers share a single part, opened that part once instead of needing a separate file read for each header. It processed all 520 source checkpoints, produced 521 records (including a separate full-source parser record), and used bounded commits. The real application image, PostgreSQL, MinIO and E01 segment bytes were NOT present, so **30–45 minutes is still a target, not an established measured outcome**. Full end-to-end runtime and quality parity require the next checks.

## Safe rollout and baseline comparison (Windows PowerShell)

1. Back up the production app and PostgreSQL before modifying or resuming a case. Preserve the original evidence image, segment hashes, existing reports, RAG chunks and previous output rows. Use a separate representative test case if possible.
2. Place this archive in a *new* project directory or apply the three updated source files to the production checkout, then inspect the diff. The ZIP retains the uploaded configuration files; keep it private.
3. From the project root, with Docker Desktop started, first run the included unit tests inside the disk worker:

```powershell
docker compose exec -T worker-disk python -m pytest -q tests/test_disk_parse_priority_v20261017.py
```

4. Stop/finish active jobs gracefully; **do not force-kill an active evidence writer**. Once no disk stage is running, restart the services that import the changed code:

```powershell
docker compose up -d --no-deps --force-recreate worker-disk worker-parse
```

5. Run the same evidence case in a *new isolated test case* first, with the same CPU, GPU, MinIO and PostgreSQL configuration, same hashes, same model/accuracy settings and the same 42 input segments. Compare with the previously captured case baseline. Do not reset or re-import the evidence only to measure the new native pass.
6. Monitor the native stage's operation line: `Priority evidence: processed / total sources checked; records committed`. After its completion, recovery/OCR/inventory/chunking still must finish. The progress bar percentage is NOT a time estimate. Look for errors, missing reads and retained `priority_source_exception` records.

### Resource tuning (trial settings, not mandatory defaults)

Current uploaded `.env`: `PARSE_WORKERS=12`, `PARSE_PARALLEL_BUCKETS=2`, `PARSE_DB_COMMIT_BATCH=250`, `PARSE_DRAIN_BATCH_LIMIT=1200`, `PARSE_FILE_TIMEOUT_SEC=0`. A zero timeout means unresponsive native parsers do not have a per-file hard timeout; do not claim there is a guaranteed bound. The stage-level process watchdog and worker cancellation are separate mechanisms. For the 12-GB laptop GPU, retain one heavy CUDA job at a time, and compare **8 vs 12** CPU parse workers and **2 vs 3** parse sidecars with host CPU temperature and disk latency monitoring. On a mechanical HDD, low concurrent source readers generally outperform many random readers. Move temporary shard spool to fast SSD/NVMe if available. Do not raise CPU/CUDA concurrency blindly: competing readers and thermal throttle can make wall time worse.

The GPU accelerates OCR and embedding steps, **not** tar decompression, metadata-only inventory, or PostgreSQL commits; the repaired priority pass is primarily I/O + SQL bounded.

## Acceptance criteria for the real 42-segment benchmark

- All original segment IDs and source SHA-256 hashes match baseline. All 184,413 acquired files still have registered provenance, and stage source-coverage exceptions are explicit. No source silently disappears or becomes marked verified if it was unreadable/corrupted.
- Native parsed/skipped/failed/pending counts reconcile; `priority_parsed_v4` checkpoint count matches eligible sources; priority normalized artifact families, row counts and stable IDs are identical, or any parser-version-independent difference is investigated per source.
- OCR bucket pending/completed and missed media; recovered deleted artifacts; browsers/communications; RAG chunks and citations; entity/graph references; and report coverage are compared against the baseline. No regression to evidence quality or forensic report reproducibility.
- No DB deadlocks, abandoned `parse_status='parsing'`, unbounded source replay, permanent 99% wait, or memory/thermal runaway. Verify worker restarts and resume checkpoint behavior with an intentional clean pause in a *test* case.
- Measure end-to-end wall clock from acquisition start to **validation** complete, not just native parsing. **PASS for the requested target** only if the same 42-segment case completes in <=45m with equivalence checks passing. Aim for <=30m after profiling; this patch alone cannot guarantee it.

## Remaining constraints and opportunities

A production E01 + PostgreSQL/MinIO benchmark is required before making a time promise. `PARSE_FILE_TIMEOUT_SEC=0` and nested thread-based parser timeout handling elsewhere in the legacy code are *not* a hard-kill guarantee. True process-level per-file kill isolation requires a separate tested change. Large SQLite/EVTX source reads and later GPU OCR, chunk generation, Neo4j or inventory may still dominate. Do not skip these evidence stages to meet a stopwatch. Only lower-priority reindexing may be overlapped if its input is committed and its checkpoint is independently verified.
