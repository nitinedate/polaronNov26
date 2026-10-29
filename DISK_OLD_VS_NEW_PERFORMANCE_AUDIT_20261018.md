# Polaron Disk Evidence: old vs current regression audit (2026-10-18)

## Baseline and scope

Compared the uploaded old `rag_new2_100(1).zip` against the current `polaron(20261017-165531).zip` and the more recent TSK/progress-agent repaired build `polaron_tsk_extraction_repaired_20261017.zip`. The delivered project is **based on the last build**, preserving the extraction watchdog, progress agent, and the prior priority-pass batching patch. Disk logic only was modified here.

The screenshots are measurements from a user's environment, **not from this build/test environment**:
- 42 E01 segments; 184,413 registered/extracted files.
- Extraction and registration completed; native parsing card remains 99% after nearly six hours.
- Actual second-pass progress: 20,049 / 183,884 priority sources and 683,719 records committed.
- Native parse complete-file counters alone are misleading: `execute_stage(..., 'parse')` invokes `run_disk_priority_evidence` *after* native parsing, holding recovery/OCR/RAG at their barriers.

### What changed versus the old project

| Older `rag_new2_100` | New Polaron serial pipeline |
|---|---|
| `backend/app/services/phase3_pipeline.py` calls materialize, `drain_pending_parse`, OCR, dual RAG and graph. | `backend/app/services/forensic_serial_pipeline.py` has 13 ordered stages. `forensic_serial_stages.py::execute_stage` calls native `_parse` plus `run_disk_priority_evidence`. |
| `backend/app/tasks.py` has a background parse drain and bucket parallelism. | Each subsequent stage waits for the current stage seal. OCR may triage early but card remains waiting. |
| No `forensic_priority_evidence.py` second-pass module. | Additional source-linked classification records and database commits for roughly 184k sources. |

The user's 45-minute old-job figure is not independently measured here, and the old build did not perform exactly the same analysis/coverage. This is a structural workload regression, not evidence of a 7x CPU-speed regression alone.

### Confirmed expensive code path

`backend/app/services/mobile_forensic/sqlite_counts.py::_read_artifact_bytes` calls `read_file_from_part(part_uri,path)` for each individual artifact. On tar.zst, each such request can seek by streaming/decompressing from the beginning of the part. The prior priority patch grouped **fallback header reads** by part but still allowed another parser for the same small artifact to re-open the compressed part. It also classified unsupported OS binaries by reading a header even where the source record had already been registered and SHA-256 was preserved.

## Changes in this release

1. Disk-only `disk_priority_fastpath.py`: defer *only* fallback header reads for recognized Windows OS binary resources under Windows OS directories with no competing parser. A `forensic_priority_records` record is retained with `signature_not_examined`, `signature_examination_pending=true` and the original source hash and path; it is not falsely described as decoded. Deleted/carved/user/download/browser/chat/mail/unknown and database-related files never take this fast path. This is a documented **signature coverage limitation**, not equivalent to examining every signature. To examine them, clear the selected `priority_parsed_v4` checkpoint in a controlled reprocessing run and use `DISK_PRIORITY_SIGNATURE_MODE=full`.
2. Reuse already verified *complete* source bytes from a streaming tar pass for any plugin on small, standalone source files <=16MiB, instead of only for the fallback plugin. This preserves full-file correctness by restricting reuse to buffers of known full size. Files with SQLite sidecars or oversized/unknown lengths use the previous reader.
3. Keep the previous patch's bounded PostgreSQL `execute_values` batches, checkpoint updates, and `sha256`/size verification of source contents. No mutations to original E01 segments.
4. Record second-pass diagnostics: deferred-signature count, streamed shard groups/file count, individual source-read count/time, and PostgreSQL batch insertion time. Results also appear in the priority result summary. These counters separate storage re-reads from database-write bottlenecks.
5. `backend/tests/test_disk_priority_fastpath_v20261018.py` covers safety filters, truthful deferred classification, and correct full-source stream-size gates. Updated an existing regression to assert that an already verified complete file is no longer redundantly fetched.

## Performance and validation evidence

**PASS:** `pytest -q backend/tests/test_disk_parse_priority_v20261017.py backend/tests/test_disk_priority_fastpath_v20261018.py` => 6 targeted tests passed on a synthetic in-memory backend.

The synthetic 520-source shared-shard scenario required one group read and zero additional per-source fetches for its small content-bearing test file. The previous build reopened that single source separately. Tests check resumable checkpoints, database batch count, SHA-256 and size validation of streamed content, full-file/prefix isolation, path safety and source linkage.

**Not tested:** production E01/MinIO/PostgreSQL/GPU throughput, full suite, 30-45 minute SLA. In this runtime `psycopg2` and certain production dependencies are unavailable. Two existing broader tests have independent limitations: `test_priority_evidence_bounds.py` imports a function absent before this patch (`priority_source_kind`), while `test_forensic_priority_evidence.py` requires unavailable `psycopg2`. These are not counted as passes.

## Safe deployment on Windows PowerShell

1. Stop or pause new disk jobs. **Wait for the active priority batch transaction to commit**, then halt the job via the application before replacing workers. Do not indiscriminately `docker compose down -v` or delete job checkpoints.
2. Back up the current source, PostgreSQL database and MinIO objects; preserve existing `.env` secrets. The distributed ZIP intentionally **excludes production `.env`**, keys, and evidence. Merge code into your own deployment rather than deleting existing configuration.
3. Set `DISK_PRIORITY_SIGNATURE_MODE=safe_deferred` in your existing production `.env`. To reproduce full header-examination behavior, set `full`.
4. From project root, build and recreate only relevant disk services, after the active job has stopped safely:

```powershell
docker compose build api
docker compose up -d --no-deps --force-recreate worker-parse worker-progress
# Restart worker-disk only if it is fully idle and runs parse sidecar tasks.
```

5. Verify source counts and hashes in PostgreSQL; confirm no duplicate `forensic_priority_records.artifact_id` and no loss of `job_artifacts`. Resume using the application's checkpoint/resume workflow. Monitor `priority_sources_completed`, `priority_sources_total`, `priority_shard_opens`, `priority_individual_reads`, `priority_individual_read_seconds`, `priority_db_insert_seconds` in `pipeline_stage_runs.details`.
6. Compare a **clone** of the same 42-part E01 case against the old code and the patched build under equivalent storage and hardware. Record total wall time plus *each* stage and source format. Compare `job_artifacts` path/hash counts, normalized records, source exceptions, recovered/deleted artifacts, OCR results and RAG citation coverage. The fast-path differences must be specifically accounted for as unexamined header signatures.

## Important operational limitations

- Deferred signature scanning is *not* source loss; `job_artifacts` and original evidence remain available, but it is a narrower derived classification than a full signature read.
- The legacy project had less processing, so simply matching its 45-minute runtime while performing more analysis is not a valid parity comparison.
- Actual runtime improvement depends on the fraction of system-resource files versus complex SQLite/browser/mail records and on MinIO/PostgreSQL throughput.
- Performance agent should flag no useful progress in `priority_sources_completed` (not mere heartbeat age), with single-owner retry and no duplicate writers. Existing progress-agent safeguards are retained, but no remote live-agent execution was possible.
- The attached screenshot shows ~11% of **the second pass** completed, not 99%; UI should show both native parsing completion and priority-pass progress as separate denominators.
