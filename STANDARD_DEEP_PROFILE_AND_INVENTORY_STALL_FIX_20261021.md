# Standard / Deep profiles and stage-9 inventory stall — 2026-10-21

Base: `polaron.zip` (complete merged source of 2026-10-21). Source patch only; no
database migration, no evidence or MinIO change, no re-extraction required.

## 1. Problems

**Standard took as long as Deep.** The profile changed exactly two things:
extraction mode (`standard → defensible`, `deep → full`) and signature carving.
`defensible` is "when in doubt, keep"; on Windows it extracts almost the same
file set as `full`, so 227,536 files were extracted in Standard. Every stage after
extraction was identical in both profiles.

**Stage 9 "Normalize / correlate / artifact inventory" ran for hours** at
"25 / 36 (Windows)" (36 = report-template catalog rows; progress updated only every
5th row, so ~11 collectors were still running). Root causes, all confirmed in code:

| # | Cause | Effect |
|---|---|---|
| 1 | USB, Your Phone, RDP, Feature Usage and both Installed Programs rows re-read registry hives / SetupAPI logs **from the tar shards** (`_read_job_files`) and re-parsed them, although stage 5 had stored the identical `parse_registry_hive` / `parse_setupapi_log` output. | Each read streams and zstd-decompresses a multi-GB shard from MinIO until the member appears. The same hives were streamed 6–7 times **concurrently** by 8 worker threads. RDP and Feature Usage had no row limit on NTUSER.DAT. |
| 2 | EML(X) Files and Email Attachments ran the MIME scan (≤20,000 EML + ≤4,000 extensionless candidates under AppData/Temp/Desktop/Downloads) **one file at a time** via `iter_artifact_content`, which streams the shard from its start for each file. The scan was not single-flight, so both rows ran it in parallel. | Up to ~24,000 shard scans, twice. |
| 3 | Outlook Emails/Tasks/Contacts/Appointments and Windows Mail each expanded **every** parse-result JSON array of the job (`jsonb_array_elements`) — 6–8 full scans. | Minutes of PostgreSQL CPU/IO per scan. |
| 4 | `normalized::text ILIKE '%…%'` over all parse results (USB supplement, USB events, Your Phone, Jump Lists). | Full detoast + text cast of every parse result. |
| 5 | PST scan not single-flight (Outlook Emails + Email Attachments). | Up to 40 × 80 MB mailboxes read twice. |
| 6 | `_doc_ready()` never accepts a `job_artifacts` census, so every document/LNK/media collector regrouped all files and rewrote `jobs.disk_source` (the row the stage heartbeat updates). | Redundant work and row-lock contention. |

**Correctness bug found and fixed:** since the disk priority scan was removed
(2026-10-19), `forensic_priority_records` has no browser rows for new disk jobs, and
`collect_job_browser_url_records` returned an **empty** list once parse was done.
Web Chat, Social Media, Malware/Phishing, Pornography and Dating Site URL counts were
therefore **0 for every new disk case**. Re-run inventory on affected cases.

## 2. What changed

### Inventory (both profiles — same records, read once)
* `registry_evidence_index.py` (new): one indexed SQL read of the latest stored
  registry/SetupAPI parse result per source, filtered to the six record types the
  collectors use. Single-flight per job. VSS/backup copies with the same SHA-256 are
  counted once (as before). Raw bytes are read **only** for hives/logs without a stored
  parse (failed/timed-out), all together in one shard pass. Provenance (path, kind,
  parsed vs live fallback) is kept in `stats`.
* USB, RDP, Feature Usage, `scan_registry_inventory` (Installed Programs), USB usage
  events and Your Phone now use the index. Full-text ILIKE scans removed (Jump Lists
  now filter on `parser_name='jumplist'`).
* Email: one aggregate for all Email & Calendar record types (single-flight cache).
  MIME scan single-flight and one streamed pass per shard
  (`iter_job_file_contents`). Extensionless candidates exclude files stage 5 parsed as
  something other than RFC822 (stage 5 runs the same `is_extensionless_email_candidate`
  test); unparsed/failed files remain candidates. PST scan single-flight.
* URL inventory: bug fixed; browser DBs, `.url` shortcuts and message stores read in
  one pass per shard (`read_job_files_capped`).
* Census reused while the registered-file count is unchanged.
* Progress advances on every collector (was every 5th); collectors > 30 s are logged
  with their name and `collector_elapsed_ms` is stored in the count snapshot.

### Standard vs Deep

| Stage | Standard | Deep |
|---|---|---|
| Extraction | New `standard` mode: defensible include rules **minus** V45 OS/vendor trees (WinSxS, SysWOW64, SystemApps, Fonts, Program Files app trees, WindowsApps, Package Cache, node_modules, …) and vendor **assets** (binaries, icons, UI scripts/JSON/XML, fonts) under `Windows\`, `Program Files*`, `ProgramData`. Never excluded: user profiles, UWP package state, KEEP prefixes, anything the OS scope pack claims specifically (hives, evtx, Prefetch, Amcache, SRUM, Panther/unattend.xml, Scheduled Tasks, LNK, jump lists, browser, mail), and documents/logs/DBs/archives/scripts/configs anywhere. Every exclusion is counted by rule in `filter_stats`. | `full` (unchanged) |
| Signature carving | Off (unchanged) | On |
| Media observations | User-space pictures/videos only; vendor media counted as `out_of_scope_vendor_media` | All media |
| Enrichment | Entity-mention regex statistics not computed; ontology count only; no vectors | Counters on a 3,500-char sample (`FORENSIC_ENRICH_FULL_TEXT=true` restores full text); vectors scheduled |
| Graph (Neo4j) | Skipped, reason shown on the card | Built |
| Validation | No vector barrier; `profile_limitations` recorded; `coverage_complete=false` | Vector barrier when `RAG_EMBEDDING_ENABLED` |

Legacy jobs (no `processing_profile`) behave as Deep. Report retrieval in Standard uses
PostgreSQL FTS/keyword/parsed-record search; graph expansion and vector search simply
return nothing, which the hybrid retriever already handles.

**Removed as forensically unnecessary:** repeated raw re-reads and re-parses (both
profiles); full-text entity statistics (both; sampled in Deep); in Standard only —
vendor asset extraction, OCR/observation of vendor icons, Neo4j graph, semantic vectors.
**Kept:** intake/hash/segment checks, extraction manifest, materialize, native parse,
recovery, OCR, inventory, chunking, validation and every limitation record.

### UI
Mode descriptions state exactly what each profile does; skipped stages show
"Not run: <reason>".

## 3. Files

New: `backend/app/services/processing_profile.py`,
`backend/app/services/registry_evidence_index.py`,
`backend/scripts/validate_inventory_sql_20261021.py` (live SQL check, scratch schema),
`backend/tests/test_inventory_single_pass_20261021.py`,
`backend/tests/test_standard_extraction_filter.py`,
`STANDARD_DEEP_TEST_RESULTS_20261021.txt`, this file.

Modified (backend/app/services): `artifact_live_counts.py`, `artifact_sections.py`,
`browser_url_inventory.py`, `catalog_aligned_counts.py`, `catalog_artifact_runner.py`,
`disk_ext_census.py`, `email_inventory.py`, `email_mime_inventory.py`,
`extract_filters.py`, `extract_noise.py`, `extract_os_vendor_noise.py`,
`extracted_disk.py`, `forensic_inventory.py`, `forensic_media_review.py`,
`forensic_serial_stages.py`, `pst_mailbox_inventory.py`, `rag_enrich.py`.
Frontend: `components/forensic/HostEvidencePanel.tsx`,
`components/forensic/SerialPipelineBanner.tsx`.
Tests: `tests/test_standard_deep_profiles.py` (mapping updated + 6 contracts),
`backend/tests/test_forensic_serial_pipeline.py` (see 4.3).

## 4. Verification performed

Full detail: `STANDARD_DEEP_TEST_RESULTS_20261021.txt`.

1. **Compile / type-check.** All 24 changed or new Python files compile. Frontend
   `tsc -b` (strict, as `npm run build` runs it) passes with no diagnostics; an
   injected type error in the edited component was caught, then reverted.
2. **Focused tests — 111 pass.** 89 extraction-scope tests (36 must-keep evidence
   paths incl. WhatsApp Desktop / Your Phone UWP state, 16 vendor-noise paths, Deep
   keeps everything, shared `defensible`/`full` modes unchanged); 12 inventory
   behaviour tests (record equivalence, VSS de-dup, live fallback only for unparsed
   hives, single-flight under 8 threads, one pass per shard, one email aggregate, MIME
   single-flight, URL bug — confirmed to fail on the original condition); 10 profile
   contracts.
3. **Live PostgreSQL 16 — 25/25.** Every new query executed through the real module
   code on the real table definitions (migration 009): VSS de-dup, latest-parse-only,
   live fallback only for the timed-out hive, USB/RDP/Feature Usage/Installed Programs/
   USB events counts, email aggregate incl. the `count` field, MIME candidate filter
   (keeps stage-5 RFC822 hits, unparsed files and validated messages exactly once;
   excludes parsed binaries), Standard media scope incl. stale Deep observations, census
   reuse and recompute on count change, jump-list predicate. Re-run on a scratch DB with
   `DATABASE_URL=… python backend/scripts/validate_inventory_sql_20261021.py`.
4. **Full regression on original vs modified tree** (same environment): 224 failed /
   23 errors in both — an identical, pre-existing set (missing Magnet AXIOM CSV, live
   Redis/Postgres/Neo4j dependencies, obsolete assertions); passing tests 1,860 → 1,968.
   **No test that passes on the original fails on the modified tree.** One original
   test was deliberately updated: the serial enrichment full-corpus assertion now runs
   with `FORENSIC_ENRICH_FULL_TEXT=true`, and a new test pins sampling as the default.
   This intentionally reverses an earlier decision that the serial stage must count
   entities over full text; set the variable to restore it.

**Not verified here:** a real E01/E02 run, MinIO shard throughput, Celery/Redis/Neo4j,
GPU OCR, query plans on production-size tables, end-to-end stage timings, the Vite
production bundle, report PDF/DOCX output. **No measured "one hour" figure is
claimed** — it depends on evidence size and on how much the Standard scope removes on
your images. Measure on a representative case (section 6).

## 5. Deployment

1. Back up project, `.env`, PostgreSQL and MinIO volume metadata. Keep evidence read-only.
2. Pause the running case from the UI and wait until its worker exits.
3. Overlay the files and rebuild. All backend workers reuse the image `api` builds
   (V77), so only two builds are needed; `--force-recreate` makes every worker pick up
   the new image:
   ```powershell
   docker compose build --no-cache api frontend
   docker compose up -d --no-build --force-recreate api frontend worker-disk worker-parse worker-quality worker-rag-gpu worker-ocr-gpu worker-report worker-agent worker-progress worker-beat worker-rag-prep
   ```
   Do not recreate `neo4j`, `opensearch`, PostgreSQL or MinIO, and never remove volumes.
4. Resume the case. Do **not** re-extract.

**The currently stalled case** (Standard, at stage 9, 25/36): on resume, the 25
persisted rows are skipped and the remaining collectors run on the new code. Graph is
skipped and enrichment is light because the case is Standard. Its extraction remains
`defensible` (the checkpointed mode is kept on resume by design) and its stage-8
observations stay as recorded. Because of the URL bug, re-run inventory after it
completes (or reprocess inventory) so the five URL rows are recounted.

## 6. How to measure

Per-stage `started_at`/`completed_at` are on the stage cards. For inventory, the disk
log line "Artifact inventory step timings — …" and per-row `collector_elapsed_ms` show
where time goes; worker logs print `registry evidence index job=… {stats}` (look for
`live_fallback_sources` — normally 0) and `slow inventory collector … Ns`. Compare
extraction `filter_stats` (`to_extract`, `standard_vendor_asset`, `os_vendor_tree:*`)
against the previous 227,536.

## 7. Switches / rollback

* `FORENSIC_ENRICH_FULL_TEXT=true` — Deep entity statistics over full text.
* To restore the previous Standard extraction scope, change the mapping in
  `extracted_disk.py` back to `"standard": "defensible"`.
* Rollback = restore the previous files and rebuild; no data migration to undo.

## 8. Addendum — drive dialog no longer opens on arrival (disk jobs)

**Problem.** After creating a disk job, `JobDetailPage` opened the "Select evidence
directory" drive dialog automatically (250 ms after load, via `autoSelectFolder`).
The examiner never saw the Examination mode first, and because the profile is sent
when the folder is registered, cases could be registered with the default profile
before a choice was made.

**Change.** `frontend/src/pages/forensic/JobDetailPage.tsx`: for disk jobs the page now
only scrolls the evidence panel into view. Flow: choose **Standard forensic** or
**Deep examination**, then click **Browse drives**. The new-job banner states that
order. Mobile jobs (no examination mode) keep their existing auto-open, as does
`MobileCompactJobPage`. A shared `isMobileEvidenceJob()` helper replaces the duplicated
mobile check.

**Verified.** `tsc -b` passes; `tests/test_disk_browse_dialog_not_auto_opened.py`
(4 tests) passes and its disk test fails against the previous page. Rebuild the
frontend image only: `docker compose build --no-cache frontend` then
`docker compose up -d --no-build --force-recreate frontend`.
