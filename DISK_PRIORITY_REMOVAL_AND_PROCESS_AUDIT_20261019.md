# Polaron disk priority scan removal and pipeline audit (2026-10-19)

## Implemented
- Removed `run_disk_priority_evidence()` from disk-only Phase 5 in `backend/app/services/forensic_serial_stages.py`. Phase 5 now completes on native artifact parse counters and the existing parse completion barrier.
- Removed the mandatory *disk* priority-record RAG chunking pass and its downstream `missing_priority` validation gate. Normal native disk chunks, profile facts, OCR chunks, vector requirements, and artifact coverage gates remain.
- Removed obsolete 'Priority evidence' live meter from `frontend/src/components/forensic/SerialPipelineBanner.tsx`.
- Added four source-level contract tests to prevent accidental reintroduction.
- Preserved historical `forensic_priority_records` and their exception accounting; no evidence database migration, delete, or backfill is performed. The priority module is retained because mobile parsing, artifact pages, and suspicious-activity logic still consume its APIs.
- Did not modify user data, MinIO, PostgreSQL volumes, or E01/E02 images.

## Important caveat for in-flight jobs
- **Do not deploy by restarting a live worker:** an already executing process may still be inside the old 8-slot priority scan. Quiesce or pause the case with the application's job controls, wait for shutdown, back up DB and MinIO state, deploy, then resume the same job using the existing serial recovery/control workflow. Never re-run extraction or reset provenance/checkpoints for a completed extraction.
- The stalled case should reconcile `pipeline_stage_runs` parse counters against `job_artifacts.parse_status`. Do not mark parse complete if pending/parsing artifacts remain; if no pending rows remain, replay the parse stage through the normal controller under its advisory lock after the old worker exits. This release intentionally does **not** execute SQL that blindly marks cases complete.
- Existing priority records have been retained. Future disk runs no longer populate additional priority-only records. Any UI that specifically lists that historical table remains usable for old cases but should not be interpreted as comprehensive for new disk cases.

## Process audit — recommendations, not automatic deletions
| Stage | Decision | Rationale / conditions |
|---|---|---|
| Intake and source preparation | KEEP | Segment continuity, evidence source safety, chain of custody. Can consolidate UI only, not verification. |
| Complete extraction and materialization | KEEP | Different work: extracted bytes/manifest vs registered provenance and parse queue. |
| Native parsing | KEEP | Main artifact coverage and source-linked parsing. Removed redundant disk-wide priority scan. |
| Deleted/recovery | KEEP | Unique deleted records and carved artifacts; optional only if examiner explicitly excludes with documented limitation. |
| GPU OCR | CONDITIONAL | Skip when no OCR bucket / examiner policy excludes OCR, but report source limitation. |
| Image/video review | CONDITIONAL | Images and videos need coverage where in scope; avoid redundant OCR/visual model passes over identical assets. |
| Normalize/correlate/inventory | KEEP, consider batching | Needed for structured findings; verify overlap with enrichment and source classification. |
| RAG chunking | KEEP | Searchable text and citations; remove duplicate synthetic chunks only after equivalence tests. |
| Entity enrichment | OPTIONAL | Expensive; run after search indexes, for investigation-specific questions or selected text. |
| Neo4j graph synchronization | OPTIONAL | PostgreSQL relational and FTS/vector retrieval do not require Neo4j; preserve when graph investigation enabled. |
| Process agent/completeness validation | KEEP | Required to avoid false 100% completion and record acquisition/processing limitations. |

## Validation
- `python -m pytest -q backend/tests/test_disk_priority_stage_removed.py` (run from backend directory with corresponding relative test path): 4 passed.
- Broader serial pipeline tests could not be collected in this environment: `psycopg2` is unavailable. Full Docker integration, PostgreSQL migrations, Windows external drive checks, UI build, E01/E02 extraction and live job resume remain **unverified**.

## Rollout
1. Back up live project including `.env` (not included in this release), database, volume metadata and relevant case state. Preserve original evidence read-only.
2. Pause/quiesce the affected job and stop old parser worker *after* safe checkpoints; do not launch duplicate extraction.
3. Merge updated sources, preserve production credentials, rebuild the API/worker/frontend images as appropriate.
4. Verify parse-stage row counts in `job_artifacts`; invoke the application's standard job resume. Confirm Phase 5 advances only when no pending native parse files remain.
5. Confirm downstream recovery, OCR, inventory, RAG, validation and report evidence citations; review exception counters.
