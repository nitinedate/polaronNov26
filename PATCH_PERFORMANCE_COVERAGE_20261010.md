# Forensic processing patch — 2026-10-10

## Applied

- `frontend/src/lib/extractionLogView.ts`: show process/count/exception events, retain operational errors (Neo4j, SQL deadlocks, decrypt, missing-key), cap displayed history to 300 rows. No silent censorship of serious failures.
- `frontend/src/components/forensic/SerialPipelineBanner.tsx`: collapse detailed source-coverage explanations under a review control, without removing limitations or reporting unsupported sources as complete.
- `backend/app/services/forensic_serial_mobile.py`: fix cross-job progress throttling: independent (job,stage) timestamps, bounded map; increase SQL `execute_values` page size from 500 to 2,000 for inventory/normalized artifacts.
- `backend/app/services/neo4j_sync.py`: make graph parallel writes configurable (`POLARON_GRAPH_WRITE_SLOTS`, default 4, range 1–8) to reduce deadlocks/contention.

## IMPORTANT limits

- The authoritative stage controller is intentionally serial and guarded by a unique active-stage index. It is NOT safe to remove that index to overlap stages. File-level committed work queues, durable producer barriers, and new integration tests are needed before overlapping extraction/parse/OCR.
- The requested 85 GiB/90 min is a target, **not a benchmarked result**. No representative evidence, actual disks or running PostgreSQL/Neo4j stack are present in this execution environment.
- CRYPT headers do not reveal secret backup keys. No code claims to recover keys from encrypted ciphertext alone. Authentic authorized keys and correct source/app version are needed.
- Coverage or recovery exceptions must be accounted for and not silently marked successful.
- Python compile validation passed. Frontend package installation did not complete within the available execution time; no end-to-end runtime assertions are made.

## Deployment

Review diff and take PostgreSQL/Neo4j/evidence backups first. Test on a copied case, run backend and frontend CI, compare per-source evidence counts, and monitor memory/DB locks. Configure `POLARON_GRAPH_WRITE_SLOTS=4` on Neo4j worker containers; reduce to 2 if contention appears. Do not replace original evidence or reset processed stages without explicit examiner action.
