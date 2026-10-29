# Early OCR overlap patch - 2026-10-10

## Implemented
- Quality-triage task atomically claims early OCR dispatch while native parse is running.
- Existing OCR worker admits the early OCR drain during native parse or recovery.
- Dispatch goes to the platform-specific OCR queue; final authoritative OCR stage remains unchanged and drains any late candidates.
- On queue-publish failure the dispatch flag is cleared, permitting later retry.

## Known limits
- Complete extraction remains a mandatory finalized-manifest barrier before materialization and native parsing. Extraction/parsing overlap is NOT implemented.
- OCR scheduling overlap is not production-qualified without end-to-end PostgreSQL/Celery/GPU tests and heavy-source benchmarks.
- The stage controller still requires sequential authoritative stage completion.
- Backend OCR counter consistency must be checked on a real full evidence job.

## Test
`cd backend && python -m pytest -q tests/test_early_ocr_overlap_20261010.py tests/test_v57_parallel_quality_ocr.py`
Result in this environment: 9 passed. These are code-level tests, not full runtime integration tests.

## Do not change
Do not remove pipeline_one_active_stage while per-file durable leases, extraction batch manifests, and stage-specific checkpoints are absent.
