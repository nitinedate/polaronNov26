# Polaron V57 - Parse-time OCR triage + Recovery/GPU OCR overlap

## What changed

1. CPU-only quality triage starts when **Native forensic parsing** starts.
2. Poor-quality images/documents and sampled video frames are placed in the OCR bucket during parsing.
3. GPU OCR does **not** start during parsing. It starts when **Deleted / recovery analysis** starts.
4. Recovery (CPU/I/O) and OCR (CUDA) run in parallel using independent workers and idempotent artifact state.
5. The same behavior is enabled for Disk, Android, and iPhone services.
6. Dedicated quality workers were added so quality detection does not occupy parse workers.
7. OCR can run as a sidecar while recovery remains the authoritative serial stage; the UI exposes OCR as Running/Done without violating the one-active-stage database invariant.
8. Large evidence that cannot be safely read by bounded CPU quality triage is not silently discarded; it is routed to streaming OCR/media review.

## Runtime flow

Native forensic parsing
  -> CPU quality triage sidecar
  -> OCR candidate bucket

When recovery starts:
  Deleted/recovery analysis (CPU/I/O) || GPU OCR (CUDA)

After both:
  media observations -> inventory -> RAG -> enrichment -> graph -> validation

## New queues/workers

- Disk: `quality-triage`
- Android: `android-quality`
- iPhone: `ios-quality`

Default worker settings:
- `QUALITY_TRIAGE_CELERY_CONCURRENCY=2`
- `QUALITY_TRIAGE_CPU_WORKERS=2`
- `QUALITY_TRIAGE_BATCH=160`

These are intentionally conservative so parsing remains the priority. Increase only after observing host CPU and storage headroom.

## Performance rationale

- Parse workers no longer synchronously perform all quality analysis.
- Quality detection overlaps parse.
- Recovery overlaps CUDA OCR.
- GPU OCR remains single-owner to avoid CUDA memory contention.
- CPU triage has a separate worker pool and no GPU visibility.
- Video OCR remains frame-sampled instead of OCRing every frame.

## Validation

- Python compileall: passed.
- Docker Compose YAML parse: passed for central, Android, and iPhone Compose files.
- V57 + V48 quality/OCR focused tests: 16 passed.
- Existing `test_ocr_glm.py`: 37 passed, 1 environment-only failure because Celery is not installed in this runner.
