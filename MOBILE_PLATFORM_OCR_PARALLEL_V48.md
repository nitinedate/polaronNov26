# Polaron V48 - Mobile Platform Detection, Dynamic OCR Bucket, Parallel CPU/GPU Processing

## Scope
This build re-audits the attached Polaron central-server project for Android/iPhone mobile handling and updates the mobile report/OCR pipeline.

## 1. Mobile platform verification before platform agents run
- Added evidence-first Android/iOS verification in `mobile_platform_agents.py`.
- Strong Android markers include `msgstore.db`, CRYPT12/14/15, `/data/data/`, `/data/user/0/`, `packages.xml`, `build.prop`, `/storage/emulated/`.
- Strong iOS markers include `ChatStorage.sqlite`, `Manifest.db`, `Manifest.plist`, `/private/var/mobile/`, `AddressBook.sqlitedb`, `Library/SMS/sms.db`.
- Ambiguous mixed evidence does not guess.
- When evidence strongly disagrees with a stale/manual platform choice, the job owner/type is corrected to `android_mobile` or `ios_mobile`, `evidence_platform`/`axiom_platform` are updated, and an OS mismatch note is retained.
- `run_mobile_analysis_pipeline()` now verifies platform ownership before the platform-specific analysis run begins.

## 2. Mobile report alignment + Evidence Details
The mobile report continues to use the supplied report style/structure for:
- Mobile Forensic Analysis Report cover
- Introduction
- Tools Used for Acquisition and Analysis
- Device Information
- Extraction Summary
- Objective / Observation / Findings sections

A new visible **Evidence Details** page is inserted immediately after Extraction Summary for mobile reports only.

Evidence Details includes:
- detected/verified mobile platform
- acquisition/import mode
- evidence source ID
- files extracted/registered
- acquired package volume
- chain-of-custody reference
- acquired evidence/package filename, size, SHA-256
- detected evidence formats
- platform mismatch/verification note when applicable

The section is now visible consistently in UI preview, HTML/PDF, and DOCX mobile report exports. Disk reports keep their previous behavior.

## 3. Poor-quality evidence is routed during filtering
Added `backend/app/services/mobile_quality_ocr.py`.

While the mobile parse/filter queue is prepared:
1. Known cache/vendor/noise is excluded from expensive quality checks.
2. Evidence images are checked for clarity/blur.
3. PDF/Office documents are CPU-prepared; scanned/poor visual content is identified.
4. Videos are sampled at bounded source timestamps and poor frames are detected.
5. Poor files receive:
   - `metadata.ocr_quality_checked=true`
   - `metadata.ocr_quality_bucket=true`
   - reason / clarity score / video sample metadata
   - `ocr_status=pending`
6. Clear files are marked as quality-checked and are not sent to GPU OCR unnecessarily.

This quality gate starts before media is parse-skipped, so poor evidence is not lost when low-value/non-parser media is filtered out of CPU parsing.

## 4. Continuous OCR bucket behavior
The quality gate drains in batches through `mobile_quality_ocr_task` and requeues itself until the current mobile quality backlog is exhausted.

OCR behavior:
- Empty bucket: OCR reports 100% complete.
- New poor files arriving after 100%: they become `pending`; the denominator changes automatically and OCR progress falls below 100% until those files finish.
- No files: GPU OCR remains idle; it does not consume GPU work just to maintain the progress card.
- New queued evidence causes OCR dispatch immediately.

Quality-routed media bypasses the normal `OCR_DOCUMENTS_ONLY` camera-roll parking rule. This is deliberate: a poor evidence image/video explicitly selected by the quality filter must reach OCR.

## 5. Video OCR
`ocr_gpu.py` now accepts quality-routed video evidence.
- CPU/native stage samples a bounded number of video frames.
- Only poor frames are sent to GLM OCR.
- Clear sampled frames do not consume GPU OCR.
- OCR output remains linked to the source video artifact.

Configuration:
- `MOBILE_QUALITY_VIDEO_FRAMES=4`
- `OCR_VIDEO_MAX_FRAMES=6`

## 6. CPU + GPU parallelism
The implementation uses separate kinds of parallel work rather than allowing all stages to compete for the same resource:

### CPU processes / worker processes
- Mobile build workers already run multiple Celery worker processes.
- Mobile parse workers remain separate from build workers.
- Quality classification uses a `ProcessPoolExecutor` when the host process can safely spawn children.
- Under Celery prefork/daemon workers it falls back to bounded threads because daemonic workers cannot safely spawn child processes.
- OCR text-layer/CPU preparation already uses the same process-first/thread-safe fallback policy.
- `forensic_serial_policy.parallelism()` caps in-process parallel work to prevent CPU/RAM/thermal runaway.

### GPU
- Dedicated mobile OCR worker remains single-owner for CUDA/GLM OCR.
- CPU quality checks and parser workers can continue while the GPU OCR worker consumes poor-quality bucket items.
- Existing GPU heavy-slot and thermal guards remain in force.
- RAG and OCR stay on controlled GPU lanes to avoid VRAM contention.

### Native video work
- ffmpeg/ffprobe performs frame decode outside Python bytecode and benefits from native CPU parallelism.

This is safer than blindly multiplying parser processes because many forensic parsers use DB sessions, source streams, and provenance state that must not be shared unsafely across processes.

## 7. Performance indexes
Added migration `040_mobile_quality_ocr_indexes.sql`:
- partial index for unchecked mobile quality candidates
- partial index for quality-routed pending OCR artifacts

These indexes avoid full `job_artifacts` scans as mobile evidence grows.

## 8. Main changed files
- `backend/app/services/mobile_platform_agents.py`
- `backend/app/services/mobile_forensic/pipeline.py`
- `backend/app/services/mobile_quality_ocr.py` (new)
- `backend/app/services/artifact_parse.py`
- `backend/app/services/ocr_gpu.py`
- `backend/app/tasks.py`
- `backend/app/celery_factory.py`
- `backend/app/services/mobile_report_service.py`
- `backend/app/services/report_renderer.py`
- `backend/app/services/report_evidence.py`
- `backend/app/services/report_export.py`
- `backend/app/services/report_pdf_export.py`
- `backend/app/services/report_docx_export.py`
- `frontend/src/components/forensic/ReportDocumentPreview.tsx`
- `migrations/040_mobile_quality_ocr_indexes.sql`
- `.env.example`
- `backend/tests/test_mobile_v48_platform_ocr_report.py` (new)

## 9. Validation
Focused V48 validation completed:
- 10/10 new V48 platform/OCR/report tests passed.
- 19/19 compatible mobile report/catalog/private-acquisition regression tests passed (1 unrelated environment-sensitive test deselected).
- 37/37 compatible OCR regression tests passed (1 test requiring Celery in this host environment deselected).
- Mobile/disk shared report structure assertion passed after adding mobile Evidence Details.

The local execution environment does not contain every production Docker dependency (`celery`, `psycopg2`, `pycryptodome`), so tests whose import path requires those packages cannot be used here as an end-to-end Docker validation. The modified Python modules themselves compile successfully, and focused tests for the changed behavior pass.
