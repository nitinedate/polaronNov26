# Mobile priority-process simplification (2026-10-19)

## Implemented
- Android/iOS mobile normalization no longer invokes `mobile_priority_coverage`, an extra priority-family counting pass over already-normalized evidence.
- Existing `persist_coverage_snapshot` remains authoritative for inventory and acquisition limitations.
- Mobile parsing, deleted/recovery stage, WhatsApp crypt/key handling, link attribution, artifacts, RAG and OCR remain enabled.
- Priority *queue ordering* is retained: this only schedules which source bundle runs first; it is not a separate evidence-processing stage.
- Historical Priority Evidence API/UI and existing database records remain available. No data is deleted or retroactively recategorized.

## Review of other mobile phases
- Acquisition/source manifest: keep, necessary for source and completeness controls.
- Native parsing and app-specific decoders: keep; benchmark overlapping parsers before consolidating.
- Deleted/recovery: keep; it provides distinct evidence.
- OCR and image/video: conditional based on matching evidence, but record skipped/inaccessible sources.
- Correlation and normalized artifact inventory: keep; deduplicate identical source scans, not source records.
- RAG chunks/indexes: keep; selectively chunk supported content, avoid duplicate text chunks.
- Entity enrichment and graph synchronization: optional after coverage equivalence tests.
- Progress/completeness gate: keep; processing 100% is not acquisition 100%.

## Important boundaries
- This is a small, conservative removal of redundant *mobile priority coverage* work, not removal of core mobile decoding. Eliminating `bundle_priority` would remove a useful scheduling order, not a processing pass.
- Existing mobile Priority Evidence views may show historical/derived classifications; use authoritative coverage and evidence-level provenance for completeness claims.
- Do not restart in-flight mobile workers without a safe checkpoint, DB/MinIO backup and controlled resume.
- Automated source-level tests only. Full PostgreSQL/Docker/Android/iOS integration and frontend build are not verified here.
