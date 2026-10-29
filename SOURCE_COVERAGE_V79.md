# V79: source limitations and processing completion

This release includes all V78 changes. The Android pipeline remains:
intake → source preparation → extraction → registration → parsing → recovery → OCR → media examination → inventory → RAG chunks → enrichment → graph → process validation → report.
Parallel producers must pass the V78 completion barriers before validation and reports.

The process validation stage now persists an evidence accessibility snapshot independently of finished work. The UI always shows source limitations, including after processing reaches 100%. Unknown source coverage is never displayed as full coverage. Specific limitations carry a source, reason and follow-up action.

WhatsApp key-required, blocked and partially decrypted source states automatically produce accessibility limitations. A successful authorized-key reprocessing run clears the corresponding current key limitation. Private app data gaps, inaccessible sources and explicitly documented overwriting remain visible through mobile coverage records and structured acquisition limitations. Zero records establishes a gap in this acquisition, not absence on the device or proof of overwriting.

Unsupported inventory items count as finished processing but retain unsupported-format exceptions. Failed and skipped parsing, extraction, OCR and media work remain in the snapshot. API polling reads only job-scoped summary rows; it does not scan all artifact or RAG records.

Report objectives and final analysis summary contain deterministic coverage disclosures. The final summary disclosure is appended after model generation and summary consistency passes, and its structured snapshot is saved with the report section. Report generation fails if this persistence step fails.

Acquisition integrations can record confirmed limitations in jobs.disk_source.source_limitations as objects with code (missing_key, private_app_data, overwritten, inaccessible, acquisition_gap, unsupported, processing_exception), source and optional resolved=true. Do not mark a limitation resolved without documented examiner verification. The application does not infer overwriting from unsuccessful recovery or generate unavailable keys. Existing report exports must be regenerated to include the disclosure; reprocess existing cases to refresh unsupported-format accounting.

No schema migration is required. Deploy the updated backend, restart relevant Celery workers, and deploy the Android frontend. Existing mobile_coverage and JSON fields hold the snapshots. This release does not recover inaccessible private data or guarantee recovery of overwritten bytes.

Validation: focused backend regression suite and Android TypeScript/Vite production build. No live database, device image, export rendering or SMTP delivery was available for integration acceptance.
