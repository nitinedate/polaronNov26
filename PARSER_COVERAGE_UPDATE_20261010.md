# Parser coverage update / limitations

Changes: `backend/app/services/mobile_forensic/parsers/forensic_fallback.py` and parser registration in `plugins.py`.

- Unrecognized binary file extensions now yield an evidence-linked `unclassified_file` artifact with SHA-256, metadata, signature classification, header sample and explicit unsupported status.
- EML and EMLX inputs within 16 MiB are parsed into `email_message` records with message headers, bounded text/HTML body previews and attachment metadata. Mailbox files have bounded per-message parsing.
- Parsers do not decrypt password-protected files, recover overwritten bytes, or automatically decode arbitrary proprietary binary formats.
- Header classification alone is not file-format parsing. Unsupported status is intentionally retained to distinguish recovered evidence from unexamined content.
- Artifact records are persisted through the existing `persist_artifacts` code path and exposed through the existing artifact browsing storage.

## Not completed

The extraction barrier and `pipeline_one_active_stage` index still enforce serialized stage execution. This patch does **not** implement extraction/parsing/OCR overlap or guarantee 85 GB per 90 minutes; doing so requires a migration to per-file durable work items, independent database sessions, a commit watermark and end-of-job barrier. The existing GPU OCR triage sidecar already permits limited concurrent classification. No full Docker/production benchmark was performed.

## Validation

Python compile checks, fallback artifact tests and email parsing tests passed locally. Full application integration tests not run.

## Operational notes

Do not put credentials, forensic acquisition images or WhatsApp recovery keys into source control. Review `.env` and evidence paths before deployment. Preserve original acquisition and record per-file parser exceptions for reprocessing.
