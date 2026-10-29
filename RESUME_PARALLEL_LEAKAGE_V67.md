# Polaron V67 — Restart Resume, Safe Parallelism, Leakage Evidence, Fast Artifact Browse

## 1. Power-loss / laptop-shutdown resume

The serial forensic controller already persisted per-artifact state (`parse_status`, `ocr_status`, OCR results, RAG chunks, stage/work-unit rows). V67 adds startup recovery around those checkpoints.

On API restart V67:

1. finds non-terminal jobs owned by that Disk/Android/iOS service;
2. identifies an abandoned `running` / `queued` serial stage;
3. supersedes only its stale Celery delivery ID;
4. resets only abandoned work claims to `pending`;
5. preserves completed extraction, parsed rows, OCR results, chunks, recovered artifacts and evidence hashes;
6. dispatches the same stage again;
7. the stage queries only unfinished artifacts and continues from that checkpoint.

Example: if OCR had 10,333 / 11,377 complete when the laptop stopped, completed OCR rows remain. After restart the OCR stage re-enters and drains the remaining eligible poor-quality bucket; it does not intentionally OCR the first 10,333 again.

Stale parallel sidecars are also recovered after restart. Their durable outputs remain in their own tables, so pre-chunking and leakage detection continue incrementally.

## 2. Performance: resource-aware parallel pipeline

The process agent retains one authoritative serial stage, but V67 uses safe sidecars where resource ownership does not conflict.

During **Deleted / recovery analysis**:

- Recovery remains authoritative (CPU/I/O).
- Native-text pre-chunking can run in parallel (CPU/DB).
- CUDA is left free for the configured OCR overlap path.

During **GPU OCR**:

- GPU OCR owns CUDA.
- Pre-chunking runs on CPU/DB.
- Company-leakage text correlation runs on CPU/DB.
- Artifact inventory can run on CPU/DB.
- Media vision review does not start concurrently because it would compete for the same GPU/vision resources.

During **Media review**:

- no additional heavyweight GPU sidecar is scheduled.
- final leakage delta is evaluated later after visual observations are available.

This is intentionally resource-class aware rather than simply increasing every worker count.

### OCR performance change

V67 restores the requested policy: CUDA OCR is only for items explicitly routed into the poor-quality/scanned/unreadable bucket. Readable documents are handled by native parsers; clear images/video are handled by media evidence review. Before the serial OCR barrier, quality triage is drained so legacy broad OCR queues are demoted when the file is known to be clear.

Default tuning in the supplied Compose files:

- `QUALITY_TRIAGE_CPU_WORKERS=6`
- `QUALITY_TRIAGE_BATCH=1200`
- `OCR_BATCH_LIMIT=64` (still reduced dynamically by the thermal/performance governor when required)

## 3. New evidence artifact: Company Information Leakage

V67 adds an examiner-reviewable evidence family named **Company Information Leakage**.

It analyzes document/image/video evidence using already-derived information instead of rereading evidence unnecessarily:

- native document parser output;
- OCR output for poor/scanned material;
- image/video visual-review descriptions and visible text;
- mobile message attachment metadata where available.

High-precision evidence classes include:

- confidential/proprietary/trade-secret markings;
- customer/client data;
- commercial/pricing material;
- payroll/financial material;
- credentials/secrets/tokens;
- source code / architecture / technical IP;
- NDA/MSA/SOW and contractual material.

The detector identifies channels such as WhatsApp, email, Teams, Slack, Telegram, Signal, Discord and cloud-sync paths. For normalized mobile WhatsApp/chat attachments it also correlates `media_name` back to the message and preserves direction, sender, conversation and timestamp when available. An outgoing message therefore has stronger leakage context than an uncorrelated local file.

Every result is stored as a **candidate requiring examiner confirmation**, not as an automatic conclusion of misconduct.

The new family is available in:

- the main Artifact Scope under **Data Leakage Evidence**;
- Android/iPhone Mobile Artifacts under **Leakage evidence**;
- the normal family evidence dialog/search APIs.

## 4. Fast artifact indexes

V67 adds indexes for:

- `(job_id, extension, id)` artifact browsing;
- `(job_id, ocr_status, id)` OCR queues;
- partial quality-triage backlog;
- partial company-leakage candidate browsing;
- company-leakage risk/channel/type;
- GIN category and matched-term lookup;
- trigram leakage source-path/excerpt search when `pg_trgm` is available;
- mobile normalized artifact family;
- mobile attachment `media_name` lookup;
- mobile message application/direction lookup.

These avoid turning the new evidence checks into full-table scans on normal UI browsing.

## 5. Evidence integrity

- Source evidence is never modified by leakage detection.
- Resume logic resets only abandoned claims, not completed forensic output.
- Existing hashes/provenance remain authoritative.
- A leakage candidate remains pending examiner review until a human confirms context and meaning.
