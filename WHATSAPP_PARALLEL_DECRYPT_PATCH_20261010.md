# WhatsApp bounded parallel decryption patch — 2026-10-10

Modified backend/app/services/mobile_forensic/whatsapp_derivation.py:
- Cryptographic analysis of already-registered backups now runs in up to two concurrent threads (WHATSAPP_DECRYPT_WORKERS=1..2); database access and writes stay on the owning stage/session thread.
- At most two backup inputs can be prefetched at a time. The producer verifies original byte count and SHA-256 against acquisition metadata before attempting decryption; the consumer persists outputs in deterministic source order.
- Native CRYPT12/14/15 support, authorized matching-key handling, external-tool fallback, authentication validation, derived evidence metadata, and report coverage limitations remain in place.
- Paused jobs stop before committing the next result. Originals are preserved; missing or incorrect keys remain marked blocked, never artificially successful.

Tests: 18 passed, 5 skipped in a dependency-limited test selection. The full cryptographic round-trip suite requires pycryptodome (Crypto package), not present in the validation environment. Complete Docker/database integration and representative 85-GB throughput benchmark were not run.

## Limitation — full pipeline parallelism
The 13-stage controller still serializes whole stages using one active-stage PostgreSQL index and an advisory lock. Removing either without redesigning stage readiness / idempotent writes / DB resource coordination would risk premature completion and evidence loss. This patch overlaps bounded WhatsApp cryptographic work with source reads and writes, but DOES NOT establish extraction/parse/OCR/graph stage overlap across the entire application. That work remains outstanding. Do not claim the 90-minute SLA without testing on the target host and media.
