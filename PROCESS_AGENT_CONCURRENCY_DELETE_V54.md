# V54 - progressAgent completion, safe parallelism and Delete Job

## 99% completion repair
When a running stage has accounted for its full denominator, progressAgent now verifies authoritative pending/running tables. If no work remains it marks the stage done and immediately dispatches the next stage. If work remains, the stage card shows exactly what remains (parse claims, work units, OCR items, chunks, media observations or inventory items).

## Concurrency
The pipeline still has one authoritative write-owning stage at a time, preserving deterministic forensic ordering. Independent evidence units inside a stage can run concurrently. `FORENSIC_MAX_PARALLELISM` defaults to up to 8 CPU workers and is hard-capped at 16. Pure CPU RAG chunk generation now uses a spawn-based process pool; DB persistence remains in one authoritative writer. Existing mobile quality checks likewise use a process pool when safe. GPU-owning stages remain serialized so CUDA models do not compete for VRAM. Mobile quality/OCR background routing remains isolated from CPU parsing.

## Delete Job
Deletion now removes the database job first after a bounded stop/revoke phase. Neo4j, MinIO and local derived-file cleanup are best-effort after commit, so an unavailable secondary service no longer causes the UI delete operation to fail. Original examiner-selected evidence paths remain protected. Shared Celery worker processes are not terminated.
