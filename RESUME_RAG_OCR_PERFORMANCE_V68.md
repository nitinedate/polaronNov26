# Polaron V68 - Resume, RAG throughput, OCR reduction, and active handoff

## Fixed idle registered jobs
A registered evidence manifest is now treated as executable work. If the original Celery handoff is missed after registration, restart, sleep, broker reconnect, or service restart, progressAgent and startup recovery re-detect the mobile platform, select the correct Android/iOS queue, persist the new task id, move the job to processing, and mark Virtual disk as running.

## Restart/resume
Completed extraction, parsing, OCR, RAG chunks, leakage results, and artifact inventory rows are preserved. Only stale claims are reset and requeued. A user-requested pause remains paused; system pauses caused by thermal/capacity/restart dependencies can resume automatically.

## OCR reduction
V68 introduces the `v68-text-likelihood` OCR quality policy. GPU OCR is limited to evidence that both needs OCR and is likely to contain useful text. Clear images, readable documents, poor photographs without text, and videos whose sampled poor frames do not meet the threshold are kept as evidence but kept out of the GPU OCR queue. Legacy broad OCR candidates are re-triaged once under the new policy.

## RAG performance
- RAG fetch batches increased to 3000.
- CPU prep workers increased to 6 with dedicated `rag-prep` queues for Disk, Android, iOS, and legacy mobile-extract.
- Parsed text projection avoids bulky normalized JSON where useful text already exists.
- Latest parser result and latest OCR result per page are used instead of aggregating every historical attempt.
- Native and OCR text are de-duplicated before chunking.
- Duplicate chunk embeddings reuse one vector while preserving every original RAG row/provenance.
- 12 GB class GPU embedding ceiling raised to 64 with FP16 enabled when embeddings are enabled.
- Chunk size 3200 / overlap 240 lowers chunk count without removing source text.
- Serial RAG is now a large-batch delta finalizer (`RAG_CHUNK_DB_BATCH=6000`) instead of doing all work at the end.

## Safe parallelism
RAG pre-chunking uses CPU-only workers and runs only when it will not compete with source recovery I/O. Company leakage analysis may overlap recovery/OCR because it does not own CUDA. Admission control checks host CPU and memory before launching sidecars.

## Indexes
Added hot-path indexes for progress watchdog, pending OCR bucket, RAG unchunked artifacts, latest OCR page result, and RAG chunk lookup.

## Validation
- V68/V66/V65/V58 focused regression set: 33 passed.
- V57/V67/progress/mobile regression set: 27 passed.
- Python compileall: passed.
- Docker Compose YAML parse: passed for central, Android, iOS, and legacy mobile-extract.
