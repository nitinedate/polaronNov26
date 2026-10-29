# OCR concurrent execution and inventory de-duplication

- OCR UI parallel-state updates now apply while materialize, parse, or recovery owns the serial stage, not recovery alone.
- Early OCR dispatcher marks the pending OCR stage with parallel activity and leaves the authoritative serial claim intact.
- Removed scheduling of the additional full catalog inventory sidecar during OCR. The final inventory stage still performs catalog generation once.
- Historical `ARTIFACT_INVENTORY`/TSK filesystem walk events from extraction are not the same operation as final catalog inventory. Existing logs remain intact.
- Parallel execution remains limited to existing sidecars and dependency checks; this change does not guarantee deadlock-free behavior without live DB/worker integration testing.
- Deploy only after checkpointing running cases; do not delete cases or MinIO/PostgreSQL volumes.
