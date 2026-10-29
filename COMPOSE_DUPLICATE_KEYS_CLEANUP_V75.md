# V75 - Compose duplicate-key cleanup

## Problem
Startup failed because YAML service keys and top-level mappings were duplicated after prior performance worker insertions. Docker Compose correctly rejected the configuration, for example `worker-rag-gpu` appeared twice in the root compose file.

## Repairs
- Removed the second, byte-identical copies of these root services: `worker-rag-gpu`, `worker-ocr-gpu`, `worker-report`, `worker-agent`, `worker-progress`, `worker-beat`, and `frontend`.
- Kept the intended `worker-rag-prep` service exactly once.
- Repaired Android and iOS compose structure so `worker-rag-prep` remains under `services:` and removed duplicated `worker-rag`, `worker-ocr`, `worker-report`, `worker-progress`, `worker-beat`, and `frontend` definitions.
- Repaired mobile-extract compose structure so `worker-rag-prep` remains under `services:` and removed the accidental repeated tail containing `worker-progress`, `worker-beat`, `worker-ocr-gpu`, `worker-rag-gpu`, and `frontend`.
- Kept only the final intended top-level `networks:` block in each affected mobile compose file.

## Duplicate-key audit
All `docker-compose*.yml` and `docker-compose*.yaml` files in the repository were parsed as YAML node trees and recursively checked for duplicate mapping keys at the same mapping level.

Result: **25 compose files scanned, 25 passed, 0 duplicate mapping keys found.**

## Important validation note
The execution environment used for this repair does not have the Docker CLI, so `docker compose config` could not be executed here. The YAML duplicate-key and syntax audit passed. On the deployment host, run the normal startup validation; Docker Compose should no longer stop on duplicate service/mapping keys.
