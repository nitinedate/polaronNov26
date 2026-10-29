# V74 - Docker Compose duplicate `volumes` fix

## Failure
Docker Compose stopped before startup with:

`mapping key "volumes" already defined at line 1109 ... line 1657`

`services/forensic/docker-compose.yml` includes the repository root `docker-compose.yml`, so the root schema error broke the forensic stack validation.

## Root cause
Performance worker definitions (`worker-rag-prep`, GPU RAG/OCR workers and related services) had been appended after an early top-level `volumes:` / `networks:` block. That prematurely ended the `services:` mapping, while the file later declared the real top-level `volumes:` and `networks:` again.

## Fix
- Removed the premature top-level `volumes:` / `networks:` block.
- Kept all worker definitions under the single `services:` mapping.
- Kept exactly one final top-level `volumes:` mapping.
- Kept exactly one final top-level `networks:` mapping.
- Added regression coverage so the root compose cannot reintroduce duplicate top-level sections and confirms the RAG/OCR workers remain services.

## Validation
- Root `docker-compose.yml`: PyYAML parse PASS.
- `services/forensic/docker-compose.yml`: PyYAML parse PASS.
- Android compose: PyYAML parse PASS.
- iOS compose: PyYAML parse PASS.
- V74 regression test verifies one top-level `volumes`, one `networks`, and required worker services.

Docker CLI is not installed in the packaging runner, so `docker compose config` itself cannot be executed here.
