# V77 - Single backend image build / worker image reuse

## Problem
BuildKit was exporting and unpacking `rag_new2-api:latest` repeatedly for `api`, `worker-rag-prep`, `worker-rag-gpu`, and other workers. Each worker had its own `build:` definition even though all of them used the same image tag.

## Fix
- Root forensic stack: only `api` owns the `rag_new2-api` backend build.
- `worker-disk`, `worker-parse`, `worker-quality`, `worker-rag-gpu`, `worker-ocr-gpu`, `worker-report`, `worker-agent`, `worker-progress`, `worker-beat`, and `worker-rag-prep` now reference `image: rag_new2-api` only.
- Android/iOS: removed `build:` from `x-app-common`; `api` now owns the single build while all workers inherit only the image/runtime configuration.
- Mobile-extract: only `api` owns the backend build; all workers reuse `rag_new2-api`.
- Mobile-extract API keeps the CUDA-compatible `TORCH_INDEX_URL` build arg so GPU OCR/RAG workers reuse a GPU-capable image.

## Expected behavior
`docker compose build --no-cache` may still build distinct images such as the frontend, but it must not independently export/unpack the same backend image once per worker.

## Regression guard
`backend/tests/test_v77_single_backend_build.py` validates one backend builder per stack and ensures worker services do not inherit `build:`.
