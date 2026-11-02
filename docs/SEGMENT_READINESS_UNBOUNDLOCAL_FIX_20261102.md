# Polaron Get segments HTTP 500 - segment_readiness UnboundLocalError (2026-11-02)

## Confirmed root cause

`POST /api/jobs/{job_id}/evidence/ingest-path` enters `app.services.host_evidence.register_segments()`. Previously, the `already registered` branch contained:

```python
if normalized_paths and all(item in existing_by_path for item in normalized_paths):
    from app.services.disk import segment_readiness
    ...
```

`segment_readiness` was **already imported at module scope**. In Python, *any* import of a name anywhere within a function makes that name local throughout that function. For a newly registering directory, this conditional branch is not executed, so the later `sr = segment_readiness(ev)` (previously line 3318) raised `UnboundLocalError` and FastAPI responded HTTP 500. This is a language scoping bug, not a damaged E01 segment.

## Patch

- Removed the conditional re-import inside `register_segments`. All code paths now use the existing module-level `from app.services.disk import SEGMENT_RE, segment_readiness, segment_key` import.
- Preserved previously fixed source-directory-scoped readiness, idempotent re-registration, folder-listing, and extraction owner code.
- Added `backend/tests/test_segment_readiness_scope_20261102.py` with real E01/E02-style test files in separate directories, in-memory PostgreSQL stubs, first-time registration, repeated registration, preservation of source identity, and a source-code regression assertion.

## Verification

From `backend/`:

```sh
PYTHONPATH=. pytest -q \
  tests/test_host_evidence_paths.py \
  tests/test_get_segments_progress_v63.py \
  tests/test_multi_directory_identity_20261102.py \
  tests/test_multi_directory_extract_20261023.py \
  tests/test_next_evidence_directory_20261023.py \
  tests/test_folder_list_nameerror_20261102.py \
  tests/test_registration_status_20261102.py \
  tests/test_segment_readiness_scope_20261102.py \
  tests/test_extraction_owner_recovery_20261102.py \
  tests/test_hostdrive_agent_refresh.py \
  tests/test_case_export_registration.py \
  tests/test_standard_extraction_filter.py
```

Result: **171 passed**. Python syntax compilation also passed.

Wider legacy test runs had failures unrelated to this patch, including assertions that expect older UI text or removed agent behavior, and the local test environment lacks the optional `zstandard` package. A real Docker/PostgreSQL/MinIO/Celery/E01 end-to-end test has **not** been run; do not treat unit tests as production verification.

## Deploy safely

1. Back up the deployed project configuration and source tree, **not** the evidence data. Prefer the small patch ZIP for a production hotfix. Replace `backend/app/services/host_evidence.py` from the patch at the same relative path. Do not change `.env`, PostgreSQL, Redis, MinIO, case folders, or E01 files.
2. Check current workers before restarting them:

```sh
docker compose ps api worker-disk worker-progress
docker compose exec worker-disk celery -A app.celery_app.celery inspect active
```

3. Rebuild the API service actually serving `/app/app/services/host_evidence.py`. Restart the worker image later **only when it is idle**, because worker-side automatic registration imports the same module:

```sh
docker compose up -d --no-deps --build api
```

4. Verify the deployed module is fixed:

```sh
docker compose exec -T api python -c "from app.services.host_evidence import register_segments; print('segment_readiness' in register_segments.__code__.co_varnames)"
```

Expected: `False`. If `True`, the API is still running an older copy or a bind-mounted source file is overriding the image. Inspect:

```sh
docker compose exec -T api python -c "import app.services.host_evidence as m; print(m.__file__)"
docker compose logs --tail=100 api
```

5. Retry **Get segments** on the existing job. A first-time directory should register its E01/E02 segments; a previously registered directory should return an idempotent result. The second directory must be counted independently, even if the E01/E02 names match. If an E01 worker is idle and worker images were rebuilt too, restart the worker(s) under your usual maintenance procedure before extraction.

## Do not

- Do not delete/recreate an existing case or job to fix this Python scoping error.
- Do not clear locks, Redis, SQL tables, MinIO, or temporary extraction checkpoints without inspecting ownership.
- Do not rename, move, or alter the original forensic evidence files.
