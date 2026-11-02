# Polaron folder-list / Get segments HTTP 500 repair (2026-11-02)

## Root cause

The `/api/jobs/{job_id}/evidence/list-folder` endpoint calls `list_folder_contents()` -> `_log_folder_listing()` in `backend/app/services/host_evidence.py`. The function had this invalid self-call:

```python
if not skip_folder_list:
    listing = _log_folder_listing(db, job_id, folder)
```

`skip_folder_list` is a parameter of `register_segments()` **only**. The above line raised `NameError`, which FastAPI returned as HTTP 500. Defining the variable as `False` would instead cause infinite recursion. The failure happened before actual evidence segment registration.

## Changes

1. Removed the self-call from `_log_folder_listing`, leaving this operation as a leaf that logs and returns the folder listing.
2. Preserved `persist_job_evidence_folder` and the listing result (`entries`, `segment_count`, `segments`, `path`, `workers`).
3. Added `_folder_listing_completed_for_path()`, which checks the committed `disk_build_logs` completion metadata by **both job and exact source path**. The old job-wide `listing_complete()` flag cannot prove another folder was listed.
4. For a **new** registration, `register_segments()` logs a listing only when `skip_folder_list=False` and no successful listing exists for that same source. Resumes with `skip_folder_list=True` do not walk the directory again. The existing already-registered fast path remains read-only.
5. Added regression tests for the actual public listing service, no recursion, per-folder lookup, listing skip, and re-registration behavior.

These changes do not merge images with duplicate `.E01/.E02` names, do not clear MinIO or PostgreSQL state, and do not alter E01 bytes.

## Validation performed

Run from `backend`:

```bash
PYTHONPATH=. pytest -q \
  tests/test_host_evidence_paths.py \
  tests/test_get_segments_progress_v63.py \
  tests/test_multi_directory_identity_20261102.py \
  tests/test_multi_directory_extract_20261023.py \
  tests/test_folder_list_nameerror_20261102.py \
  tests/test_registration_status_20261102.py \
  tests/test_extraction_owner_recovery_20261102.py \
  tests/test_hostdrive_agent_refresh.py \
  tests/test_case_export_registration.py
```

Result: **74 passed**. Also checked `python -m py_compile backend/app/services/host_evidence.py`.

**Not run:** live end-to-end evidence registration with an E01 set, real PostgreSQL/MinIO/Celery/Windows Docker drive mount. Running that needs the deployed environment. Do not infer live success from unit tests.

## Deployment

Use the full updated project, or copy `backend/app/services/host_evidence.py` from the patch into the corresponding location of your deployed source tree. Keep your compose files, `.env`, PostgreSQL volumes, Redis/Celery state, MinIO objects, and evidence source directories unchanged.

1. **Check the current worker first**; do not restart if an E01 extraction is genuinely active:

   ```bash
   docker compose ps api worker-disk worker-progress
   docker compose exec worker-disk celery -A app.celery_app.celery inspect active
   ```

2. On a maintenance window with no active extraction, rebuild only the API service that runs `/app/app/services/host_evidence.py` (adapt Compose service name as needed):

   ```bash
   docker compose up -d --no-deps --build api
   ```

3. Retry **List folder / Get segments** for the existing job. The folder-list request should return HTTP 200 (possibly with `status: running` for background listing), not HTTP 500 for `skip_folder_list`. Expect `segment_count` for the selected folder, followed by independent per-source registration.

4. If it still fails, capture the **first** backend exception and the response status for:

   ```text
   POST /api/jobs/<job_id>/evidence/list-folder
   POST /api/jobs/<job_id>/evidence/ingest-path
   ```

   The genuine new exception will identify any further path/mount, database, or worker failure.

## Do not do

- Do not delete or recreate the original forensic job merely to resolve this `NameError`.
- Do not delete evidence_files rows or manually remove extraction locks.
- Do not clear MinIO, PostgreSQL, or Redis volumes.
- Do not change source evidence or move split E01 segments between folders.
