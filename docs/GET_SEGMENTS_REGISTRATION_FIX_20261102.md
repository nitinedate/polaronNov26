# Polaron — multi-directory Get segments registration repair (2026-11-02)

## Problem observed

On a job with two EWF evidence directories, the modal stopped at **Get segments** and said `Directory 1 of 2 ... was not registered. Extraction has not started.` Drive mount and List folder had succeeded. The screenshot itself does not contain the API's original exception, so the precise runtime failure (disk read, SQL, incomplete segments, gateway) cannot be established without server logs.

## Root cause confirmed in source

- In `HostEvidencePanel.tsx`, `registerPickedFolder()` swallowed the exception from `ingestAtResolvedPath()`, then returned `void`. The multi-directory loop replaced any detailed error with a generic directory failure.
- The frontend API client parsed `data.error` but **not** FastAPI's nested `detail.error` response, losing the actionable error code/message.
- The registration gate could accept any nonzero segment count, not all filenames chosen in a given directory. In single-directory mode the server could dispatch extraction before the client noticed partially accepted evidence.
- Gateway timeout recovery looked at the entire job's evidence count, which is unsafe for multi-directory jobs because Directory 2's records cannot prove Directory 1 was committed.

## Changes

1. Propagate the concrete registration exception and FastAPI error detail to the operator.
2. Send the selected filenames (`selected_names`) to `/evidence/ingest-path`. The server returns HTTP 409 `partial_segment_registration` before dispatching extraction if any selected segment is missing.
3. Add read-only `/api/jobs/{job_id}/evidence/registration-status` with request `{ "path": "G:\\Case\\image", "expected_names": ["image.E01", "image.E02"] }`. It only counts committed records under that source directory, never job-wide totals or identically named segments from another source.
4. On gateway timeout, query the source-scoped registration status before retrying. Do not trigger a drive remount on network timeouts. If the selected directory is only partly registered, show its exact missing segment names and do not start the combined job.
5. Add registration failure details to extraction logs for failed segment-level registration, including first error. Preserve committed registrations on retries.
6. Keep existing multi-directory extraction namespaces, sequential source extraction, merged MinIO index, progress and Redis ownership protections unchanged.

## Safe deploy

- Back up the job's database and retain all MinIO objects/checkpoints. Do not delete E01 files, re-create the job, clear Redis locks manually, or force an active extractor to stop.
- Apply the patch relative to the repository root (or use the complete source ZIP). **Keep your existing `.env`**, which is deliberately excluded from this delivery.
- Check active extraction first: `docker compose ps api worker-disk worker-progress` and `docker compose exec worker-disk celery -A app.celery_app.celery inspect active`.
- If no active extraction reader is present and restarting is safe, deploy the backend code: `docker compose up -d --no-deps --build api`. The API uses the `./backend:/app` bind mount in the provided compose file.
- Rebuild/redeploy the **actual running Enterprise Console frontend** used at `https://localhost/` (the `frontend` service in base `docker-compose.yml` has `legacy-ui` profile; rebuilding it alone may not update the UI you see). Its production build must include the new `frontend/src/` files and API client change.
- Test the same job again with the original two directories. The existing committed segments should be reused without duplicate hashing.

## Diagnostic after deploy

Check the failed request in Chrome DevTools Network: `/api/jobs/<job-id>/evidence/ingest-path`. Read its HTTP status and `Response` tab (not just Headers). A 409 `partial_segment_registration` now identifies missing segment names; a 400 `register_failed` identifies unreadable or invalid evidence paths. For API-side failures inspect:

```
docker compose logs --tail=200 api
docker compose logs --tail=200 worker-disk worker-progress
```

Do not share bearer tokens, full authorization headers, passwords, or evidence data from these logs.

## Tests and limitations

- 54 targeted tests pass, including original multi-directory and lock recovery tests, and tests verifying independent registration of sources with identically named E01/E02 fragments. Two newly added route checks are structural/source-order tests; live route integration is unverified because production psycopg2 is not installed in this isolated environment.
- Python syntax checks passed. TypeScript syntax was checked using the installed TypeScript compiler. A full frontend build was **not possible** because offline npm cache lacks a package (`yallist`); this is not a claim that the deployment build passes.
- Production filesystem, PostgreSQL, Redis, MinIO, gateway and actual E01-image behavior were not available for end-to-end testing.
