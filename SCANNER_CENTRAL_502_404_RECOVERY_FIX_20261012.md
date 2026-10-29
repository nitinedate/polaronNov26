# Scanner central 502 / job 404 recovery (2026-10-12)

## Changes
- The laptop agent no longer treats one `PATCH /jobs/{id}` 404 as authorization to stop local OpenVAS tasks. It continues to poll and preserves running tasks.
- Central API logs `edge_job_progress_not_found` with `scanner_mismatch` or `absent_in_tenant_schema`, enabling an operator to identify wrong scanner IDs, tenant routing and deleted/missing rows. The client continues to receive the original 404 without disclosure of other scanner identifiers.
- Existing HTTP timeout and 502 backoff behavior remains unchanged.

## Required verification
1. Confirm the correct `CENTRAL_API_URL` is configured: logs use 122.179.140.167 but the earlier production deployment referenced 122.179.141.248.
2. Restart the central API and the laptop scanner-agent after deploying matching versions; do not delete volumes.
3. Inspect the central API log for `edge_job_progress_not_found` and its reason. Fix scanner registration / tenant schema / actual job existence accordingly.
4. Confirm the scanner retains local GVMD tasks when progress PATCH fails and that the job results eventually arrive on the central server.
5. The original 502 requires separate reverse-proxy and upstream health diagnosis. This patch mitigates client behavior; it does not cure an unhealthy server.

## Limitations
When the job is genuinely gone, results submission can still fail. Do not claim a successful central scan without persisted evidence. This patch favors preservation of local activity over destructive cancellation and is not a replacement for durable offline result spooling and explicit job-reconciliation API.
