# Scanner Engine / Coverage UI v1.6.0

Updated from laptop-scanner v1.5.9 and central Polaron v1.5.5.

## What changed

- The central server now parses real release-build strings such as `1.5.9+v47.2` rather than incorrectly labeling them `legacy (pre-V45.4)`. The displayed build for historical jobs is also corrected on read.
- The React scan-details and job-list views distinguish **processing complete (100%)** from **service coverage verified**. An incomplete assessment gets an amber status, without hiding already captured findings.
- The scanner disables the automatic 600-second per-IP cutoff **by default**; a positive `SCAN_IP_BUDGET_SEC` is now explicitly opt-in and logged with a partial-coverage warning. Existing `.env` values take precedence: change `SCAN_IP_BUDGET_SEC=600` to `SCAN_IP_BUDGET_SEC=0` to receive this benefit.
- Default `MAX_SCAN_RUNTIME_SEC` in the laptop scanner Compose file is now `0` (not limited). An explicit positive value still bounds runtime. Do not remove real operator-enforced scan windows.
- A multi-lane aggregator no longer calls a combined scan `completed` when another lane failed/stopped. It preserves known findings and incomplete evidence. Current default uses one Greenbone task per IP with configurable concurrent service checks.
- Greenbone cancellation warnings distinguish a GVMD task-state lookup timeout from a stop-command timeout. An old stop request can still time out under GVMD load; this cannot be guaranteed away.

## Evidence caveats

The screenshots from job `85b423d0-6b30-4dc6-b643-b808760016ee` show nine results sent successfully, but no evidence that all 52 families had executed vulnerability tests. The target was `192.168.0.163` (the laptop's own Wi-Fi IP in earlier diagnostics), not `192.168.0.164`. No vulnerability findings are fabricated and absent services are not marked tested.

## Safe deployment

1. Wait for active scan uploads and back up central and laptop project directories.
2. Keep the existing private `.env`, certificates, evidence and persistent Docker volumes; the release packages intentionally exclude runtime secrets and evidence.
3. Update central Polaron code **and** laptop agent code to align UI with scanner evidence.
4. On laptop update `.env` explicitly: `SCAN_IP_BUDGET_SEC=0`; optionally `MAX_SCAN_RUNTIME_SEC=0`.
5. Rebuild only changed Docker application images; do not delete Greenbone feed or PostgreSQL volumes.
6. Confirm the configured `CENTRAL_API_URL` still points to the actual running production server. Do not blindly replace 122.179.140.167 with 122.179.141.248.
7. Rerun a scan of explicitly authorized IPs and compare native GVMD reports, task dates, port discovery evidence, and per-service status.

Validation: 161 scanner tests and 16 focused backend tests; modified TSX syntax parsed. Live Docker / GMP / React integration and a full npm build were not run in this environment.
