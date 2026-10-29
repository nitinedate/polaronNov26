# Polaron3 V1.6.1: Greenbone terminal-state and scan-scope correction

Date: 2026-10-14. Based on the complete user-supplied Polaron3 V1.6.0 package.

## Failure reproduced in source

* A `HIGH_PROGRESS_STALL_SEC` setting missing from Compose defaulted inside Python to 45 seconds. A stationary 90%-99% task could be harvested while still running.
* `seal_tail_harvest()` previously rewrote a running task/report as `done` / `assessment_complete=True`, scheduled `stop_task()` asynchronously, and uploaded a report containing only the findings produced up to that point. The asynchronous stop could time out *after* an HTTP 200 result upload.
* `200 OK` on result upload proves acceptance of the submitted report, not that all requested NVTs or 52 service families were checked.

## Corrections

1. `HIGH_PROGRESS_STALL_SEC` defaults to 0, including the Compose-provided scanner-agent environment. An explicitly nonzero diagnostic threshold NEVER converts a running task to Done or cancels it.
2. `seal_tail_harvest()` is fail-closed; no partial report can become terminal by a progress heuristic. The pipeline waits for the native GMP terminal state. Existing explicit per-IP/runtime budgets remain available for intentional *partial* assessments.
3. The background `stop_task()` call from high-progress tail harvesting is removed. State-aware cancellation remains available for intentional timeout, LAN departure, and lost-job cases.
4. The central server's progress message distinguishes "Engine complete - service coverage unverified" from assessment verified.
5. The log distinguishes `assessment_complete` from `service_checks_verified`, preserving source NVT results and severity.
6. Adds `python -m agent.audit_scan_policy` to check the configured catalog port hints without falsely claiming NVT execution.

## Audit and testing

- `166` laptop-scanner tests passed.
- `7` focused backend tests passed. Broader database-dependent tests were not run because `psycopg2` is unavailable in this sandbox.
- Python compilation and Compose YAML parsing passed.
- Policy self-audit for `PORT_PROFILE=full`, `UDP_PROFILE=priority` confirms all 52 configured families have their port hints in scope: 65,535 TCP ports and 30 priority UDP ports under effective scanner defaults.
- **No live Docker, Greenbone, target network, NVT execution, or HTTPS test was performed.** Greenbone readiness and native NVT checks must be confirmed on the scanner host. Full UDP 1-65535 requires explicitly setting `UDP_PROFILE=full` and considerably more time.

## Upgrade on the laptop (PowerShell)

Back up `C:\Users\Public\laptop-scanner`, wait until scans and uploads complete, and merge the updated laptop-scanner directory. Keep your private `.env`, certificates, agent token, and Docker volumes.

Recommended .env overrides for uncapped full-service execution:

```ini
SCAN_IP_BUDGET_SEC=0
MAX_SCAN_RUNTIME_SEC=0
HIGH_PROGRESS_STALL_SEC=0
PORT_PROFILE=full
UDP_PROFILE=priority
GVM_OPTIMIZE_TEST=no
```

Then run:

```powershell
cd C:\Users\Public\laptop-scanner
docker compose config --quiet
docker compose build scanner-agent
docker compose up -d --no-deps scanner-agent
docker compose exec -T scanner-agent python -m agent.audit_scan_policy
docker compose logs --tail 150 scanner-agent ospd-openvas gvmd
```

The policy audit checks the *requested* ports and 52-family catalog. It is not native proof that every service was reachable, that authenticated checks ran, or that OpenVAS has covered every vulnerability.

## Upgrade on the central server

Back up the existing project and install the complete Polaron3 archive, keeping private production config, certificates, evidence and Docker volumes. Validate using `script_docker/start_docker_prod.cmd -ValidateOnly` and deploy through your usual maintenance process. Central backend changes are necessary for the corrected completion message.

## Interpretation

A host with only three observed TCP endpoints will not legitimately have 52 positively verified service families. Unreachable, closed, not applicable, credential-required and untested conditions must remain distinct. Native results may show Medium/Low findings while full service coverage is unverified. Never manufacture Critical/High findings or mark untested services as passed.
