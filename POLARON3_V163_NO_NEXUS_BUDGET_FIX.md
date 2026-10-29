# Polaron V1.6.3 - Deprecated Nexus 600-second budget removed

## Root cause and behavior

Previously, `SCAN_IP_BUDGET_SEC=600` in a retained laptop `.env` triggered the
Nexus budget code in `scanner-agent/agent/main.py`: it harvested a running report,
stopped its service lanes, set `status=completed` and `progress=100`, and marked
its coverage `degraded_time_budget`. The resulting 100% was a forced stop, not
Greenbone NVT completion. The `stop_task` timeout observed afterward was a
consequence of cancellation, not the cause of missing tests.

**V1.6.3 removes that entire per-IP interruption path.** The old environment
variable is forwarded *only* to print `LEGACY_IP_BUDGET_IGNORED` if nonzero.
Even a preserved `SCAN_IP_BUDGET_SEC=600` cannot truncate an IP. Native GMP
terminal states still determine scan completion. Existing results are not
altered. A separate explicitly positive `MAX_SCAN_RUNTIME_SEC` remains a
job-wide operator safety ceiling; default `0` disables it.

The legacy PowerShell performance helpers were also updated to avoid restoring
fast port scope, optimize-test shortcuts, or a 2-hour global limit when invoked
in the future. They do **not** run automatically on upgrade.

## Service logging (carried forward from V1.6.2)

The scanner logs every requested service (52 `SERVICE_PLAN` lines per IP), every
service result (`SERVICE_RESULT`), native severity and CVSS (`SERVICE_FINDING`),
and an `SERVICE_AUDIT_END` summary. Every observation is evidence-backed;
`not-tested` is NOT clean or passed. Logs are both in `docker compose logs` and
durable JSONL under the scanner's existing `logs/ip` folder.

```powershell
cd C:\Users\Public\laptop-scanner
docker compose logs -f --tail 100 scanner-agent | Select-String 'SERVICE_PLAN|SERVICE_RESULT|SERVICE_FINDING|SERVICE_AUDIT|LEGACY_IP_BUDGET'
```

## CVSS severity classification

The default central server chooses CVSS v3 (configurable using
`VULN_SEVERITY_BASIS`; `cvss_v2` is special):

| Score | CVSS v3/v4 severity |
| --- | --- |
| 9.0-10.0 | Critical |
| 7.0-8.9 | High |
| 4.0-6.9 | Medium |
| 0.1-3.9 | Low |
| 0.0 | Info |

With `VULN_SEVERITY_BASIS=cvss_v2`, `9.0-9.9` is **High** and only `10.0`
is Critical. The laptop uses per-category `VULN_SEVERITY_*_MIN` thresholds,
which an operator can override. Port catalog priority is not CVSS severity.

## Safe laptop deployment

1. Wait for active Greenbone tasks and uploads to finish. Back up
   `C:\Users\Public\laptop-scanner` and `.env`.
2. Extract the new complete `laptop-scanner` archive into the existing folder;
   retain the installed `.env`, agent token, reports, logs and Docker volumes.
3. In the existing `.env`, set `SCAN_IP_BUDGET_SEC=0`,
   `MAX_SCAN_RUNTIME_SEC=0` (unless a deliberate global ceiling is required),
   `HIGH_PROGRESS_STALL_SEC=0`, `PORT_PROFILE=full`, `UDP_PROFILE=priority`,
   `GVM_OPTIMIZE_TEST=no`.
4. Run `docker compose config --quiet`, then
   `docker compose build scanner-agent` and
   `docker compose up -d --no-deps scanner-agent`.
5. Run `docker compose exec -T scanner-agent python -m agent.audit_scan_policy`
   to verify **requested** service scope (not native NVT completion).
6. Run new authorized scans and compare genuine per-service outcomes.

**Validation limitation:** Offline regression tests, Python compilation, Compose
YAML and ZIP integrity are available here. Windows Docker/GVMD integration,
network access, and actual execution of NVTs on a client LAN need live testing.
