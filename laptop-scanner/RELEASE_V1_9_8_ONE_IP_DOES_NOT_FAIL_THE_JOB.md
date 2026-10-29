# V1.9.8 — one IP that cannot be assessed no longer fails the job

Agent build `1.9.8-v58.0` (cumulative: V1.9.1–V1.9.7) and the central update
`polaron-v1.9.8-update.zip` (backend, scan-details page, and the laptop-scanner copy it ships).

## What job fcbb90c0 showed (10 IPs, 9 assessed)

The job was red "failed" for two reasons, both caused by one IP, 192.168.1.239, whose
OpenVAS scan failed part-way:

1. **"OpenVAS report has no assessment evidence for target(s): 192.168.1.239."** The agent
   had already skipped that IP with a stated reason, so its peers were not held up
   ("do not let one bad IP fail 49 healthy peers"), but the central server still counted
   any IP without report results as missing and failed the whole job.
2. **"report declares 241 result(s) but the agent uploaded 291 parsed row(s)."** A bug in
   the agent: when it skipped a failed or stalled IP, it kept that IP's partial findings
   (intentionally — they are real observations) but declared the IP's result count as 0.
   The job then carried 50 rows more than it declared, and the central result-integrity
   check failed the job. 291 − 241 = 50: 192.168.1.239's partial findings.

## Changes

**Agent:** the kept findings of a failed/stalled IP are declared with them (the count
OpenVAS reported for that IP, or the number of rows kept if none was read). Declared and
uploaded counts match again.

**Central:** when at least one requested IP was assessed and every IP without results is
explained by the agent — skipped with a reason (scan failed, stalled, stopped,
unreachable), stopped at the per-IP time limit, or "no response" — the job is
**completed, with warnings**. The warning names the IPs and why, e.g.
"1 of 10 IP(s) not assessed: 192.168.1.239 (scan_failed)". Their rows in Per-IP scan
activity still show what happened. Such a job is never marked clean. (This replaces the
amber "incomplete" from V1.9.7 for these cases.)

Still failed, unchanged: an IP missing from the report with no explanation from the agent;
a real result-count mismatch; a job in which no IP was assessed; a single-IP job whose IP
could not be assessed.

**Scan details:** for such a job the heading reads "9 of 10 IPs were assessed and their
findings are valid; a clean result is not claimed because:" followed by the not-assessed
IPs, instead of "The network scan finished for every host".

## Marking the existing job fcbb90c0 as completed (PostgreSQL)

This job was ingested before the fix, so it stays "failed" until changed by hand. Run in
the central database (e.g. `psql`), first checking that exactly one job matches:

```sql
SELECT id, status, error FROM vuln_scan_jobs WHERE id::text LIKE 'fcbb90c0%';

BEGIN;
UPDATE vuln_scan_jobs
SET status = 'completed',
    error = NULL,
    orchestration_json = COALESCE(orchestration_json, '{}'::jsonb) || jsonb_build_object(
        'assessment_complete', true,
        'completed_with_warnings', false,
        'partial', false,
        'partial_reason', NULL,
        'degraded_hosts', '[]'::jsonb,
        'edge_progress', jsonb_build_object('pct', 100, 'message', 'Assessment verified')
    ),
    completed_at = COALESCE(completed_at, NOW()),
    updated_at = NOW()
WHERE id::text LIKE 'fcbb90c0%'
  AND status = 'failed';
-- expect "UPDATE 1"; if anything else, ROLLBACK;
COMMIT;
```

The job then shows "Completed" with no error text. Its findings are not changed, it is not
marked clean (`clean_eligible` stays false), and 192.168.1.239's own row in Per-IP scan
activity still shows that IP's scan failed.

## Upgrade

Laptop (no scan running): extract `laptop-scanner-v1.9.8-update.zip`, run
`Apply-Scanner-v1.9.8.cmd`.

Central: extract `polaron-v1.9.8-update.zip` over the central install, restart the backend
(vuln `api` service) and rebuild/redeploy the frontend so the scan-details text changes.

## Testing

Agent: 422 tests pass (2 new: a failed IP's kept rows are declared, with and without a
count from OpenVAS; both fail without the fix, reproducing the 50-row gap). One of 16
full-suite runs had a single failure that did not recur in the other 15 runs or in 30
targeted runs of the new and thread-timing tests. `Apply-Scanner-v1.9.8.ps1` re-run against
the stub `docker.exe` scenarios.
Central: 25 verdict tests pass (5 new for job fcbb90c0's shape; 2 older tests updated
because they asserted the old rule that an agent-skipped IP fails the job; the test for an
unexplained missing IP still passes unchanged). The 8 unrelated central test failures
noted in V1.9.7 are unchanged. Frontend edits were syntax-checked with the TypeScript
compiler; a full type check needs the frontend's dependencies installed.
