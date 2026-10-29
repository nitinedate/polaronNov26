# V1.9.9 — Resume no longer fails a job for IPs the earlier attempt already assessed

Agent build `1.9.9-v59.0` (cumulative: V1.9.1–V1.9.8) and the central update
`polaron-v1.9.9-update.zip` (cumulative: central V1.9.7–V1.9.8.1).

## Where the new fcbb90c0 message came from

1. First attempt (finished 5:28): 9 of 10 IPs assessed; 192.168.1.239's scan failed.
2. **Resume** requeued the job with its 10 targets and its OpenVAS task ids, and gave the
   agent the 9 assessed IPs (`assessed_hosts` in the job's orchestration data).
3. The agent, by design, does not rescan assessed IPs: it scanned only 192.168.1.239 and
   uploaded results for that one IP (finished 7:12).
4. The agent summarised that upload against all 10 targets — "OpenVAS finished but
   assessed 1 of 10 target(s)" (agent `_merge_chunk_details`) — and the central ingest
   (`ingest_agent_results` → `evaluate_edge_ingest_verdict` in
   `backend/app/services/scanner_agent_jobs.py`) took the assessed list from this upload
   only, added "OpenVAS report has no assessment evidence for target(s): <the 9 IPs>",
   and set the job to failed. It also overwrote the job's stored assessed list with the
   one IP. The findings of the 9 IPs were not lost: findings are upserted, never deleted.

## Changes

**Agent:** when the job carries IPs assessed by an earlier attempt, the upload counts them
as assessed (`assessed_hosts`, `hosts_assessed`) and lists them as
`assessed_in_earlier_attempt`. Only IPs of this job's target list are counted.

**Central:** when a resumed job's results arrive (`edge_resume_requested`), the IPs the
earlier attempt assessed — taken from the job's own stored data, limited to its targets —
are added to the assessed list before the verdict, and their per-IP coverage is kept.
A fresh-OpenVAS retry clears that list first, so nothing carries over there. An IP that
no attempt assessed still counts as missing. Includes the central V1.9.8.1 scan-details
error message.

## Marking the existing job fcbb90c0 as completed (PostgreSQL)

The job was ingested before the fix and its stored assessed list was overwritten, so it
must be changed by hand. Check first that exactly one job matches:

```sql
SELECT id, status, error FROM vuln_scan_jobs WHERE id::text LIKE 'fcbb90c0%';

BEGIN;
UPDATE vuln_scan_jobs j
SET status = 'completed',
    error = NULL,
    orchestration_json = COALESCE(j.orchestration_json, '{}'::jsonb) || jsonb_build_object(
        'assessed_hosts', COALESCE((SELECT jsonb_agg(t.target ORDER BY t.target)
                                      FROM vuln_scan_targets t
                                     WHERE t.scan_job_id = j.id
                                       AND COALESCE(t.excluded, false) = false), '[]'::jsonb),
        'assessment_complete', true,
        'completed_with_warnings', false,
        'partial', false,
        'partial_reason', NULL,
        'degraded_hosts', '[]'::jsonb,
        'not_assessed_hosts', '[]'::jsonb,
        'edge_progress', jsonb_build_object('pct', 100, 'message', 'Assessment verified')),
    completed_at = COALESCE(j.completed_at, NOW()),
    updated_at = NOW()
WHERE j.id::text LIKE 'fcbb90c0%' AND j.status = 'failed';
-- expect "UPDATE 1"; otherwise ROLLBACK;

-- Optional: make the stored evidence row agree, so Scan details does not show
-- "UNVERIFIED" for this job.
UPDATE vuln_scan_results r
SET hosts_assessed = sub.n,
    result_json = COALESCE(r.result_json::jsonb, '{}'::jsonb)
                  || jsonb_build_object('assessed_hosts', sub.hosts, 'assessment_complete', true)
FROM (SELECT j.id AS job_id, count(t.*) AS n, jsonb_agg(t.target ORDER BY t.target) AS hosts
        FROM vuln_scan_jobs j
        JOIN vuln_scan_targets t ON t.scan_job_id = j.id AND COALESCE(t.excluded, false) = false
       WHERE j.id::text LIKE 'fcbb90c0%'
       GROUP BY j.id) sub
WHERE r.scan_job_id = sub.job_id;
COMMIT;
```

This records all 10 IPs as assessed, which matches what happened: 9 in the first attempt,
192.168.1.239 in the resumed one. Findings are not changed and the job is not marked clean.

## Upgrade

Laptop (no scan running): extract `laptop-scanner-v1.9.9-update.zip`, run
`Apply-Scanner-v1.9.9.cmd`. Central: extract `polaron-v1.9.9-update.zip`, restart the
backend (`api`), rebuild/redeploy the frontend.

## Testing

Agent: 425 tests pass, three runs (3 new: a resumed upload counts the earlier attempt's
IPs; without them the job is still incomplete; IPs outside the job's targets are
ignored). Central: 118 pass in the scanner test set (3 new ingest tests for the resumed
fcbb90c0 shape — the main one fails without the fix); the same 8 unrelated failures as in
V1.9.7/V1.9.8. Upgrade script re-run against the stub `docker.exe` scenarios.
