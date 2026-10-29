# V1.10.1 — "no port answered" is no longer reported as a completed assessment from the wrong network

Agent build `1.10.1-v61.0` (cumulative: V1.9.1–V1.10.0). Central: `polaron-v1.10.1-update.zip`
(cumulative central V1.9.7–V1.10.0 plus this laptop-scanner copy; no backend change).

## Jobs 3df13145 vs 6bee3375

3df13145 (20 IPs) found open ports and 11 findings (4 Medium, 7 Low) on 192.168.1.x.
6bee3375 (25 IPs, the same IPs plus 5) recorded only 6 informational results per IP and the
note "No TCP port answered at all" on every IP — also on IPs where 3df13145 had open ports.
Two causes produce exactly this, and the job data tells which:

1. **Different networks.** The laptop that ran 6bee3375 was not on 192.168.1.x (other site,
   other Wi-Fi/VPN, or a queued job taken over by another online laptop — central lets an
   online laptop adopt jobs queued on a scanner that is offline for 3 minutes). Then nothing
   answers. The agent log line `Portable LAN fingerprint for job 6bee3375 ... subnet=` shows
   the laptop's network during that job.
2. **Different port lists.** 3df13145 ran an all-ports policy (Advanced/Exhaustive) and found
   services on ports outside the Full audit list; 6bee3375 ran Nexpose Full audit / Basic
   Network Scan (about 154 TCP service ports) and Windows firewalls dropped all of those. The
   agent probes only the policy's ports, so "No TCP port answered at all" overstated it.

## Changes

- **Unreachable-network guard.** When at least two IPs were scanned, none of them answered on
  any probed port (no open port, no reset) and none is on the laptop's own network (from the
  LAN fingerprint written by Start-Laptop; Docker's own networks do not count), the job is
  reported **failed** with: "Nothing was assessed: none of the N IPs answered on any probed TCP
  port, and none of them is on this laptop's network (<subnet>, gateway <gw>). Connect the
  laptop to the targets' network (or launch the scan on a laptop that is there) and run it
  again." Silent IPs on the laptop's own network remain a result (PCs off, firewalls).
- **Accurate per-IP note.** "None of the N TCP ports in this policy's port list answered (a
  firewall dropped them, or the host is offline). Ports outside the list were not probed: an
  all-ports policy (Advanced) may find services there. Credentials need SMB 445 / SSH 22
  reachable first."

## Find the policy, laptop and ports of both jobs (central PostgreSQL)

```sql
SELECT j.id, j.status, p.name AS policy, s.name AS scanner_that_ran_it,
       j.orchestration_json->>'edge_agent_version' AS agent_version,
       j.started_at, j.completed_at,
       (SELECT count(*) FROM vuln_scan_targets t WHERE t.scan_job_id = j.id) AS targets
  FROM vuln_scan_jobs j
  LEFT JOIN vuln_scan_policies p ON p.id = j.policy_id
  LEFT JOIN vuln_scanners s ON s.id = j.scanner_id
 WHERE j.id::text LIKE '3df13145%' OR j.id::text LIKE '6bee3375%';

SELECT left(j.id::text, 8) AS job, a.primary_ip,
       string_agg(DISTINCT f.port::text || '/' || COALESCE(f.protocol, ''), ', ') AS ports_with_results
  FROM vuln_findings f
  JOIN vuln_scan_jobs j ON j.id = f.scan_job_id
  LEFT JOIN vuln_assets a ON a.id = f.asset_id
 WHERE (j.id::text LIKE '3df13145%' OR j.id::text LIKE '6bee3375%')
   AND f.port IS NOT NULL AND f.port > 0
 GROUP BY 1, 2
 ORDER BY 2, 1;
```
`scanner_that_ran_it` is the laptop that executed the job (a takeover rewrites it). On that
laptop: `docker compose logs --since 48h scanner-agent | Select-String "LAN fingerprint for job (3df13145|6bee3375)"`.

## Testing

Agent: 435 tests pass (6 new: guard fails a job only when every IP is silent and off the
laptop's network; silent IPs on its own network, one answering host, unknown LAN, Docker NAT
fingerprint, self-scan and single-IP jobs are left as results; a completed payload becomes
failed with the reason). Upgrade script re-run against the stub `docker.exe` scenarios.
