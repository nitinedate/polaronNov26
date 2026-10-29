# V1.10.2 — "all vulnerabilities on one IP": silent IPs were shown as clean "Completed" scans

Agent build **1.10.2-v62.0** (same build as the Polaron policy). Central + laptop change; no migration.

## 1. What the job showed, and what it means

| IP | Shown | Behind it |
|---|---|---|
| 192.168.0.254 | Completed with warnings — open TCP 22, 80, 443; 2 C / 7 H / 25 M / 7 L | the gateway answered; its findings are on its own ports |
| .162 … .246 (10 IPs) | **Completed**, 1 note, 0 / 0 / 0 / 0 | **not assessed**: no open port and no TCP reset on any policy port, for both the agent's connect probe and Greenbone's SYN scan |

The findings are attributed correctly. If other hosts' results had been merged into .254, it would show their ports
(445, 3389, …). The 10 IPs simply never answered, so no unauthenticated scanner, Nessus included, can report a
vulnerability on them. That they read as clean "Completed" rows was the bug.

## 2. Bugs fixed

1. **The explanation was overwritten (central).** A late per-IP "completed" progress event, which carries a GMP task id
   that the classified row did not have, replaced "No exposed services … (firewall blocking or host offline)" with a
   bare "Completed" and kept the note. That is exactly the row in the screenshot, reproduced in
   `test_late_completed_event_keeps_the_not_assessed_explanation`. Rule now: once a host is classified, a later terminal
   event refreshes only its sequence and timestamp. A genuinely new task (scanning with another task id) drops the old
   verdict, notes and warnings.
2. **Silent IPs looked assessed.**
   - Their row now reads "No response - not assessed: none of N policy TCP ports answered (cause)".
   - The UI shows an amber **No response** badge and counts these IPs separately ("10 no response (not assessed)").
   - The job's assessment label becomes "NETWORK SCAN COMPLETE - 10 OF 11 IP(S) DID NOT ANSWER".
   - A job-level note says all findings come from the IPs that answered, and names them.
3. **The cause is now measured (laptop agent).** At the end of a job, each silent IP gets one ICMP echo.
   - **Answers ping** → the host is up and its firewall drops the scanner (`host_firewall`).
   - **No ping, and only the default gateway answered anything** → Wi-Fi client/AP isolation, a guest network or
     another VLAN (`client_isolation_suspected`).
   - **No ping, other hosts answered** → offline, or dropping everything (`no_answer`).
   - **Ping unusable** → no cause is guessed. This covers a ping that cannot be sent, and a control ping to
     192.0.2.1 (RFC 5737, can never answer) that "replies" because some virtual network stacks answer every echo.
     The build sandbox does this, which is how the guard was found.
4. **The pre-probe used the laptop's default port list (154), not the job's policy.** It now probes the job policy's
   own TCP ports, so for the Polaron policy all 262 are probed and "none of N ports answered" is exact.

## 3. What to check on your network (before the next scan)

On the scanner laptop (PowerShell), for one silent IP and the gateway:
```powershell
ping 192.168.0.162
Test-NetConnection 192.168.0.162 -Port 445
Test-NetConnection 192.168.0.162 -Port 3389
Get-NetNeighbor -IPAddress 192.168.0.162 -ErrorAction SilentlyContinue   # MAC known = host present at layer 2
Test-NetConnection 192.168.0.254 -Port 443                                 # should succeed, as in the scan
```

| Result | Meaning | Fix |
|---|---|---|
| ping fails, no neighbour entry, laptop on Wi-Fi | client/AP isolation or guest SSID | scan from a wired port (or a non-isolated SSID) on the same VLAN |
| ping OK, 445/3389 time out | host firewall drops the laptop (Windows Public profile or default deny) | set the network to Private/Domain or allow the scanner IP (File and Printer Sharing, Remote Service Management) |
| ping fails, neighbour entry present | host up, ICMP and TCP dropped | as above; it is the host firewall |
| no neighbour entry, other IPs on the LAN answer | the IP is not in use (old DHCP lease, device off) | remove it from the target list |

Credentialed (SMB/SSH) policies do not help until 445/22 is reachable from the laptop.

## 4. Files

- **Central:**
  - `backend/app/services/scanner_agent_jobs.py`: progress merge fix, `silent_hosts`, `silent_hosts_note`, row text, coverage flags
  - `backend/app/routers/vuln.py`: job note, assessment label
- **UI:**
  - `frontend/src/pages/vuln/ScanJobsPage.tsx`: No response badge, counts
  - `frontend/src/lib/types/vuln.ts`
- **Agent:**
  - `agent/reachability_diagnosis.py` (new)
  - `agent/main.py`: diagnosis at job end, `reachability` in the result, job-policy probe ports
  - `agent/port_discovery.py`: `discovery_plan(port_range=…)`
- **Tests:**
  - `backend/tests/test_silent_hosts_v1102.py` (6, new)
  - `laptop-scanner/scanner-agent/tests/test_reachability_diagnosis_v1102.py` (7, new)
  - `backend/tests/test_service_ports_v170.py`: the row text it pinned was changed on purpose

## 5. Verified / not verified

**Verified:**
- New tests pass; the screenshot rows are reproduced and fixed.
- Backend and root suites: the same failing set as the original upload (217 failed / 20 errors); 2,120 passed.
- Agent suite: 444 passed, with the same 2 failures as the original.
- `tsc -b` clean, and an injected error in the edited page was caught.
- `vite build --mode vuln` builds.

**Not verified:**
- A live scan on the 192.168.0.x network.
- ICMP from the scanner-agent container on Docker Desktop. If the container cannot send ICMP, the cause is reported
  as unknown rather than guessed.
- The UI in a browser.

**Which cause applies to your 10 IPs is not known from the screenshot.** The next scan with this build records it
per IP; the PowerShell checks above tell you immediately.
