# Laptop Scanner / Polaron V1.6.6 — fast scan mode, NVT timeout handling, stalled-task watchdog

Date: 2026-10-14. Cumulative on top of V1.6.5. New agent build: **1.6.6-v47.8**.

## 1. Where the time actually goes (from your field logs)

| Job | Host | Reached 94 % | Tail after 94 % | Total | Check timeouts |
|---|---|---|---|---|---|
| 57b12618 | 192.168.0.163 | 201 s | 46 s | 247 s | 0 |
| 50dba2dd | 192.168.0.164 | 326 s | 47 s | 373 s | 0 |
| 096705e1 | 192.168.0.163 | 185 s | 324 s, then cut at 600 s | 609 s | 1 |
| d26e3145 | 192.168.0.163 | 216 s | 324 s + 355 s | 895 s | 2 |

Every scan does the real work in about 3.5–5.5 minutes, about 2 minutes of it port scanning. A slow scan
is slow only because one check (NVT) hangs until the 320-second per-check limit, and the checks
that depend on it wait behind it: about 5.5 minutes per hung check.

## 2. What V1.6.6 changes

### Fast profile (`SCAN_PERFORMANCE=fast`, default on; per policy via **Speed**)
Every port and every check still runs. Only engine timing changes:

| Setting | Standard (1.6.5) | Fast | Reference |
|---|---|---|---|
| Socket read timeout (`checks_read_timeout`) | 10 s | 5 s | OpenVAS default 5 s; Nessus "network timeout" 5 s |
| Simultaneous checks per host | 4 | 5 | Nessus default 5 |
| Nmap timing policy | Normal (T3) | Aggressive (T4) | Nmap's recommendation for ethernet/LAN |
| Checks that already timed out ≥ 2 times in 30 days | 320 s | 120 s | learned per check, see below |

Fast mode uses its own Greenbone config clone (`Aetheris fast <hash>`). The Nmap "Timing policy"
preference is read from gvmd by name, not guessed. If gvmd rejects anything, the standard config is
used, which is slower but never narrower. The unscoped full config must still pass the
10,000-NVT floor, which shows that no checks were dropped.

### Learned NVT timeout caps (the hang fix)
- Every NVT timeout in a report is recorded in `logs\nvt_hang_stats.json`, with the NVT name, hosts and ports.
- A check that timed out `NVT_HANG_MIN_EVENTS` (2) times in `NVT_HANG_WINDOW_DAYS` (30) gets
  `NVT_HANG_CAP_SEC` (120 s) in fast mode. It still runs on every host; it just cannot hold a host
  for 320 s again.
- Port scanners (Nmap, Check Open TCP Ports), the "Services" detection check, "Ping Host" and web crawling/mirroring checks are **never** capped.
- The cap is written as gvmd's per-check timeout preference (`<oid>:0:entry:timeout`). This format was
  verified against the gvmd source, which forwards it to the scanner as that check's timeout.
- Each task's policy shows which checks were capped. The checks still report timeout warnings when
  they hit the cap, so nothing is silent.
- `Show-Hang-Stats.cmd` lists the offenders. `Show-Hang-Stats.cmd --reset <OID>` clears one.
  `NVT_HANG_CAPS=false` turns capping off.

### Stalled-task watchdog
A task is stopped only when it shows **no progress at all** for much longer than any single check may run:

| State | Default limit | Variable |
|---|---|---|
| Task never started (New/Requested/Queued) | 900 s | `SCAN_TASK_START_STALL_SEC` |
| Port scanning (< 10 %) | 3600 s | `SCAN_PORTSCAN_STALL_SEC` |
| Vulnerability checks (≥ 10 %) | 1800 s (5.6 × the 320 s check limit) | `SCAN_IP_STALL_SEC` |

When a limit is hit, the agent does four things:
- It logs `STALLED` and emits a `stalled` event.
- It stops that one task.
- It keeps the partial findings.
- It reports the host as **skipped: scan_stalled**, with the reason. The host is never marked completed.

Other IPs continue. Slow-but-moving scans are not touched: the tests include a task that sits on the
same percentage for about 22 minutes at a time and is not stopped. `0` disables a rule.
With this per-IP watchdog, the job-wide `MAX_SCAN_RUNTIME_SEC` should be `0`.

## 3. Expected effect
- **A check that hangs on every host** costs about 120 s instead of 320 s once it has been seen twice.
  For a host like d26e3145, with two such checks, the tail drops from about 11 minutes to about 4.
  Total time for that host drops from about 15 minutes to about 8 minutes, based on the field timings.
- **The first time a new check hangs**, it still costs the full 320 s, because learning needs two events.
- **The socket timeout, checks per host, and Nmap T4 changes** should shorten the 3.5-minute main phase,
  especially on firewalled hosts. **This has not been measured.** Compare `duration_sec` before and after.
- **A scanner that is truly stuck** now ends at the stall limit with an honest "stalled" result,
  instead of running forever.

## 4. Quality trade-offs, stated plainly
- 5 s read timeout, 5 checks per host and Nmap T4 are the Nessus/OpenVAS/Nmap defaults for LAN scanning.
  On a slow WAN or VPN link, use `SCAN_PERFORMANCE=standard`.
- A capped check that would have finished between 120 s and 320 s on some host loses that result.
  Such checks are listed in the task policy and keep reporting timeout warnings. Raise `NVT_HANG_CAP_SEC`
  or set `NVT_HANG_CAPS=false` if a capped check matters to you.
- A stalled host is reported as skipped (stalled), never as assessed or clean.

## 5. Upgrade (laptop, PowerShell)
1. Wait for running scans to finish, then back up `C:\Users\Public\laptop-scanner`.
2. Extract this package over the folder. Keep `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`.
3. In `.env`, add or change:
   ```ini
   SCAN_PERFORMANCE=fast
   MAX_SCAN_RUNTIME_SEC=0
   SCAN_IP_BUDGET_SEC=0
   PORT_PROFILE=nessus
   GVM_OPTIMIZE_TEST=yes
   ```
   Your current `.env` has `MAX_SCAN_RUNTIME_SEC=3600`. That stops an entire multi-IP job after one hour.
4. Apply:
   ```powershell
   cd C:\Users\Public\laptop-scanner
   docker compose config --quiet
   docker compose build scanner-agent
   docker compose up -d --no-deps scanner-agent
   docker compose logs --tail 100 scanner-agent | Select-String '1.6.6|Fast scan config|NVT_TIMEOUT|STALLED|quality profile'
   .\Show-Hang-Stats.cmd
   ```
The central overlay adds the **Speed** option to scan policies and speed details to Scan details. No database migration is needed.

## 6. Testing
- Laptop agent: **243 passed**, 22 of them new. The new tests include the real job loop with a fake
  clock: a frozen task is stopped and reported `scan_stalled` with its partial findings kept, and a slow
  but advancing task is not stopped.
- Central focused suite: 72 passed. The same 4 failures are pre-existing in the original package.
- Frontend: no type errors in the changed files; `vite build --mode vuln` succeeds.
- **Not tested live:** gvmd accepting the fast config clone, the Nmap Timing policy preference,
  per-NVT timeout caps, and real-world speed gains. Look for these log lines:
  - `Fast scan config ... N NVT timeout cap(s), Nmap timing Aggressive`
  - `quality profile ... checks_read_timeout=5s`
