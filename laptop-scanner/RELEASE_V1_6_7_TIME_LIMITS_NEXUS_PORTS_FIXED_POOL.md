# Laptop Scanner / Polaron V1.6.7 — 15-minute IP limit, Nexus ports, fixed pool of 4

Date: 2026-10-14. Cumulative (includes V1.6.5 and V1.6.6). Agent build **1.6.7-v47.9**.

## 1. Why V1.6.6 was still slow (94 % after 30 minutes)

1. **The timing settings never reached OpenVAS.** I checked this in gvmd's source code
   (`manage_osp.c`, `init_preference_iterator`). gvmd forwards only `max_checks` and `max_hosts` from a
   task's preferences to the scanner. Every other scanner value comes from the scan config's own
   scanner preferences, or else from gvmd's global defaults. The agent had always sent `plugins_timeout`,
   `checks_read_timeout`, `optimize_test` and `safe_checks` as task preferences, so they were ignored.
   On top of that, `sync-scanner-timeouts.sh` raises the global per-check limit back to 320 s every 5
   minutes. Every hung check therefore still cost the full 320 s.
2. **V1.6.5 widened the default ports** from the 88-port Nexus catalog to the IANA TCP list. On a Windows
   host this finds extra listeners (for example HTTP-based Windows services), and each one brings a
   large set of extra checks.
3. **There was no hard per-IP limit**, only the 30-minute "no progress at all" watchdog. A scan that keeps
   advancing slowly at 94 % was never stopped.

## 2. What V1.6.7 does

| Change | Effect |
|---|---|
| `nexus` = Nexus service ports again (52 families, ~88 TCP + 30 priority UDP), and it is the default | Same scope as before V1.6.5. The wider scope is opt-in as `nessus` (IANA list) or `full`. |
| Scan settings are written as **scanner preferences on a scan-config clone** (`Aetheris profile <hash>`) | OpenVAS actually uses them. In fast mode: 120 s per check, 5 s socket timeout, optimize on, safe checks on. |
| Checks that timed out 2+ times in 30 days get **60 s** in fast mode | Repeat hangers no longer cost 320 s each. Port scanners, service detection and crawlers are never capped. |
| **Hard per-IP limit: 15 minutes** (`SCAN_IP_DEADLINE_SEC=900`, fast mode) | Every IP ends by about 15 minutes. |
| **Fixed pool of 4 IPs** (`SCAN_IP_WORKERS_FIXED=4`) | Exactly 4 IPs run at once; the next starts as soon as one finishes. The old sizing never went below 5. |
| Stuck-IP diagnostics | At 90 % or above with no progress for 5 min, the agent logs which NVTs OpenVAS shows for that IP (event `tail_activity`). |

### What a time-limited IP looks like
- **Port scan had finished (the normal case):** the IP shows **"Completed at time limit - stopped after 15 min
  at 94%; network scan finished, N open TCP port(s); …; service checks unverified"**. All findings are kept.
  The warning names the limit. The job completes. Clean result: **NO**.
- **The limit hit during port scanning:** the IP is **Incomplete** (`degraded_time_limit`) and is not
  automatically re-run.

### Where the 15 minutes come from (field timings on 192.168.0.163)
Port scan about 2 min, then checks up to 94 % about 1.5 min, then any hung checks at 120 s (or 60 s once
learned) instead of 320 s. A clean run should still take about 4 minutes. Hung checks are now bounded,
and anything still running at 15 minutes is stopped. With 4 IPs in parallel, the worst case is
**about 16 IPs per hour**. Typical throughput is higher.

## 3. Upgrade (laptop, PowerShell)
1. Let running scans finish, then back up `C:\Users\Public\laptop-scanner`.
2. Extract this package over the folder. **Keep** `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`.
3. In `.env`, set:
   ```ini
   PORT_PROFILE=nexus
   SCAN_PERFORMANCE=fast
   FAST_PLUGINS_TIMEOUT=120
   NVT_HANG_CAP_SEC=60
   SCAN_IP_DEADLINE_SEC=900
   SCAN_IP_WORKERS_FIXED=4
   MAX_SCAN_RUNTIME_SEC=0
   SCAN_IP_BUDGET_SEC=0
   GVM_OPTIMIZE_TEST=yes
   ```
   `SCAN_IP_PARALLELISM` / `SCAN_IP_MAX_PARALLELISM` are ignored while `SCAN_IP_WORKERS_FIXED` is above 0.
4. Recreate the agent. The Compose file now mounts the OpenVAS log read-only, so `up` must recreate the container:
   ```powershell
   cd C:\Users\Public\laptop-scanner
   docker compose config --quiet
   docker compose build scanner-agent
   docker compose up -d --no-deps scanner-agent
   docker compose logs --tail 100 scanner-agent | Select-String '1.6.7|speed profile|Scan profile config'
   ```
   Expected lines:
   - `Job … speed profile=fast per-IP time limit=900s fixed IP workers=4`
   - `Scan profile config Aetheris profile … scanner prefs {'plugins_timeout': '120', 'checks_read_timeout': '5', …}`

## 4. If an IP is still slow, send me this
```powershell
docker compose logs --tail 2000 scanner-agent | Select-String 'tail_activity|OpenVAS log NVTs|time limit|STALLED|NVT_TIMEOUT|Scan profile config|speed profile'
.\Show-Hang-Stats.cmd
```
The `OpenVAS log NVTs:` line names the checks that IP is stuck on.

## 5. Testing
- Laptop agent: **255 passed**. The new tests exercise the real job loop with a fake clock:
  - an IP stopped at exactly 900 s is reported "completed at time limit", with its findings kept and a
    payload central accepts;
  - a time limit during port scanning gives `degraded_time_limit`, with no re-run;
  - standard mode has no limit;
  - never more than 4 IPs run at once out of 10 (2 when configured to 2);
  - the stuck-IP diagnostics name the NVT taken from the OpenVAS log.
- Central focused suite: 74 passed. The same 4 failures are pre-existing in the original package.
- Frontend: no type errors in the changed files; `vite build --mode vuln` succeeds.
- **Not tested live.** Not tried on a real Greenbone:
  - gvmd accepting `plugins_timeout` and the other values as config scanner preferences. The python-gvm
    call and gvmd's handling of it were both checked in source; the log line in step 4 confirms it on your laptop.
  - Real-world scan times.
