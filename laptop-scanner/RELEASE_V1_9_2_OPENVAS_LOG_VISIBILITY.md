# Laptop Scanner V1.9.2 — "per-check logging is off" at 98 % was a blind spot

Date: 2026-10-15. Agent build **1.9.2-v52.0**. Cumulative: includes V1.9.1
(see RELEASE_V1_9_1_SEVERITY_SCOPE_AND_SELF_SCAN.md) and V1.9.0.

## 1. The warning
```
WARNING IP 192.168.1.8 at 98% for 309s: OpenVAS per-check logging is off (set log_whole_attack);
cannot see running checks. OpenVAS log NVTs: none found; slow finished: none
```
Two separate things are in that line.

**"at 98% for 309s" is normal.** The last 2 % of a host is usually the SSL/TLS cipher checks
(one TLS handshake per cipher, per TLS port). The agent never stops a scan for being slow.

**"per-check logging is off" was wrong.** `log_whole_attack = yes` is written by default
(`.env` does not override it). The agent reads only the last 8 MB of `openvas.log`, and the
compose file (copied from Greenbone's community compose) sets `openvas_log.conf` to
**DEBUG (128)**. During the cipher checks libgvm writes thousands of
`libgvm util: DEBUG: ... Key 'ssl_tls/ciphers/sni/<ip>/...' already contained integer '1'`
lines per second. In field jobs 320903ac and c8416cd6 the whole 8 MB window was those lines,
all stamped within one second. Job 3c4f45e0 found **no line at all** for 192.168.1.8 — not even
`Vulnerability scan ... started for host`, which OpenVAS logs unconditionally — so the
"Launching" lines were simply out of reach.

Two more problems were behind the same blind spot:
- **Self-scan:** the agent searched the log for the laptop's LAN IP, but OpenVAS scans (and logs)
  the loopback alias (e.g. 192.168.65.254), so a self-scan never matched its own log lines.
- **Latent risk:** the evidence-based stall rule stops a task when the log shows "logging on,
  nothing running, host not finished". With a short window, a check launched before the window
  looks finished. The DEBUG flood happened to keep the agent blind (so it always waited); simply
  un-flooding the log would have let it stop busy scans.

Upstream's own `openvas_log.conf` also warns that DEBUG "may reveal passwords in the logs" —
relevant since V1.9.0 added laptop-local SMB/SSH credentials.

## 2. Changes
- **`agent/openvas_log.py` rewritten:** follows the file incrementally (offset + anchor, so a
  rewritten or rotated log is re-read), backfills up to `OPENVAS_LOG_BACKFILL_MB` (256) on first
  use, drops DEBUG lines before decoding them, and keeps per-host state from the host's
  `started for host` line on. Every needed line is MESSAGE level, so DEBUG is never required.
  Measured: 0.9 s for a 257 MB DEBUG flood on first use, then ~0.2 ms per call.
- **Stall rule safer** (`scan_performance.stall_decision`): "nothing running" only counts when
  the reader saw the host's start line. Otherwise it waits.
- **Self-scan:** log lookups use the address OpenVAS scanned (the alias).
- **Honest messages:** "per-check logging is off" only when the host's scan is in the log and no
  launches are logged; otherwise "Cannot see this host's running checks: ..." with the reason
  (and the DEBUG share). The 98 % notice is **INFO** when the agent can name the running check or
  the host is finished, **WARNING** only for a real blind spot.
- **`docker-compose.yml`:** new `OPENVAS_LOG_LEVEL` (default **127**, upstream's default; 128 =
  DEBUG). Invalid values fall back to 127.
- **Diagnostic:** `python -m agent.diagnose_check_scope` now reports the openvas.log size, DEBUG
  share and whether check launches are logged, with verdicts `OPENVAS DEBUG LOGGING` /
  `OPENVAS PER-CHECK LOGGING OFF`.

## 3. Upgrade (laptop, PowerShell, install folder e.g. `D:\laptop-scanner`)
Wait until no scan is running. Back up the folder. Extract the package over it (keep `.env`,
`.lan-fingerprint`, `scanner-agent\runtime\`, `logs\`). Then:
```powershell
.\Start-Laptop.cmd                                          # V1.9.1: stops stale fingerprint writers
docker compose up -d --force-recreate configure-openvas     # rewrites openvas_log.conf at level 127
docker compose restart ospd-openvas                         # next openvas run reads the new level
docker compose build scanner-agent
docker compose up -d --force-recreate --no-deps scanner-agent
docker compose logs --tail 50 scanner-agent | Select-String 'AGENT BUILD'   # 1.9.2-v52.0
```
Optional — reclaim disk space used by the DEBUG log (the agent detects the truncation):
```powershell
docker compose exec -T ospd-openvas sh -c "ls -la /var/log/openvas/; : > /var/log/openvas/openvas.log"
```

## 4. Verify
```powershell
docker compose exec -T ospd-openvas sh -c "grep -c '^level=127' /etc/openvas/openvas_log.conf; grep log_whole_attack /etc/openvas/openvas.conf"
```
Expected: `7` and `log_whole_attack = yes`. Then
`docker compose exec -T scanner-agent python -m agent.diagnose_check_scope` should show no
`OPENVAS DEBUG LOGGING` verdict once new scans have written to the log. During the next scan's
tail, expect an INFO line such as
`IP 192.168.1.8 at 98% for 312s: 1 check(s) still running in OpenVAS: gb_ssl_....nasl (...) for 290s`.

## 5. Settings
| Setting | Default | Meaning |
|---|---|---|
| `OPENVAS_LOG_LEVEL` | `127` | openvas.log level (127 = no DEBUG, 128 = DEBUG) |
| `OPENVAS_LOG_BACKFILL_MB` | `256` | how far back the agent reads openvas.log on first use (1–4096) |
| `OPENVAS_LOG_WHOLE_ATTACK` | `yes` | unchanged: log each check launch/finish |

## 6. Testing
376 agent tests pass (V1.9.1: 366). New tests rebuild the field log (launch, then ~11 MB of
real-format DEBUG lines): the V1.6.8 reader returns exactly the field message, the new reader
names the running check and its true run time. Also covered: incremental reads, a launch before
the read window (old rule: stop; new: wait), logging really off, rewritten log, same-second
launches, OID digits never mistaken for IPs, and the self-scan alias end to end (INFO, not
WARNING). One V1.6.6 fixture gained the `started for host` line real OpenVAS always writes.
The compose `sed` was run against upstream's `openvas_log.conf` template (all 7 sections set;
invalid value -> 127) and the script passes `sh -n`.
**Not tested live** on the laptop; section 4 is the live check.
