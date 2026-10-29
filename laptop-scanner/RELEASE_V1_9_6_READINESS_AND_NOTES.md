# Laptop Scanner V1.9.6 — readiness probe cadence and the timed-out check note

Build stamp: `1.9.6-v56.0`. Cumulative: includes V1.9.1–V1.9.5.

## What job 8d4e431e showed (192.168.0.163, the scanner laptop, agent 1.9.5)

The scan is complete: 100 %, the host assessed, 11 results (1 Medium, 1 Low, 9 Info)
collected and uploaded. Compared with job d1c55fbe (agent 1.9.3) on the same laptop:

| | d1c55fbe (1.9.3) | 8d4e431e (1.9.5) |
|---|---|---|
| IP start (`start_attempt` → `started`) | 55 s | 14 s |
| Time at 98 % | ~6 min | ~1 min |
| Whole scan | 606 s | 262 s |
| Findings | 11 | 11 |

"Completed with warnings" has one cause: the check *Microsoft Windows SMB Server NTLM
Multiple Vulnerabilities (971468)*, `1.3.6.1.4.1.25623.1.0.902269`, did not finish. It
has not finished in any scan of this laptop: jobs 3c4f45e0 (192.168.1.8), d1c55fbe and
8d4e431e (192.168.0.163) — every time the laptop was scanned through the Docker loopback
(192.168.65.254). The learned limit worked: the check was stopped after 60 s instead of
320 s. The check still gives no verdict on this host, so the result is correctly not
called clean. Separately, "Clean-result eligible (needs credentials): NO" is because the
scan is unauthenticated; that would hold even without the timeout.

## Problems found in the log, and fixes

**1. gvmd probed every ~4 seconds (regression from V1.9.4).** The dispatcher loop calls
`ready()` on every pass (`QUEUE_POLL_INTERVAL_SEC=3`). Each probe opens a GMP session and
reads the scanner list, feeds, NVT count, every scan config and the full 185k-check base
config. Until V1.9.4 one probe took ~40 s, which hid this; once V1.9.4 made it fast, the
log shows "Base config 'Full and fast' not present" every ~4 s, including during the scan.
Fix: a successful readiness result is reused for `READINESS_RECHECK_SEC` (default 60 s);
not-ready is still re-checked on every pass so a starting gvmd is picked up at once. The
"Base config" note is logged once per hour.

**2. The timed-out check note was wrong about the limit.** It said "the next scans give
it 60 s" although this scan had already run the check with the 60 s limit. It now says:
"… did not finish: OpenVAS stopped it at its time limit after 60 s. … It has timed out in
3 scans in the last 30 days. This host is the scanner laptop, scanned through the Docker
loopback (192.168.65.254). The agent already limits it to 60 s, so it no longer holds the
scan up." The count comes from the agent's timeout statistics.

**3. Still not applied on the laptop (no code change; install steps).**
- `NVT timeout caps … index unavailable: plugins not readable at /var/lib/openvas/plugins`
  — the scanner-agent container still has no `gvm_vt_data` mount (added in V1.9.3). It is
  only added by recreating the container from the new compose file.
- `LEGACY_IP_BUDGET_IGNORED: SCAN_IP_BUDGET_SEC=600` — the line is still in `.env`.
- Per-check logging (V1.9.5 fix) could not be confirmed from this job: the 98 % phase was
  under the 300 s threshold at which the agent inspects `openvas.log`.

Not changed: the service table repeats "not-tested; authentication/privilege evidence is
required" on every row. It is correct — no authenticated checks ran, and those can find
installed software even where nothing listens — just repetitive.

## Upgrade (laptop, when no scan is running)

Extract `laptop-scanner-v1.9.6-update.zip` over the install (it contains no `.env`,
logs, token or fingerprint, so those stay as they are). Then run:
```powershell
.\Apply-Scanner-v1.9.6.cmd
```
The script checks the extracted files are V1.9.6, stops if OpenVAS is scanning (use
`-Force` to override), backs up `.env` and removes `SCAN_IP_BUDGET_SEC`, sets
`OPENVAS_LOG_LEVEL` 128 → 127 and a stale `AGENT_VERSION` to 1.9.6 (`-SkipEnv` leaves
`.env` alone), re-runs configure-openvas, recreates scanner-agent, and verifies
`log_whole_attack`, the log level, the feed mount and the running build. It prints
`[OK]`/`[WARN]` per step; it never uses `docker restart` or touches volumes.

The same steps by hand:
```powershell
docker compose up -d --force-recreate configure-openvas
docker compose up -d --force-recreate --no-deps scanner-agent
docker compose exec -T scanner-agent sh -c "ls /var/lib/openvas/plugins | head -3"
docker compose exec -T ospd-openvas sh -c "grep -E '^log_whole_attack' /etc/openvas/openvas.conf; grep -m1 '^level' /etc/openvas/openvas_log.conf; grep -c 'Launching ' /var/log/openvas/openvas.log"
docker compose logs --tail 200 scanner-agent | Select-String "AGENT BUILD|NVT timeout index|OPENVAS_LOG_SETUP"
```
Expected: the `ls` lists feed files (if it fails, the compose file in use is not the new
one); `log_whole_attack = yes`, `level=127`; after the next scan the `Launching` count is
above 0; `AGENT BUILD 1.9.6-v56.0`; then `NVT timeout index … built`.

After the update, the agent log should show the "Base config" line about once an hour and
`jobs/next` roughly every 3 s only while idle.

## Full project

`laptop-scanner-v1.9.6-full.zip` is the complete project tree for a new install or a
clean copy. Like the update zip it leaves out `.env`, `.lan-fingerprint`,
`scanner-agent\runtime\` contents (agent token and id), `logs\` and caches; copy
`.env.example` to `.env` for a new install, and `Start-Laptop.cmd` writes the rest.

## Testing

411 agent tests pass. New: a ready result is reused (20 calls → 1 probe); not-ready is
re-probed every pass; `READINESS_RECHECK_SEC=0` probes every time and
`invalidate_readiness()` forces a probe; the base-config note is logged once for 10
lookups; the note says "already limits it to 60 s" when the scan used the limit, counts
earlier timeouts, names the Docker loopback for the scanner laptop, and keeps the port.
`Apply-Scanner-v1.9.6.ps1` was parse-checked and run under PowerShell 7.4 against a stub
`docker.exe`: normal upgrade, scan running (stops, `.env` untouched), `-Force`, old
compose file or missing feed mount (stops before any change), and a leftover-container
name conflict (removes it and retries). Its `.env` edit keeps CRLF line endings, writes
no BOM, leaves comments and other lines unchanged, and is idempotent. It has not been
run on Windows PowerShell 5.1 itself.
