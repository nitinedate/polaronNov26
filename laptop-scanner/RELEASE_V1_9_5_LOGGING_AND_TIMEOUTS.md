# Laptop Scanner V1.9.5 — per-check logging, DEBUG log, and the timed-out check

Build stamp: `1.9.5-v55.0`. Cumulative: includes V1.9.1–V1.9.4.

## What job d1c55fbe showed (192.168.0.163, the scanner laptop, agent 1.9.3)

The scan worked: OpenVAS finished, 11 results (1 Medium, 1 Low, 9 Info) were collected
and uploaded, and every finding is valid. It ran 606 s; 6 of those minutes were spent at
98 %, and the job is "Completed with warnings". Three things are behind that.

**1. One check did not finish.** NVT `1.3.6.1.4.1.25623.1.0.902269` ran into OpenVAS's 320 s time limit and was stopped. That is the entire 98 % wait and the
only reason the result is "with warnings" instead of clean. The same check timed out on
this laptop in job 3c4f45e0. Marking the result "with warnings" is correct — one check
did not run to completion — but the UI only said "plugin errors or timeouts".

**2. Per-check logging was switched off — by V1.9.3.** V1.9.3 put `log_whole_attack=yes`
on every scan config. Verified in the upstream sources:
- gvmd sends scan-config scanner preferences with `yes`/`no` rewritten to `"1"`/`"0"`
  (`gvmd src/manage_osp.c`);
- ospd-openvas turns `"1"` back into `yes` only for its own boolean parameters
  (`OSPD_PARAMS`), and `log_whole_attack` is not one of them;
- OpenVAS counts only the exact string `yes` as true (`gvm-libs base/prefs.c`
  `prefs_get_bool`), and scan preferences override `openvas.conf`.

So the setting arrived as `"1"`, read as "off", and overrode `openvas.conf`. That is why
the agent logged "per-check logging is off" and could not name the check at 98 %.

**3. openvas.log is still at DEBUG level.** `debug_share: 1.0` — essentially every line
the agent read was DEBUG. The DEBUG level comes from the original compose
(`sed "s/127/128/"`); V1.9.2 changed the compose, but `configure-openvas` — a one-shot
container that writes `openvas.conf` and `openvas_log.conf` — has not been re-run since.
A plain `docker compose up -d` does not re-run an exited one-shot container, and the
agent's own hint said exactly that command.

## Changes

- `log_whole_attack` is never set on a scan config again, and each new profile config has
  any inherited copy removed (a preference sent without a value is deleted by gvmd while no
  task uses the config). The profile-config name changes once, so V1.9.3 configs are not
  reused. `openvas.conf` decides per-check logging again.
- The job log no longer claims "per-check logging on"; it says the setting comes from
  `openvas.conf` and is checked in `openvas.log`.
- **The check behind "with warnings" is named** in the host notes the UI shows, e.g.:
  "Check <name> (1.3.6.1.4.1.25623.1.0.902269) on <port> did not finish: OpenVAS
  stopped it at its time limit after 320 s. Every other check completed and the findings
  are valid; this one check is why the result is 'with warnings' rather than clean. It has
  timed out 2+ times in 30 days, so the next scans give it 60 s instead of waiting the full
  time." The same text is logged as a WARNING.
- **Startup check:** the agent reads `openvas.log` once at start and logs
  `OPENVAS_LOG_SETUP` warnings if it is mostly DEBUG or has no check launches, with the
  exact fix.
- Every hint now gives the command that really re-runs the container:
  `docker compose up -d --force-recreate configure-openvas`.

The learned cap for 902269 already exists (since V1.6.6): after 2 timeouts in 30 days it
gets 60 s. With jobs 3c4f45e0 and d1c55fbe both recorded, the next scan should list
"1 learned" in "NVT timeout caps on …" and wait about 1 minute at 98 % instead of 6. If
the check still cannot finish in 60 s, the result stays "with warnings" — by design, the
agent never calls a result clean when a check did not run.

## Upgrade (laptop, when no scan is running)

Extract over the install (keep `.env`, `logs\`, `scanner-agent\runtime\`). In `.env`,
`OPENVAS_LOG_LEVEL` must be 127 (or absent) and `OPENVAS_LOG_WHOLE_ATTACK` yes (or
absent); `SCAN_IP_BUDGET_SEC=600` can be deleted. Then:
```powershell
docker compose up -d --force-recreate configure-openvas
docker compose up -d --force-recreate --no-deps scanner-agent
docker compose exec -T ospd-openvas sh -c "grep -E '^log_whole_attack' /etc/openvas/openvas.conf; grep -m1 '^level' /etc/openvas/openvas_log.conf"
```
Expected: `log_whole_attack = yes` and `level=127`. OpenVAS starts a new process for each
scan and reads both files then, so the next scan uses them. If that scan still writes
DEBUG lines, restart ospd-openvas once while idle.

## Verify on the next scan

- `AGENT BUILD 1.9.5-v55.0` and, after the 1.9.4 mount, `NVT timeout index … built`.
- `Scan profile config Aetheris profile …` is a new name; its scanner prefs do not list
  `log_whole_attack`.
- `NVT timeout caps on …: … 1 learned` (902269 at 60 s).
- If a host waits at 98 %, the tail line names the running check(s) instead of
  "per-check logging is off".
- The `OPENVAS_LOG_SETUP` startup warnings read past scans; they clear after a new scan
  has run and the agent restarts.

## Testing

405 agent tests pass. New: the profile config removes `log_whole_attack` and never sets
it; pre-fix configs are not reused; timed-out check notes (named, port, seconds, cap
status; other hosts and non-timeout errors ignored; discovery checks never promised a
cap); the note reaches the uploaded host coverage through the job loop; startup warnings
for DEBUG level and missing launches, and silence when logging is right; the tail hint
uses `--force-recreate`. Updated: V1.6.6/V1.9.3 tests that expected
`log_whole_attack=yes` on the config.
