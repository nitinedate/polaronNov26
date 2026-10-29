# Laptop Scanner V1.9.3 — parallel IP starts, one clock per IP, and the 98 % tail

Build stamp: `1.9.3-v53.0`. Cumulative: includes everything in V1.9.1 and V1.9.2.

## 1. What field job 3c4f45e0 showed (build 1.9.1-v51.0, 2 IPs)

Both IPs did scan at the same time inside OpenVAS, but three things around that were wrong.

**Starts were serial.** Starting one IP (pre-probe, scan-config lookup, target and task
creation) took 45–55 s and ran on the polling thread. 192.168.1.9 only began to start after
192.168.1.8's start had finished, and no IP was polled while a start was running. About
30–40 s of every start was a second full read of the 185,633-check scan config, repeating a
count the agent had read a moment earlier.

**One clock for the whole job.** `MAX_SCAN_RUNTIME_SEC=3600` was measured from the start of
the job, for all IPs together. .9 got whatever .8 left over, and an IP still waiting for a
slot would have got nothing. When it fired, every IP was stopped at once.

**The 98 % tail.** .9 reached 98 % at 08:03 and stayed there until the job cap stopped it
(kept as a partial result). The 5 static SSL cipher caps *were* applied in this build
(profile `2f1eba78bb`, "5 NVT timeout cap(s)"); they did not help. In openvas-scanner,
`pluginlaunch.c` reads a check's own `timeout` preference (set by `script_timeout()` in the
NASL file) before `plugins_timeout`. A check declaring 30–60 min runs that long; one
declaring `-1` is never killed. A fixed list of 5 OIDs cannot catch those. The agent also
could not say which check was running: it never set `log_whole_attack` on its own scan
config, and the DEBUG flood (fixed in V1.9.2) buried the rest.

**Per-IP check concurrency was three numbers.** `SCAN_SERVICE_PARALLELISM` was silently
clamped to 3–4 (left over from the old multi-task lane design), the profile then raised it to
5, and the build line printed 8 (`GVM_MAX_CHECKS`). OpenVAS used 5.

## 2. Changes

- **IP starts run in parallel** (`main.py`). Each IP starts on its own `aetheris-start`
  thread; the polling loop keeps polling. The IP slot is still taken before the start, so
  `SCAN_IP_WORKERS_FIXED` still holds. Only scan-config lookup/creation is serialised
  (`gmp_local._CONFIG_PREP_LOCK`), so two starts never clone the same config twice. If a job
  is stopped (LAN change, job removed on central, job limit) while an IP is starting, a task
  that still gets created is stopped at once. Progress shows a starting IP as scanning.
- **Faster starts** (`gmp_local.py`). The scan-config minimum-check floor uses the count
  `effective_selection` already read, instead of reading the 185k-check config again.
  The floor still refuses an incomplete config.
- **One clock per IP** (`scan_performance.ip_runtime_limit`). `MAX_SCAN_RUNTIME_SEC` now
  applies to each IP from its own task start (`SCAN_IP_DEADLINE_SEC` still wins if set).
  At the limit only that IP's task is stopped; its findings are kept and the host is
  reported finished at the time limit (never clean), as V1.6.7's per-IP limit always did.
  A whole-job limit is now its own setting, `MAX_JOB_RUNTIME_SEC`, off by default.
- **Per-IP check concurrency is one number** (`per_ip_check_concurrency`): the larger of
  `SCAN_SERVICE_PARALLELISM` (now 1–32) and the profile's own value (`FAST_MAX_CHECKS=5`).
  The job log prints the value OpenVAS gets.
- **Checks with long own timeouts are capped** (new `agent/nvt_timeouts.py`). The agent reads
  every `.nasl` file on the read-only `gvm_vt_data` volume once per feed version, in a
  background thread started at agent start, and caches the result in
  `logs/nvt_timeout_index.json`. Every check whose own timeout is above `SCAN_NVT_MAX_SEC`
  (default 900 s), or unlimited, gets `<oid>:0:entry:timeout = 900` on the Aetheris profile
  config — the same mechanism as the static and learned caps. Port scanners, service
  detection and web crawlers are never capped. A cap never raises a shorter limit, and a
  timeout written as a variable is left alone, never guessed. Until the index exists (no
  mount, or the first minutes after a feed update), scans run with the static/learned caps.
- **Caps for every profile.** Caps and Nmap timing were passed only when the profile was
  `fast`, so `turbo` and `standard` scans got no caps at all, despite the V1.9.0 comment.
- **Per-check logging on every scan.** `log_whole_attack=yes` is written onto every Aetheris
  scan config, so a host at 98 % names the check it is waiting for, whatever openvas.conf or
  gvmd's synced default says. `OPENVAS_LOG_WHOLE_ATTACK=no` leaves it to openvas.conf.
- **Concurrency safety.** The port-list note kept on the scanner object is per thread, so two
  parallel starts cannot swap it in their policy snapshots.

A check stopped at 900 s produces OpenVAS's normal "NVT timed out" error; the host is then
completed with warnings, not clean — the existing handling.

## 3. Upgrade (laptop, PowerShell, install folder e.g. `D:\laptop-scanner`)

The field laptop is on 1.9.1, so this includes the V1.9.2 OpenVAS steps. Wait until no scan
is running. Back up the folder. Extract the package over it (keep `.env`, `.lan-fingerprint`,
`scanner-agent\runtime\`, `logs\`). `Start-Laptop.cmd` does **not** recreate a running
scanner-agent (`--no-recreate`), so the recreate below is required for the new volume.
```powershell
.\Start-Laptop.cmd                                          # V1.9.1: stops stale fingerprint writers
docker compose up -d --force-recreate configure-openvas     # V1.9.2: openvas_log.conf level 127
docker compose restart ospd-openvas                         # next openvas run reads the new level
docker compose build scanner-agent
docker compose up -d --force-recreate --no-deps scanner-agent   # picks up the gvm_vt_data mount
docker compose logs --tail 80 scanner-agent | Select-String 'AGENT BUILD|NVT timeout index'
```
Keep `MAX_SCAN_RUNTIME_SEC=3600` in `.env` if you want a limit: it now means one hour per IP.

## 4. Verify

```powershell
docker compose exec -T scanner-agent sh -c "grep PLUGIN_SET /var/lib/openvas/plugins/plugin_feed_info.inc"
docker compose logs --tail 400 scanner-agent | Select-String 'NVT timeout index|parallel:|NVT timeout caps on'
```
Expected, in order:
- `AGENT BUILD 1.9.3-v53.0`
- `NVT timeout index (SCAN_NVT_MAX_SEC=900s): building for feed ...`, then
  `NVT timeout index built for feed ...: N checks read, K declare their own timeout (S s)`
- per job: `... | parallel: up to 2 IP(s) at once, 5 checks at once per IP | per-IP time limit=3600s (MAX_SCAN_RUNTIME_SEC (per IP since V1.9.3)) | job limit=off | per-check max=900s`
- per IP: `NVT timeout caps on <config>: 5 static SSL, <n> long-timeout (...), 0 learned; per-check logging on`
- both IPs' `start_attempt` events within a second or two of each other in `logs\ip\`.

If the index line says `unavailable: plugins not readable`, the scanner-agent container was
not recreated with the new compose file.

## 5. Settings

| Setting | Default | Meaning |
|---|---|---|
| `MAX_SCAN_RUNTIME_SEC` | `0` | **changed:** per-IP limit, each IP from its own task start (0 = none) |
| `MAX_JOB_RUNTIME_SEC` | `0` | new: whole-job limit (0 = off) |
| `SCAN_IP_DEADLINE_SEC` | empty | per-IP limit; overrides `MAX_SCAN_RUNTIME_SEC` |
| `SCAN_SERVICE_PARALLELISM` | `4` | checks at once per IP, now 1–32; the larger of this and `FAST_MAX_CHECKS` is used |
| `SCAN_NVT_MAX_SEC` | `900` | new: cap for checks whose own timeout is longer or unlimited (0 = off) |
| `NVT_TIMEOUT_INDEX_FILE` | `/app/logs/nvt_timeout_index.json` | new: cached feed index |
| `OPENVAS_LOG_WHOLE_ATTACK` | `yes` | now also written onto every Aetheris scan config |

## 6. Not verified against a live Greenbone

The tests use fakes for gvmd and the feed. Three things should be checked on the laptop's
first scan:
- that gvmd accepts `log_whole_attack` as a scan-config scanner preference. If not, the agent
  logs `Scanner preference log_whole_attack=yes rejected` and continues; openvas.conf still
  sets it.
- how long the index build takes on the real feed (logged), and how many checks it caps.
  Writing the caps onto a new profile config costs one GMP call per check, once per feed
  version.
- how long one IP's start now takes (compare `start_attempt` and `started` in the IP logs):
  expected about 30–40 s shorter than the 45–55 s seen in job 3c4f45e0.

## 7. Testing

394 agent tests pass (V1.9.2: 376), and the job-loop tests were re-run 5 times without
failure. New tests: two IP starts that must both be inside `start_scan` at once (a barrier),
a start failure freeing the slot for the next IP, a 3-IP job that is not cut by a limit each
IP fits in while `MAX_JOB_RUNTIME_SEC` at the same value still stops it, a slow IP stopped at
its own limit with findings kept, NASL parsing (literals, `60*60`, `-1`, variables refused,
code never evaluated), the index (scanners never capped, shorter limits never raised, cache
reused, rebuilt on a new `PLUGIN_SET`, missing mount reported), caps and per-check logging on
fast/turbo/standard, the big config read once per start, and the config floor still refusing
an incomplete config. Updated: the 3–4 parallelism band test, the standard-profile scanner
preferences, and the version pins.
