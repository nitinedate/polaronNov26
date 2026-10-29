# Laptop Scanner / Polaron V1.9.1 — Medium/Low findings restored, self-scan made reliable

Date: 2026-10-15. Agent build **1.9.1-v51.0**. Cumulative (includes V1.9.0).

## 1. What was wrong

Scans of the scanner laptop (192.168.0.163, jobs 1598a7c8, dffcee8e, 64b549f1) finished with
**0 Critical / 0 High / 0 Medium / 0 Low**. That was not a clean host:

| Evidence | |
|---|---|
| Same laptop, agent 1.6.4 (field job d26e3145) | `severity={'info': 8, 'medium': 2, 'low': 1}` |
| Every scan from agent 1.6.8 on (~35 scans, 3 hosts) | Info only, never a single Low or above |
| DCE/RPC enumeration (108044) succeeded on 135/tcp every time | its Medium report check, 10736 (CVSS 5.0), never ran |
| Elasticsearch 9200, Neo4j 7474 open | no product detection ever reported |

### Root cause A — vulnerability-only scan config silently truncated (the missing severities)
V1.6.8 made `SCAN_CHECK_SCOPE=vulnerability` the default (the `nx_full_audit` and `basic_network`
templates use it). It built a **fixed list of check IDs per family** with `get_info_list(... rows=-1)`.
gvmd caps every GET at its "Max Rows Per Page" setting, **default 1000**, and turns `rows=-1` into
1000 (gvmd INSTALL.md). Every family with more than 1000 qualifying checks was cut at row 1000
(sorted by name). The V1.6.8 notes listed large NVT lists as "not tested live".

### Root cause B — the truncated config was reused forever
python-gvm takes `comment=` **keyword-only**. The agent passed it positionally inside
`try/except: pass`, so no comment was ever stored. Reuse therefore logged
`reused (None checks)` / `scanner prefs None` and could not validate anything.

### Root cause C — self-scan silently off ("41 no answer")
The agent recognises the laptop's own IP from `host_ips` in `.lan-fingerprint`. The live file had
**no `host_ips` key** — the signature of a pre-1.8.0 `Write-LanFingerprint` loop still running.
Every Start-Laptop run started another hidden loop and never stopped old ones, so old and new
writers raced. When the old one won, the laptop was scanned through its own firewall
(149 of 154 ports "no answer"), and no `self_target_check` event recorded why.

## 2. Fix — check scope (`gmp_local.py`)
- **`vulnerability` (default):** every family of Full and fast **whole and growing**, minus
  Brute force attacks, Compliance, Policy, IT-Grundschutz*, Nmap NSE*, Denial of Service.
  No check-ID lists, so nothing can be truncated and new feed checks are picked up automatically
  (Nessus "Advanced Scan" parity). Config name: `Aetheris vuln-scope v2 ...`.
- **Verified before use and before reuse:** each whole family must have
  selected = available (`nvt_count == max_nvt_count`); excluded families must be empty;
  total checks >= `GVM_MIN_NVT_COUNT`. A config that fails is deleted (if unused) and rebuilt.
- **`severity` (opt-in, `SCAN_CHECK_SCOPE=severity`):** the old severity>0 selection, now fetched
  in pages of 500 (`GVM_INFO_PAGE_ROWS`) and required to match gvmd's own filtered total.
  Product detection is kept whole. Advanced Dynamic filters use the same paged, verified fetch.
- **Legacy configs retired:** unused pre-V1.9.1 `Aetheris vuln-scope ...` / `Aetheris dynamic ...`
  configs are deleted automatically.
- **Comment bug fixed** for scope and profile configs.
- **New evidence:** each task logs
  `Effective check selection for task config ...: N checks in X/Y families; partial families: ...; not selected: ...`
  and sends it as `check_selection` in the policy snapshot (central whitelist updated too).

## 3. Fix — self-scan
- `scripts/start-laptop.ps1` **stops every running fingerprint writer** before starting one, then
  prints whether the fingerprint has `host_ips`.
- `scripts/Write-LanFingerprint.ps1` allows **one looping writer** (named mutex) and writes
  `writer_version`. It still rewrites the file in place on purpose: it is a single-file Docker bind
  mount, and replacing it by rename would leave the container reading the old file.
- Agent: a fingerprint without `host_ips`, or one read mid-write, is re-read for up to
  `SELF_SCAN_FINGERPRINT_WAIT_SEC` (default 25 s), with a 2-minute negative cache so large jobs do
  not wait per IP. A stale file is still never trusted.
- The `self_target_check` event is now emitted **with its reason** whenever the scanner cannot tell
  whether a target is itself, and the agent logs `SELF-SCAN DISABLED: ...` (at most every 15 min).

## 4. New read-only diagnostic
```powershell
docker compose exec -T scanner-agent python -m agent.diagnose_check_scope
```
Changes nothing. Shows gvmd's row cap, Feed Import Owner, every Aetheris config with families cut
at 1000 rows, whether DCE/RPC reporting (10736) and TCP/ICMP timestamp checks are in each config,
which config recent tasks used, and the fingerprint state. Exit code 1 when a truncated config or
missing check is found. `--json` for machine output.

## 5. Upgrade (laptop, PowerShell, from the install folder, e.g. `D:\laptop-scanner`)
1. Let running scans finish. Back up the folder.
2. Extract the package over the folder. **Keep** `.env`, `.lan-fingerprint`,
   `scanner-agent\runtime\` and `logs\`.
3. Run `Start-Laptop.cmd` (stops stale fingerprint writers, starts the current one).
   Expected: `[OK] Stopped N old LAN fingerprint writer(s).` (when any were running) and
   `[OK] Fingerprint host_ips: 192.168.x.y ...`.
4. Load the new agent code. Start-Laptop does not rebuild or recreate a running agent:
   ```powershell
   docker compose build scanner-agent
   docker compose up -d --force-recreate --no-deps scanner-agent
   docker compose logs --tail 50 scanner-agent | Select-String 'AGENT BUILD'
   ```
   Expected: `AGENT BUILD 1.9.1-v51.0`.
5. If you set `SCAN_CHECK_SCOPE=all` as a workaround, you may set it back to `vulnerability`.
6. If the diagnostic reports the stock "Full and fast" config missing or no Feed Import Owner, run
   `scripts\Repair-Greenbone-Feed-v1.4.1.ps1`.

## 6. Verify
```powershell
docker compose exec -T scanner-agent python -m agent.diagnose_check_scope
```
Before the first scan it may still list the old truncated configs (`CUT AT 1000 ROWS`); the first
scan retires unused ones. After rescanning 192.168.0.163:
```powershell
docker compose logs --tail 5000 scanner-agent | Select-String 'Check-scope config|Retired legacy|Effective check selection|SELF-SCAN|self_target_check'
```
Expected:
- `Check-scope config Aetheris vuln-scope v2 ... [vulnerability]: N of M checks verified; ... partial families: none`
- `Effective check selection ...: partial families: none; not selected: Brute force attacks, ...`
- `self_target_check` with `"is_self": true` (or, if not, a `reason` saying why)
- Findings: at least DCE/RPC and MSRPC Services Enumeration Reporting (Medium) when 135/tcp answers.

## 7. Settings
| Setting | Default | Meaning |
|---|---|---|
| `SCAN_CHECK_SCOPE` | `vulnerability` | `vulnerability` / `severity` / `all` (also per policy `check_scope`) |
| `GVM_INFO_PAGE_ROWS` | `500` | page size for severity/dynamic check lists (50–1000) |
| `SELF_SCAN_FINGERPRINT_WAIT_SEC` | `25` | wait for a fingerprint with `host_ips` (0–60) |

## 8. Testing
- Laptop agent: **366 passed** (both the standalone tree and Polaron's bundled `laptop-scanner/`).
  New tests use a fake gvmd that enforces the 1000-row cap, the keyword-only comment and real
  per-family counts. On the original code they fail exactly as the field did: 1000 of 1872 Windows
  checks selected, DCE/RPC reporting missing, no `self_target_check` event.
- PowerShell: both scripts parse under PowerShell 7.4; the writer singleton was exercised on a real
  .NET runtime (second writer exits in 1 s; `host_ips` is always written, even as `[]`).
- Central: `scanner_service_policy.py` mirrored byte-for-byte (parity test passes). Policy-related
  central tests: 38 passed, 2 failed — the **same 2 fail on the original package**:
  `test_policy_speed_is_validated` (expects `turbo` rejected; V1.9.0 added it) and
  `test_finding_api_preserves_v2_basis_and_unscored_flag` (expects a CVSS v2 9.1 to stay High;
  central labels it Critical — a severity-labelling decision left unchanged here).
- **Not tested live:** against the laptop's real gvmd. Section 4's diagnostic is the live check.

## 9. Rollback
Set `SCAN_CHECK_SCOPE=all` (runs every check, no scope config) or restore the backup folder and
repeat step 4. The V1.9.1 configs are named `... v2 ...` and do not affect older agents.
