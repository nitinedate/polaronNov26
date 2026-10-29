# Polaron / Laptop Scanner V1.6.5 — correct coverage verdicts, service attribution, Nessus-equivalent policies

Date: 2026-10-14. Based on the user-supplied Polaron and laptop-scanner packages (agent build 1.6.4-v47.6).
New agent build: **1.6.5-v47.7**.

## 1. What went wrong on job d26e3145 (192.168.0.163)

The UI showed *Incomplete — no open ports enumerated and only 11 NVT(s) ran*, while the same log showed
SMB results on 139/tcp and 445/tcp and the pre-probe saw 135/139/445 open. The verdict was false:

1. `_harvest_report_xml` read report metadata with `details=False rows=1`. gvmd omits host port details and
   `<error>` rows from that page but still sends `<errors><count>2</count>`.
2. `coverage_from_report` ran on that empty page → `degraded_no_ports`.
3. `_coverage_includes_parsed_results` then added 139/445 from the 11 parsed rows, but
   `scanner_failed = plugin_error_count > 0` kept the degraded verdict and rewrote the reason to
   "no open ports … 11 NVT(s)" while the same dict held `open_tcp_ports=[139,445]`. "11" was result rows.
4. The two errors were NVT timeouts (progress sat at 98 % from 02:00:24 to 02:06:19 ≈ the 320 s
   `plugins_timeout`), not a port-scanner failure. Three earlier scans of the same host with
   `plugin_errors=0` were classified `observed_unverified`.
5. Central marked every verdict other than `full` as Incomplete, but the agent never emits `full`, so no
   host from this agent could ever show as finished.
6. 8 of 11 results were attributed to no service, including both Mediums and the Low: RPC patterns did not
   match OpenVAS "DCE/RPC"/"MSRPC" wording, HTTP had no title patterns, `general/tcp` rows had no home,
   and unmapped rows were never logged with titles.

Note: 192.168.0.163 is the scanner laptop's own Wi-Fi IP (see V1.6.0 notes). A self-scan through Docker
Desktop NAT is a smoke test, not a client-host assessment.

## 2. Corrected result for this job

| Item | Shown in 1.6.4 | Correct (V1.6.5 logic) |
|---|---|---|
| Per-IP status | Incomplete — "no open ports" | Completed with warnings — network scan finished, 3 open TCP ports, 2 check warnings |
| Open ports | none | TCP 135, 139, 445 |
| Severity | 0 C / 0 H / 2 M / 1 L / 8 I | unchanged (the counts were right) |
| Services | 0 with findings, 50 not tested | SMB and RPC with findings; WMI not tested (needs Windows credentials); 48 not observed in scanned range; DHCP unsupported; Low in the host-level group |
| Clean result | NO | NO — no credentials, 2 checks timed out, unverified per-service checks |

The service split assumes the second Medium is on 445 and the Low is TCP timestamps (typical for Windows);
1.6.4 never logged those titles. Confirm on the laptop (read-only):

```bat
Diagnose-Report.cmd 034bf5f5-ff36-4f9f-ac7f-3935036b3b99 192.168.0.163
```

It prints every result (severity, CVSS, port, NVT OID, title), which NVTs timed out, host port details,
the scanned port range and the V1.6.5 verdict for that existing report.

## 3. What changed

### Laptop scanner agent
- Report harvest keeps the first `details=True` page; host port details and per-NVT error rows feed the verdict.
- Only a port-scanner NVT error (Nmap / Ping Host / Services / Open TCP Port) degrades a host. Other NVT
  errors become named warnings (`check X on 445/tcp: NVT timed out after 320 seconds`).
- `nvts_evidenced` counts distinct NVT OIDs; `results_evidenced` counts rows. New `network_scan_complete`.
- Merged job evidence keeps the declared GMP error count; pre-probe ports missing from Greenbone become a warning.
- Service attribution: word-boundary title rules (lighttpd ≠ Apache, tftp/sftp ≠ FTP), OpenVAS wording rules
  (DCE/RPC, MSRPC, SSL/TLS, SSH, HTTP, …), protocol port owners for results reported on that port only
  (product families such as Tomcat/IIS still need product evidence), plus two groups:
  *Host / OS / network stack (general)* and *Other open ports (outside the 52-family catalog)*.
  Every native result is now attributed and logged with its title.
- Service states: `finding`, `observation`, `not-tested` (port open, no check result), `not-observed`
  (port scanned and closed, no open port identified as the service), `not-in-scope` (port not scanned),
  `unsupported`. None of them is a pass.
- Resumed tasks recover the scanned range from the GMP target (same session).
- `python -m agent.report_diagnose <report_id>` and `Diagnose-Report.cmd`.

### Central server
- Ingest re-runs attribution with each host's scanned range and maps hosts with `network_scan_complete` to
  *Completed (with warnings)*; degraded hosts stay *Incomplete*. Clean eligibility is unchanged and stays NO.
- Job label *Complete with warnings*; assessment label *NETWORK SCAN COMPLETE - N SCANNER WARNING(S)*;
  new `clean_blockers`, `network_complete_hosts`, `cve_watchlist` in the job summary.
- `GET /api/scan-policy-templates`; policies accept `template_key`; all policy settings are validated on
  create/update (400 on anything the scanner would reject); jobs from a credentialed template without a
  credential reference are refused (`policy_credentials_missing`).
- Gap-assessment report wording covers the new states and host-level results.

### Web UI
- Scan policies: Nessus template picker with the effective settings, "How this differs from Nessus",
  port/UDP overrides, extra TCP ports, SMB/SSH credential IDs (required ones enforced).
- Scan details: *Completed with warnings* with the reasons a clean result is not claimed; per-IP open ports
  and expandable warnings; new service states; host-level and other-port result tables; CVE watchlist panel;
  template/port-list/family-scope details on the task policy.

## 4. Nessus parity

| Area | Nessus default | Before | V1.6.5 |
|---|---|---|---|
| TCP ports | "default" ≈ 4,790 common ports | `nexus` = 88 TCP | `nessus`/`nexus` = Greenbone "All IANA assigned TCP" + 52-family catalog (fallback TCP 1-1024 + catalog); `full` = 65,535; `catalog` = old 88 |
| UDP | UDP scanner off | 30 priority UDP | 30 priority UDP kept (OpenVAS only tests UDP services whose ports are in the target list); templates may set off/full |
| Service detection | probe all open ports | yes (OpenVAS find_service) | unchanged |
| Safe checks | on | on | on (all templates) |
| optimize_test | yes | forced **no** | **yes** by default; `GVM_OPTIMIZE_TEST=no` or a policy restores the old behaviour |
| Credentials | per policy | possible, unused | per policy; Credentialed Patch Audit refuses to run without them |
| Templates | ~25 | none (name + label only) | 11 (below) |

Templates (`agent/scan_templates.json`, shared byte-for-byte with central):

| Key | Nessus template | Greenbone config | Ports / UDP | Notes |
|---|---|---|---|---|
| host_discovery | Host Discovery | Discovery | catalog / off | ICMP, TCP-ACK & ARP ping; no vulnerability checks |
| basic_network | Basic Network Scan | Full and fast | nessus / priority | default general scan |
| advanced | Advanced Scan | Full and fast | full / priority | optional `nvt_families` |
| credentialed_patch_audit | Credentialed Patch Audit | Full and fast | catalog / off | needs SMB or SSH credential reference |
| web_app_tests | Web Application Tests | Full and fast, scoped to web/TLS families | catalog + web ports / off | falls back to full config if Greenbone rejects scoping |
| internal_pci | Internal PCI Network Scan | Full and fast | full / priority | PCI DSS label; apply the CVSS ≥ 4.0 threshold in review (no automatic pass/fail) |
| threat_ms17_010 | WannaCry Ransomware | Full and fast | 139, 445 / off | CVE watchlist MS17-010 |
| threat_zerologon | Zerologon Remote Scan | Full and fast | full / off | all TCP: dynamic RPC range |
| threat_printnightmare | PrintNightmare | Full and fast | full / off | credentials strongly recommended |
| threat_log4shell | Log4Shell | Full and fast | full / off | remote exposure only |
| threat_proxylogon | ProxyLogon : MS Exchange | Full and fast | 80, 443 / off | target Exchange servers |

A CVE watchlist "no hit" is reported as *no hit in scanned scope*, never as proof the host is unaffected.

## 5. Behaviour changes to expect
- Scans of Windows hosts should spend less time on checks for services that are not present
  (`optimize_test=yes`), and NVT timeouts become visible warnings instead of failing the host.
- `PORT_PROFILE=nexus` now scans the Nessus-default range, not 88 ports, so each host scans more TCP ports.
  Set `PORT_PROFILE=catalog` to keep the old scope.
- Hosts that finish their network scan show *Completed with warnings*; a clean result is still never claimed
  without verified evidence.

## 6. Upgrade

### Laptop (PowerShell, as the scanner user)
1. Wait for running scans and uploads to finish. Back up `C:\Users\Public\laptop-scanner`.
2. Extract this package over the existing folder. **Keep** your `.env`, `.lan-fingerprint`,
   `scanner-agent\runtime\` (agent token and instance ID) and `logs\`. The package contains none of them.
3. In `.env` set:
   ```ini
   PORT_PROFILE=nessus
   SCAN_IP_BUDGET_SEC=0
   GVM_OPTIMIZE_TEST=yes
   ```
4. Apply and verify:
   ```powershell
   cd C:\Users\Public\laptop-scanner
   docker compose config --quiet
   docker compose build scanner-agent
   docker compose up -d --no-deps scanner-agent
   docker compose logs --tail 80 scanner-agent | Select-String '1.6.5|Nessus profile|port list'
   .\Diagnose-Report.cmd 034bf5f5-ff36-4f9f-ac7f-3935036b3b99 192.168.0.163
   ```

### Central server
Copy the overlay files over the Polaron tree (paths are relative to the Polaron root), then rebuild the
backend and frontend images through your normal deployment. No database migration is needed:
`vuln_scan_policies.settings_json` already exists. Existing policies keep working; they have no template
until recreated from one.

## 7. Testing performed
- Laptop agent: **221 passed** (187 before), including a reproduction of job d26e3145 that fails on 1.6.4.
- Central focused suite: 70 passed; **4 failures pre-exist in the original package** and are unchanged
  (`test_claim_queued_parallel::test_adopts_queued_job_from_stale_scanner`,
  `test_edge_evidence_recovery::test_completed_edge_job_without_result_is_reopened_for_evidence`,
  `test_scan_job_network_identity::test_retry_sql_does_not_rewrite_targets`,
  `test_scanner_service_policy_v153::test_finding_api_preserves_v2_basis_and_unscored_flag`).
- Frontend: `tsc -b` reports no errors in the changed files; `vite build --mode vuln` succeeds.
  One **pre-existing** error in the untouched `src/hooks/usePipelineStepTracker.ts`
  (`sanitizeRegisterError` undefined) still makes `npm run build` (which runs `tsc -b` first) fail.
- python-gvm 27.10 signatures for `get_port_lists`, `clone_scan_config`,
  `modify_scan_config_set_family_selection` and the alive-test values were checked.

**Not tested:** no live Docker, gvmd, OpenVAS feed, target network, HTTPS upload or browser session.
Confirm on the laptop: the "All IANA assigned TCP" port list loads (log line `Nessus profile: loaded N TCP
ports`), Web Application Tests family scoping (task policy shows *scoped* or *not applied*), and a
Credentialed Patch Audit with a real SMB credential reference.

## 8. Security
The uploaded laptop-scanner archive contained live secrets (`AGENT_TOKEN`, `AGENT_RECOVERY_TOKEN`,
`FIRM_PASSWORD`, `GVM_PASSWORD`, `scanner-agent/runtime/agent-token`). Rotate them. This package excludes
`.env`, runtime tokens, `.lan-fingerprint` and client scan logs.
