# Aetheris / Polaron V1.8.0 — Nexpose policies, built-in policy dropdown, scanning the scanner laptop

Date: 2026-10-14. Laptop agent build **1.8.0-v50.0**. Cumulative over V1.7.0.

## 1. What the field logs and screenshots showed (job e158c5dc, 172.20.10.2)

| Evidence (logs/ip/e158c5dc…/172.20.10.2.jsonl) | Meaning |
|---|---|
| `port_discovery`: 0 open, 0 closed, **87 filtered**, in 3 s | No policy TCP port answered the agent's probe |
| Greenbone results: Hostname, OS detection, Host Summary, pnscan, Traceroute, **Firewall Enabled** (all Info) | Greenbone's own port scan also found nothing open |
| `completed`, coverage `no_exposed_services`, 0 plugin errors, 297 s | The scan did finish; there was nothing Low+ to report |
| `.lan-fingerprint`: subnet 172.20.10.0/24, gateway 172.20.10.1 | The laptop is on an iPhone Personal Hotspot; 172.20.10.2 is almost certainly the laptop itself |

Severity capture was not broken: CVSS → Critical/High/Medium/Low mapping is correct. Windows treats a
hotspot as a **Public** network and drops inbound SMB/RPC/RDP; traffic from the Docker containers to the
laptop's own Wi-Fi address is inbound traffic, so every port was dropped. The same laptop on 192.168.0.163
(earlier jobs, Private network) showed 135/139/445 open. An unauthenticated Nexpose scan would report the
same thing; Rapid7's own guidance is to open the Windows firewall for the scan engine, use credentials,
or use its endpoint agent.

Two further problems were found:
* **Empty policy dropdown.** Launch listed only rows in `vuln_scan_policies`. Templates were never turned
  into rows, `scripts/_purge_all_jobs.sql` and case deletion delete rows, the page loaded policies once and
  hid errors, and new policies were saved as `draft`, which central (premise) scans refuse.
* **Hotspot treated as Docker NAT.** `lan_fingerprint.is_docker_nat_fingerprint` classified any gateway in
  172.16.0.0/12 as Docker; 172.20.10.1 is in that range, so roam detection was off on every iPhone hotspot.

## 2. What changed

### Laptop agent
* **Self-target scanning** (`agent/self_target.py`). When an authorized target is one of the laptop's own
  addresses, Greenbone scans it through Docker's `host.docker.internal` loopback, which the Windows firewall
  does not filter. Findings show what is installed and listening (local view, like an endpoint agent) and are
  reported under the original IP. What other machines can reach is recorded separately
  (`self_scan.network_exposure`) and shown on the IP row.
  * Own addresses come from `.lan-fingerprint` → `host_ips` (written every 10 s by
    `scripts/Write-LanFingerprint.ps1`) and are trusted only if the file is under 5 minutes old, so a client
    device that later gets the laptop's old address is never confused with the laptop. `SCANNER_HOST_IPS`
    overrides.
  * If the loopback answers on ≥90 % of policy ports (a proxy accepting everything), the agent logs
    `self_target_unreliable` and scans the normal network path instead.
  * The task → address mapping is persisted (`logs/self_target_aliases.json`) so a restart mid-scan still
    maps results back. `SELF_SCAN_MODE=off` disables the feature.
* **Service port policy 1.1**: 95 services, 154 TCP / 33 UDP ports (was 67 / 87 / 25). See section 4.
* **18 Nexpose-equivalent templates** (section 3), 33 templates in total.
* "No TCP port answered" is now a **note**, not a warning.
* Hotspot fingerprint fix; `ospd-openvas` gets the `host.docker.internal` mapping in `docker-compose.yml`.

### Central (backend, frontend, database)
* **Built-in policies**: every template marked `seed_as_builtin` becomes one `active`, read-only policy per
  tenant (25 today). Created on the first `GET /api/scan-policies`, recreated on the next list after a purge
  (no restart), retired if a template stops being seedable. Credentialed templates and Denial of service are
  never created automatically.
* `POST /api/cases/{id}/scan-jobs` accepts `template_key`; it resolves to the built-in policy.
* Policies created in **Scan policies** are `active` immediately. Built-in policies return 409 on edit.
* Status: **"Complete with warnings" only for real problems** (plugin errors, skipped or unfinished hosts,
  check warnings). A finished unauthenticated scan is "Complete" with a neutral note. The job summary has
  `assessment.warnings` and `assessment.notes`; `clean_eligible` is unchanged (still needs credentials).
* UI: the Launch dialog reloads policies when it opens, shows load errors, groups options (your policies,
  Nexpose, Nessus, threat checks), preselects **Nexpose · Full audit**, disables policies missing a
  credential, and falls back to templates if no policy row exists. Scan policies shows Built-in badges and
  the Nexpose/Nessus equivalent. Scan details shows notes separately and a "Scanner laptop: scanned through
  loopback" line.
* Migration `044_builtin_scan_policies_v180.sql` (idempotent; the API applies the same column change itself).
* Unrelated build fix: `frontend/src/hooks/usePipelineStepTracker.ts` was missing the import of
  `sanitizeRegisterError`, which made `tsc -b` (and so every `npm run build:*`) fail.

## 3. Nexpose / InsightVM templates

Names and scope follow Rapid7's "Scan templates appendix" (docs.rapid7.com/insightvm/scan-templates).
"Default ports" are the Aetheris service port policy; Rapid7 does not publish its internal default list.

| Nexpose / InsightVM template | Aetheris key | Greenbone config | TCP ports | UDP ports | Credentials | Built-in policy |
|---|---|---|---|---|---|---|
| Full audit | `nx_full_audit` | Full and fast | 154 | 33 | optional | yes |
| Exhaustive | `nx_exhaustive` | Full and fast | all 65,535 | 23 | optional | yes |
| Safe network audit | `nx_safe_network_audit` | Full and fast | 154 | 33 | optional | yes |
| Discovery scan | `nx_discovery` | Discovery | 154 | 33 | optional | yes |
| Discovery scan (aggressive) | `nx_discovery_aggressive` | Discovery | 154 | 33 | optional | yes |
| Internet DMZ audit | `nx_internet_dmz_audit` | Full and fast | 62 | 7 | optional | yes |
| Web audit | `nx_web_audit` | Full and fast | 24 | 0 | optional | yes |
| Penetration test | `nx_penetration_test` | Full and fast | all 65,535 | 23 | optional | yes |
| Microsoft hotfix | `nx_microsoft_hotfix` | Full and fast | 5 | 0 | SMB | no - needs credential |
| Linux RPMs | `nx_linux_rpms` | Full and fast | 1 | 0 | SSH | no - needs credential |
| PCI ASV external audit | `nx_pci_asv_external` | Full and fast | all 65,535 | 23 | optional | yes |
| PCI internal audit | `nx_pci_internal` | Full and fast | 156 | 33 | optional | yes |
| HIPAA compliance | `nx_hipaa` | Full and fast | 154 | 33 | optional | yes |
| Sarbanes-Oxley (SOX) compliance | `nx_sox` | Full and fast | 154 | 33 | optional | yes |
| SCADA audit | `nx_scada_audit` | Full and fast | 17 | 4 | optional | yes |
| CIS | `nx_cis` | Full and fast | 154 | 0 | SMB / SSH | no - needs credential |
| DISA | `nx_disa` | Full and fast | 154 | 0 | SMB / SSH | no - needs credential |
| Denial of service | `nx_denial_of_service` | Full and fast | 154 | 33 | optional | no - unsafe |

Not supported (documented in `scan_templates.json` → `not_supported`): **FDCC** and **USGCB** (Windows
XP/Vista/7 government baselines; Greenbone ships no content) and the deprecated **Full audit with Web
spider**. CIS and DISA run Greenbone's Policy/Compliance checks, which cover fewer benchmarks than Rapid7
Policy Manager. Aetheris never discovers assets outside the authorized target list, unlike Nexpose's
Penetration test.

## 4. Service and port coverage added in policy 1.1

| Service | Category | TCP | UDP | Low+ findings it can produce |
|---|---|---|---|---|
| Echo / Discard / Daytime / Chargen / Time | Legacy services | 7, 9, 13, 19, 37 | 7, 19 | chargen/echo reflection and denial of service (CVE-1999-0103), information disclosure |
| Finger | Legacy services | 79 | — | user enumeration and information disclosure |
| HTTP web servers (extended) | Web | 8008, 8081 | — | outdated servers and frameworks, missing security controls, exposed admin pages, injection flaws |
| Microsoft RPC / WMI endpoint mapper (extended) | Windows | 593 | — | exposed DCE/RPC endpoints, RPC CVEs, RPC over HTTP (593) endpoint exposure |
| Service Location Protocol (SLP) | Network infrastructure | 427 | 427 | OpenSLP heap overflow on VMware ESXi (CVE-2021-21974), SLP reflection/amplification (CVE-2023-29552) |
| LPD printing | Printers | 515 | — | unauthenticated print queue access, LPD daemon CVEs |
| Intel AMT / vPro | Out-of-band management | 623, 664, 16992, 16993, 16994, 16995 | — | INTEL-SA-00075 authentication bypass (Critical), outdated AMT firmware on business laptops and desktops |
| Open proxy (SOCKS / HTTP proxy) | Web | 1080, 3128, 8888 | — | open proxy relay, outdated Squid or proxy software with known CVEs |
| HCL / IBM Domino (Lotus Notes) | Mail | 1352 | — | outdated Domino servers with known CVEs, information disclosure |
| IBM MQ | Messaging | 1414 | — | unauthenticated channels, outdated MQ with known CVEs |
| Citrix ICA / CGP | Remote access | 1494, 2598 | — | outdated Citrix Virtual Apps with known CVEs, unencrypted ICA sessions |
| Oracle Database / TNS (extended) | Databases | 2483, 2484 | — | TNS listener CVEs, default accounts |
| cPanel / WHM | Web | 2082, 2083, 2086, 2087 | — | outdated cPanel/WHM with known CVEs, exposed administrative login |
| etcd | Containers | 2379, 2380 | — | unauthenticated key/value access exposing Kubernetes secrets |
| SAP (Dispatcher / Gateway / SAProuter / Management Console) | Application servers | 3200, 3299, 3300, 50013 | — | SAProuter and Gateway misconfiguration, SAP Management Console information disclosure |
| iSCSI | File transfer | 3260 | — | unauthenticated targets exposing disk volumes |
| Subversion (svnserve) | Web | 3690 | — | unauthenticated repository read access |
| Erlang Port Mapper (EPMD) | Messaging | 4369 | — | Erlang node enumeration, cookie brute force leading to code execution |
| SIP / VoIP (extended) | VoIP | 5060, 5061 | — | unauthenticated registration, SIP stack CVEs |
| XMPP | Messaging | 5222, 5269 | — | weak or missing TLS, outdated XMPP servers with known CVEs |
| X11 / XDMCP | Remote access | 6000, 6001, 6002, 6003, 6004, 6005 | 177 | unauthenticated X server access (screen and keystroke capture), open XDMCP |
| IRC | Messaging | 6667, 6697 | — | backdoored UnrealIRCd (CVE-2010-2075), outdated IRC daemons |
| Cassandra / Neo4j / InfluxDB | Databases | 7474, 8086, 9042 | — | unauthenticated database access, outdated versions with known CVEs |
| TR-069 / CWMP | Network infrastructure | 7547 | — | Misfortune Cookie (CVE-2014-9222) and TR-064 command injection on routers |
| Apache Hadoop (YARN / HDFS) | Application servers | 8088, 9870, 50070 | — | unauthenticated YARN ResourceManager job submission (remote code execution), open HDFS web UI |
| Apache ActiveMQ | Messaging | 8161, 61616 | — | OpenWire deserialization remote code execution (CVE-2023-46604, Critical), default web console credentials |
| MikroTik RouterOS (Winbox / API) | Network infrastructure | 8291, 8728, 8729 | — | Winbox credential disclosure (CVE-2018-14847), outdated RouterOS |
| Apache Solr | Application servers | 8983 | — | Log4Shell, Velocity template remote code execution (CVE-2019-17558), unauthenticated admin API |
| kubelet (extended) | Containers | 10255 | — | anonymous kubelet API leading to container exec, read-only kubelet port (10255) exposing pod data |
| MongoDB (extended) | Databases | 27018 | — | unauthenticated databases, outdated versions |
| IBM Db2 | Databases | 50000 | 523 | outdated Db2 with known CVEs, discovery service information disclosure |
| WS-Discovery | Network infrastructure | — | 3702 | WS-Discovery reflection/amplification |
| CoAP (IoT) | Network infrastructure | — | 5683 | CoAP reflection/amplification, unauthenticated IoT resources |
| Ubiquiti discovery | Network infrastructure | — | 10001 | discovery protocol amplification and device information disclosure |

SCADA/ICS ports (102, 502, 2404, 20000, 44818/tcp; 2222, 47808/udp) are deliberately **not** in the default
scope, because some controllers fail when probed by a general scan. Only the SCADA audit template scans them.

## 5. Upgrade

**Central server**
1. Copy the overlay over the project folder.
2. Apply `migrations/044_builtin_scan_policies_v180.sql` (or let the API add the columns on first use).
   It also activates existing `draft` policies.
3. Rebuild and restart the API and the vuln frontend, for example
   `docker compose -f services/vuln/docker-compose.yml --project-directory . up -d --build api frontend`.

**Laptop**
1. Extract the overlay over the laptop-scanner folder. Keep `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`.
2. Run `Start-Laptop.cmd` once, so the new `Write-LanFingerprint.ps1` writes `host_ips`.
3. `docker compose build scanner-agent` then `docker compose up -d` (this also recreates `ospd-openvas`
   with the loopback mapping).

## 6. Checking a run

```powershell
Get-Content .lan-fingerprint                      # must contain "host_ips"
docker compose logs --tail 3000 scanner-agent | Select-String 'self_target|port_discovery|No exposed'
Get-Content logs\ip\<job-id>\<ip>.jsonl | Select-String 'self_target'
```
* `self_target_check` with `is_self: true` and `self_target` with `local_open_ports` → the laptop was scanned
  through the loopback; Low+ findings appear under its IP.
* `self_target_unreliable` → Docker Desktop's loopback accepted every port; the network path was used.
* Scanning **other** client hosts is unchanged. If a client host drops every port, the result is still
  "No exposed services": allow the scanner through its firewall (Private/Domain profile, or the File and
  Printer Sharing / Remote Service Management rules) or use a credentialed policy (Microsoft hotfix with SMB).

## 7. Testing

* Laptop agent: **308 passed** (296 + 12 new in `tests/test_self_target_v180.py`): own-address detection,
  stale fingerprint rejection, accept-all fallback, Greenbone target uses the loopback while results keep the
  authorized IP, restart recovery, the screenshot job end to end, notes vs warnings, hotspot fingerprint.
  Eight older tests changed only where they pinned counts (67/87/25), the build number, or the
  Nessus-only template rule.
* Central backend: **200 passed**, 3 failed. The same 3 fail on the original V1.7.0 package
  (`test_edge_evidence_recovery`, `test_scan_job_network_identity`, `test_finding_api_preserves_v2_basis…`).
  The 11 new tests include 2 that run on PostgreSQL 16 (set `AETHERIS_TEST_PG_URL`): seeding,
  repair after purge, read-only built-ins. Migration 044 was run twice on PostgreSQL 16.
* Launch-by-template was exercised on PostgreSQL against an edge-agent scanner: job linked to
  "Nexpose · Full audit"; Microsoft hotfix without a credential refused with `policy_credentials_missing`.
* Frontend: `tsc --noEmit` clean; `npm run build:vuln` and `build:unified` succeed.
* **Not tested live:** Docker Desktop's loopback behaviour on the laptop (the accept-all guard covers a proxy
  that answers every port), and `Write-LanFingerprint.ps1` (no PowerShell in the build environment).
