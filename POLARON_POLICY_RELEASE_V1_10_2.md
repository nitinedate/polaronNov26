# Polaron V1.10.2 — "Polaron policy" (default scan policy)

Date: 2026-10-22. Laptop agent build **1.10.2-v62.0**. Template catalog **aetheris-templates-1.4**.
Cumulative on the 2026-10-22 forensic package. No database migration.

## 1. What the policy is

**Polaron policy** = the ports of **Nessus · Basic Network Scan**, plus every port on which Nessus
reported a finding in the eight Polaron solution-set exports. It is preselected whenever a scan is launched.

| | TCP | UDP |
|---|---|---|
| Nessus · Basic Network Scan (Polaron service port policy `aetheris-service-ports-1.1`) | 154 | 33 |
| Ports with findings in the reports | 138 | 7 |
| of which already in Basic Network Scan | 30 | 5 |
| **added by the reports** | **108** | **2** (17 QOTD, 5355 LLMNR) |
| **Polaron policy total** | **262** | **35** |

Scanner settings are identical to Basic Network Scan:

- scan config: Full and fast;
- safe checks and optimize tests on;
- priority UDP;
- authorized targets treated as alive.

The report ports are pinned in the policy (`custom_tcp_ports` / `custom_udp_ports`), so they stay in scope even if a service is later disabled in the service port policy.

**Important.** In Polaron, "Nessus · Basic Network Scan" uses the Polaron service port policy (154 TCP / 33 UDP). It is not Tenable's own ~4,790-port Nessus default list. The Polaron policy builds on the Polaron definition.

### Source data

The eight uploaded Nessus exports:

- Core June 2026 and Core July;
- RRP June 2026;
- RRP Electrical May 2026;
- Lilavati December 2025;
- January 2026;
- Savarkar May and Savarkar September.

In total:

- 6,659 finding rows;
- 437 host-level rows on port 0 (for example "Unsupported Windows OS"), which carry no service port;
- 145 distinct protocol/port pairs.

Per-port evidence is in `docs/POLARON_POLICY_PORT_MATRIX.xlsx`. It has four sheets:

- **Summary**: live formulas;
- **Port Matrix**: all 297 policy ports with their source, service, classification, finding counts by risk, hosts, reports and top findings;
- **Report Evidence**: one row per export;
- **Findings**: the raw rows.

### Ports that differ per host (18 TCP)

- **10 are Windows dynamic RPC ports**: 49154–49193 and 56155. They carry the MS16-047 SAM/LSAD findings.
- **8 are SQL Server named-instance ports**: 49278, 49668, 56164, 56168, 57674, 58290, 61553 and 63891.

Windows and SQL Server assign these ports at start-up. They are kept so re-tests of the same hosts cover them. New hosts are found through 135/tcp (RPC endpoint mapper) and 1434/udp (SQL Server Browser), and both are in scope.

Another 18 ports above 49152 are fixed, service-specific listeners. For example, 62128 shows TLS 1.0/1.1 findings on 68 hosts.

### Credentials and other limits

Missing-patch findings in the reports (MS16-047, MS17-010, unsupported OS) need an SMB credential, exactly as in Nessus.

Use **Advanced Scan** (all 65,535 TCP ports) when a host may run services on other unlisted ports.

## 2. Default selection

- The template has `"default": true`. The catalog validator allows at most one default, and the default must be a seeded built-in policy.
  - `default_template_key()` returns it.
  - `GET /api/scan-policy-templates` and `GET /api/scan-policies` return `is_default`.
- **Launch scan** preselects the default from the server flag (the fallback key is `polaron`). The dropdown shows a first group, **Polaron (default)**, labelled "Polaron policy (default)".
- **Scan policies → New policy** starts from the Polaron template. The policy list shows a **Default** badge.
- The built-in "Polaron policy" row is created automatically in every tenant on the next policy list, as for every built-in since V1.8.0.
- **Not changed:** the explicit "— scanner default —" option, and API launches that name no policy, still use the scanner's own default.

## 3. Laptops that are not updated yet

Laptop agents re-expand a job by template key and reject keys they do not ship ("Unknown scan template"). Without a safeguard, every default scan on a v61 laptop would fail.

The safeguard: central compares the agent's advertised build with the template's `min_agent_build` (`v62.0`). An older agent, or one that advertises no build, receives the fully expanded settings without the template key. It then scans exactly the same 262 TCP / 35 UDP ports; only its policy snapshot does not name the template.

As a result, central and laptops can be updated in either order.

## 4. Files

- **Catalog**, kept identical on both sides:
  - `backend/app/services/scan_templates.json`
  - `laptop-scanner/scanner-agent/agent/scan_templates.json`
- **Policy module**, kept identical on both sides:
  - `backend/app/services/scanner_service_policy.py`
  - `laptop-scanner/scanner-agent/agent/service_policy.py`
- **Central backend:**
  - `backend/app/services/builtin_scan_policies.py` (Polaron vendor label)
  - `backend/app/services/scanner_agent_jobs.py` (older-agent fallback)
  - `backend/app/routers/vuln.py` (`is_default`)
- **Frontend:**
  - `frontend/src/pages/vuln/ScanJobsPage.tsx`
  - `frontend/src/pages/vuln/ScanPoliciesPage.tsx`
  - `frontend/src/lib/types/vuln.ts`
- **Agent:**
  - `laptop-scanner/scanner-agent/agent/__init__.py` (build `1.10.2-v62.0`)
- **Tests:**
  - new: `backend/tests/test_polaron_policy_v1102.py` (15)
  - new: `laptop-scanner/scanner-agent/tests/test_polaron_policy_v1102.py` (3)
  - new evidence fixtures: `polaron_report_ports.json`
  - updated pins: `test_no_false_clean_v157.py`, `test_no_nexus_budget_v163.py` (build string) and `test_templates_v165.py` (Polaron vendor rule)
- **Evidence:** `docs/POLARON_POLICY_PORT_MATRIX.xlsx`

## 5. Verification

Full detail is in `POLARON_POLICY_TEST_RESULTS_V1_10_2.txt`.

- The policy resolves to 262 TCP / 35 UDP.
  - The TCP set equals Basic Network Scan TCP ∪ the 138 report TCP ports; the UDP set equals Basic Network Scan UDP ∪ the 7 report UDP ports. Both are checked against a fixture derived from the reports, not from the template.
- A simulated v61 agent rejects the keyed request but runs the request central sends it and gets the identical port range.
- Backend and root suites: the same 217 failed / 20 errors as the original upload, so no test that passed before now fails. 2,114 tests passed.
- Laptop-agent suite: 437 passed, with the same 2 failures as the original.
- Frontend:
  - `tsc -b` is clean, and an error injected into the edited page was caught.
  - `vite build --mode vuln` builds.
- Workbook: 2,168 formulas recalculated with 0 errors, and the values were checked against the independently derived counts.

**Not verified:**

- a live scan;
- the Launch dialog in a browser;
- built-in seeding on PostgreSQL (the existing v180 seeding tests are skipped without `AETHERIS_TEST_PG_URL`);
- a v61 laptop claiming a real job.

## 6. Upgrade

**Central**

1. Copy the overlay over the project folder.
2. Rebuild and restart the API and the vuln frontend, for example:
   ```powershell
   docker compose -f services/vuln/docker-compose.yml --project-directory . up -d --build api frontend
   ```
3. Open **Scan policies**. "Polaron policy" appears with the Built-in and Default badges.

**Laptop**

1. Extract the overlay over the laptop-scanner folder. Keep `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`.
2. Rebuild and restart the agent:
   ```powershell
   docker compose build scanner-agent
   docker compose up -d
   ```
3. The agent then reports build `1.10.2+v62.0`.

**Check a run.** The job's policy snapshot shows `template: polaron`, `tcp_port_count: 262` and `udp_port_count: 35`. A not-yet-updated laptop shows the same counts without the template name.
