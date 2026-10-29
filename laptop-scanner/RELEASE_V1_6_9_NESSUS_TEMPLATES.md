# Laptop Scanner / Polaron V1.6.9 — four more Nessus templates, threat checks relabelled

Date: 2026-10-14. Cumulative (includes V1.6.5–V1.6.8). Agent build **1.6.9-v48.1**.

## 1. New templates (matching the Nessus 10.11 scanner list)

| Template | Nessus equivalent | How Aetheris runs it | What each IP shows |
|---|---|---|---|
| **Ping-Only Discovery** | Ping-Only Discovery | Greenbone "Host Discovery" config: alive test only (ICMP, TCP-ACK, ARP), no port scan, no checks | **Alive** – answered the ping, or **skipped: not alive** |
| **Credential Validation** | Credential Validation | Login ports only (22, 135, 139, 445, 5985, 5986); Credentials/Settings/General families; needs an SMB or SSH credential | **Credential check** – "SMB login succeeded, SSH login failed", or "no login result reported" |
| **Advanced Dynamic Scan** | Advanced Dynamic Scan | Checks chosen by filter (minimum severity, name contains, optional families) instead of fixed families; rebuilt after each feed update, so new matching checks join automatically | Normal vulnerability result. The task policy shows the filter. |
| **Policy Compliance Auditing** | Policy Compliance Auditing | Greenbone Policy, Compliance and IT-Grundschutz families; needs an SMB or SSH credential | **Compliance audit finished**, plus login status |

Details:
- **Advanced Dynamic:**
  - The default filter is severity 7.0 and above (High and Critical). In the policy you can choose Low+, Medium+, High+ or Critical only, and add "Check name contains" text.
  - The filter is structured and validated; no raw filter text reaches gvmd. gvmd filters have no `>=`, so "7.0 and above" is sent as `severity>6.9`. Severities have one decimal, so this is exact.
  - A filter that matches nothing, or that gvmd rejects, **refuses the job** with a clear message. It never silently runs all checks.
  - The detection checks that the selected checks depend on still run, through OpenVAS's automatic dependency loading.
- **Policy Compliance:**
  - Greenbone's community compliance checks are far fewer than Nessus audit files; CIS and DISA benchmarks are not included.
  - gvmd **silently ignores** family names a feed doesn't have (verified in gvmd source). If this feed has none of the compliance families, the job is **refused** instead of quietly running discovery only. Families that are missing are listed in the task policy.
- **Credential Validation:** login outcomes come from Greenbone's `Auth-<protocol>-<Success|Failure>` host details. These are parsed the same way as Greenbone's own web interface: any success for a protocol counts as success. Every scan now records this as `auth_status`.
- **Ping-Only from a laptop:** ARP ping cannot cross Docker Desktop's network layer. A host that also blocks ICMP and the TCP probe ports can look not alive.

## 2. Relabelled
- **Threat checks.** WannaCry, Zerologon, PrintNightmare, Log4Shell and ProxyLogon are now named "Threat check: …" and show **"Aetheris threat check"** instead of a Nessus template name. None of them is in the Nessus 10.11 scanner list; Tenable publishes vulnerability-specific templates separately. What they scan is unchanged.
- **Web Application Tests** is labelled "Nessus 10.9 and earlier". It is not in the 10.11 scanner list, because Nessus Expert now has separate web-app templates.

## 3. Verified while building this
- gvmd **whole-only families**: every "… Local Security Checks" family must be selected entirely and as growing (`manage.h` `FAMILIES_WHOLE_ONLY`, `manage_set_config_families`). The V1.6.8 vulnerability-only builder and the new dynamic builder both do this, so gvmd will not reject them.
- gvmd NVT filter columns include `family`, `severity` and `name`, and the comparison operators are `=`, `~`, `>` and `<`.

## 4. Upgrade
No `.env` or `openvas.conf` change is needed beyond V1.6.8.
- **Laptop:** extract over the folder, keeping `.env`, `.lan-fingerprint`, `scanner-agent\runtime\` and `logs\`. Then run `docker compose build scanner-agent` and `docker compose up -d --no-deps scanner-agent`.
- **Central:** copy the overlay files and rebuild the backend and frontend images. No database migration is needed.

## 5. Testing
- Laptop agent: **286 passed** (13 new). The new tests cover:
  - filter validation and gvmd operator use;
  - honouring an explicit family list;
  - refusing instead of silently falling back;
  - reporting or refusing missing compliance families;
  - parsing login results;
  - ping-only verdicts, including a not-alive host in the real job loop, which is skipped while the job still completes;
  - each template's Greenbone config and quality-floor handling.
- Central focused suite: 78 passed. The same 4 failures are pre-existing in the original package.
- Frontend: no type errors in the changed files; `vite build --mode vuln` succeeds.
- **Not tested live:**
  - whether this feed registers `Auth-*` details with the reduced Credential Validation family set (if it doesn't, the IP says "no login result reported");
  - which compliance families the installed community feed contains;
  - ping results through Docker Desktop.
