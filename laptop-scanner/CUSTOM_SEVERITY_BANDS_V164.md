# Custom vulnerability severity bands — V1.6.4 (2026-10-14)

Both Polaron central backend and the laptop Greenbone agent use **organization-defined**
CVSS score-to-severity mappings rather than the default CVSS qualitative labels.

| Label | Numeric CVSS score |
| --- | --- |
| Critical | 8.0–10.0 |
| High | 6.0–7.9 |
| Medium | 4.0–5.9 |
| Low | 0.1–3.9 |
| Info | 0.0 |

Threshold comparisons use `>=` directly (for example, 7.99 is High, 8.0
is Critical). CVSS scores are not modified. The same bands apply when the
selected source score is CVSS v2, v3, or v4. Risk Number/weighted asset-risk
bands are **not** changed by this CVSS severity policy.

Updated components: central `aetheris_severity.py` including SQL grouping,
`multi_scanner_clients.py`, `vuln_nessus_parity.py`; laptop
`severity_policy.py`, `gmp_local.py`, `service_audit.py`; both `.env.example`
files and regression tests. Historical stored finding severity strings are not
rewritten: dynamic SQL queries and new reads use the current numeric bands,
and new ingests store the revised labels. Cached past exports may need
regeneration.

**Existing production `.env`** values override defaults. From each project's
root, run the included `Set-Severity-Bands.ps1` explicitly, with appropriate
PowerShell execution-policy permissions. It creates a timestamped `.env`
backup and only updates the four severity values. Never replace the existing
`.env` with `.env.example`, and preserve Docker volumes.

**Deployment:** Recreate the central vuln `api` and `worker-nessus` services,
and rebuild/recreate the laptop `scanner-agent` once active scans have finished.
Run new authorized scans to verify that the same CVSS values now receive the
updated categories and that service audit logs agree with central reports.

**Scope:** This change modifies vulnerability *categorization*, not discovery,
NVT coverage, Greenbone task lifecycles, CVSS source scores, or findings count.

Historical central database severity labels can be reconciled with the optional
central-project migration `migrations/043_custom_cvss_severity_v164.sql`
after taking a database backup; the laptop ZIP does not contain migrations.
