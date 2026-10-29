# V1.6.2 - Per-service audit and severity logging

This update applies to the **laptop scanner**. It adds read-only, evidence-backed
service logging for each authorized host, using the same 52-service catalog and
native Greenbone result IDs as the existing coverage report. It does not add
vulnerability plugins or change ports, task lifecycle, scan timeouts or ratings.

## When records are emitted

- **After the Greenbone task is created:** `SERVICE_PLAN` prints each requested
  service as `REQUESTED_NOT_VERIFIED`. This is not proof its NVTs ran.
- **After the IP reaches a terminal scan state:** `SERVICE_RESULT` prints each
  catalog service, status, highest **native-result-backed** severity, counts of
  Critical / High / Medium / Low / Info / Unscored, and observed port hints.
- **For source-matched native results:** `SERVICE_FINDING` prints severity, CVSS,
  port, plugin/NVT and title. This includes informational results.
- **At the end:** `SERVICE_AUDIT_END` counts native results that could not be
  matched to any service; they remain present in the original Greenbone report.

Status meanings: `finding` (native risk result), `observation` (native
observation/protocol context), `not-tested` (no sufficient native evidence),
`unsupported` (a required external collector is unavailable). `not-tested` is
never printed as `passed` or `clean`. Severity labels are from Greenbone's
parsed result or valid CVSS score, **not** the catalog's port priority.

Example (illustrative, not an actual scan):

```text
SERVICE_PLAN IP=192.0.2.9 id=SVC-06 service=SSH: OpenSSH / Dropbear status=REQUESTED_NOT_VERIFIED
SERVICE_RESULT IP=192.0.2.9 id=SVC-06 service=SSH: OpenSSH / Dropbear status=finding severity=Critical native_results=1 findings=1 ports=22/tcp [Critical=1,High=0,Medium=0,Low=0,Info=0,Unscored=0]
SERVICE_FINDING IP=192.0.2.9 service=SSH: OpenSSH / Dropbear severity=Critical CVSS=9.8 port=22/tcp nvt=1.3.6... title=OpenSSH security update
SERVICE_RESULT IP=192.0.2.9 id=SVC-01 service=SMB / CIFS status=not-tested severity=Not verified native_results=0 findings=0 ports=none [Critical=0,High=0,Medium=0,Low=0,Info=0,Unscored=0]
```

## PowerShell: follow service logs

Run on the **client laptop** from the installed project directory:

```powershell
cd C:\Users\Public\laptop-scanner
docker compose logs -f --tail 100 scanner-agent | Select-String 'SERVICE_PLAN|SERVICE_RESULT|SERVICE_FINDING|SERVICE_AUDIT'
```

Durable structured audit events are also written under:
`C:\Users\Public\laptop-scanner\logs\ip\<job-id>\<target-IP>.jsonl`.
This directory is already bind-mounted from `./logs` to `/app/logs`.

## Settings

```dotenv
SERVICE_AUDIT_ENABLED=true
SERVICE_AUDIT_INCLUDE_UNTESTED=true
SERVICE_AUDIT_LOG_FINDINGS=true
SERVICE_AUDIT_MAX_FINDING_LINES=100
```

The last setting limits detailed lines **per service per IP** to avoid a log
storm during a large scan. Severity counts are not truncated. The original
Greenbone report and central result upload are not modified. Defaults apply
even if the variables are not added to your existing `.env`.

## Update without losing scan data

Back up the existing project and retain its `.env`, runtime tokens, Greenbone
Docker volumes, feed data and `logs` directory. Wait for active jobs and their
result uploads to complete. Then extract the complete laptop-scanner ZIP and run:

```powershell
cd C:\Users\Public\laptop-scanner
docker compose config --quiet
docker compose build scanner-agent
docker compose up -d --no-deps scanner-agent
```

Only a new terminal per-IP report produces `SERVICE_RESULT` rows. Historical
scans do not retroactively generate these logs. The check is source-driven:
listing all 52 entries does **not** establish 52 successful vulnerability
assessments or guarantee Critical/High findings. Live Docker/GMP verification
must be completed on the client laptop.
