# Scanner V1.5.8: Windows / Docker / OSPd target-route diagnostics

## Evidence from incident

The Windows laptop and scanner-agent container both received TCP timeouts on
ports 22, 80, 135, 139, 443, 445, 3389, 8080, and 8443 for `192.168.0.164`.
The third diagnostic (OSPd) failed because Windows PowerShell stripped Python
string-literal quotes from the `python3 -c` argument. None of this evidence
establishes any open listener, service identity, NVT coverage or vulnerability.

## Changes

- Removed the fragile OSPd `python3 -c <PowerShell multiline string>` invocation.
  The diagnostic now sends the Python source over standard input using
  `docker compose exec -T ospd-openvas python3 - <target> ...`.
- New `scripts/ospd-network-probe.py` provides JSON with actual TCP connection
  outcomes from the OSPd container using concurrent checks, with a 256-port cap.
- Aligned Windows, scanner-agent and OSPd on the **same user-selected port list**
  and timeout. Port-range input is bounded and no subnet is automatically scanned.
- Added `Find-NetRoute`, local IPv4 interface, neighbor-table and ICMP supporting
  observations, with non-fatal fallbacks if Windows networking cmdlets are missing.
- Windows socket results distinguish OPEN, REFUSED_CLOSED, TIMEOUT_OR_FILTERED,
  HOST_UNREACHABLE and NETWORK_UNREACHABLE.
- Added `Test-Target-Network.cmd` launcher to avoid permanently changing the
  PowerShell execution policy for a trusted local diagnostic.
- No Docker image modification, no scanner-engine setting changes, no target
  firewall modification and **no Docker volume deletion**.

## Run on Windows laptop (PowerShell)

```powershell
cd C:\Users\Public\laptop-scanner
.\Test-Target-Network.cmd 192.168.0.164
```

To specify a different authorized port set or longer timeout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Test-Target-Network.ps1" -TargetIP 192.168.0.164 -Ports "22,80,443,445,3389,8000-8010" -TimeoutSec 3
```

**No scanner container rebuild is required for the OSPd fix**; the Python probe
is streamed into the existing OSPd image. Scanner-agent source must be at least
V1.5.7 to provide `agent.network_diagnostics`.

## How to interpret output

- **Windows and scanner-agent and OSPd all time out:** validate the actual
  target IP, power, VLAN/subnet route, ACLs and target host firewall. There
  may be no accessible TCP services on these nine ports. This cannot be fixed
  by changing React, severity weights, Greenbone feed or reporting code.
- **Windows OPEN but Docker fails:** inspect Docker Desktop/WSL networking and
  host routing/firewall between Docker and the client VLAN.
- **Windows and scanner-agent OPEN but OSPd fails:** inspect the OSPd container's
  route, network policy, and scan capabilities separately.
- **Any TCP REFUSED:** host/network path answered but *that port is closed*.
- **Any TCP OPEN:** a listener was reachable, not evidence of a vulnerability.
  Use the native Greenbone NVT report and its configured task scope to verify
  that actual vulnerability tests were performed.
- **Ping fails:** ICMP may be filtered; assess the TCP, routing and ARP evidence.

Do not enable every firewall service, expose SMB/RDP publicly, or assume that
missing Critical/High findings are bugs. For authorized corporate assessment,
coordinate the correct host IP, firewall allowance from the scanner source,
and credentialed scanning access with the network owner.

## Validation

Source Python compiles. 145 scanner tests pass (including 4 new tests).
PowerShell syntax is reviewed statically. Live PowerShell/Docker/OSPd/LAN scans
must be verified on the target laptop.
