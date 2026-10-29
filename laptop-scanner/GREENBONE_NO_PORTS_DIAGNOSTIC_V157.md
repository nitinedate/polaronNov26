# V1.5.7 - No-open-port report / scan coverage repair

## Observed

Job `46552c1d-8558-4cff-946d-d1ab2fcfd8b2`, IP `192.168.0.164`:
OpenVAS report `29b781b6-70cb-4836-beb3-18a12ef7da6a` returned **3 informational rows, zero open ports**. This is **incomplete**, not proof of a clean host. `ports` in `scan_status` events are *configured candidates*, not observed open sockets.

## Changes

1. Full/Nexus scan mode always selects `optimize_test=no` for scanner preferences, including if a previous deployment's `.env` still contains `GVM_OPTIMIZE_TEST=yes`. `fast` retains its independent setting.
2. A result row or open port no longer promotes the full service catalog to `full` scan coverage. Native vulnerability findings are still preserved.
3. Per-IP scanner-agent TCP preprobe evidence is compared against Greenbone's native reported ports; if they disagree, the job is explicitly incomplete (`degraded_discovery_mismatch`) with an actionable reason and source-separated fields.
4. Added `Test-Target-Network.ps1` and `python -m agent.network_diagnostics` for route/ACL/listener diagnosis from Windows, scanner-agent and OSPd without stopping scans.
5. Preserved the configured service catalog for scan scope, including extensible `SERVICE_EXTRA_TCP_PORTS`/`SERVICE_EXTRA_UDP_PORTS`; no unauthorized targets are discovered automatically.
6. Restored compatibility helpers for the versioned 52-family service registry and older local scanner adapters.
7. Bounded port diagnostics to 256 ports, without inventing severity for open sockets.
8. Stopped scans at an operator-defined per-IP time budget are flagged `degraded_time_budget`, never falsely marked service-complete; available partial findings stay attached.
9. Updated source build stamp to `1.5.7-v47.0`, which identifies the actually running image even if an older local `.env` has a stale AGENT_VERSION setting.

## Deployment

Back up the existing laptop scanner folder and preserve its `.env`, runtime credentials, and Docker volumes. This distribution deliberately excludes secrets, local runtime logs, cached files and tokens. Extract the complete source into `C:\Users\Public\laptop-scanner`.

From PowerShell in the project directory:

```powershell
# Do NOT rebuild/restart during a running job.
docker compose config --quiet
docker compose build scanner-agent
docker compose up -d --no-deps scanner-agent
.\Test-Target-Network.ps1 -TargetIP 192.168.0.164
```

If Windows reports OPEN but scanner-agent or OSPd cannot connect, inspect Windows Firewall, Docker Desktop/WSL routing, client network/VLAN, and VPN/LAN access. If all three cannot connect, check the target's listener, address, host firewall and scan authorization. If the scanner agent connects but OSPd cannot, investigate OSPd container network/capabilities and Greenbone port-scan config.

Use the *native Greenbone report*, scanner error records, actual target/port-list and NVT inventory before claiming a full scan. A remote host with no accessible services may legitimately have no reportable service vulnerabilities.

## Validation

Python regression tests: 141 passed locally. Docker Desktop/OSPd and real client-LAN scanning were not accessible in this environment. Re-run the target and inspect evidence after deploying.
