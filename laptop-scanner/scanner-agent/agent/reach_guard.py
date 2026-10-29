"""V1.10.1 — a job in which no target answered from a laptop on another network.

Field: job 6bee3375 (25 IPs) completed with "No TCP port answered at all" on every IP,
including IPs where an earlier job (3df13145) had found open ports and 11 findings. A
job whose targets all stay silent while none of them is on the laptop's own network
was not assessed at all (wrong network, or routing to that network blocked); it must
not be reported as a completed assessment. Targets on the laptop's own network that
are all silent stay a result (PCs off, firewalls dropping everything).
"""
from __future__ import annotations

import ipaddress
from typing import Any


def _all_silent(host_coverage: dict[str, Any]) -> list[str] | None:
    hosts: list[str] = []
    for host, cov in (host_coverage or {}).items():
        if not isinstance(cov, dict):
            continue
        if cov.get("self_scan") or cov.get("verdict") != "no_exposed_services" or cov.get("host_responded"):
            return None
        hosts.append(str(host))
    return hosts


def unreachable_network_error(evidence: dict[str, Any], lan_fp: dict[str, Any] | None) -> str | None:
    hosts = _all_silent(evidence.get("host_coverage") or {})
    if not hosts or len(hosts) < 2:
        return None
    from agent.lan_fingerprint import is_docker_nat_fingerprint

    if not lan_fp or is_docker_nat_fingerprint(lan_fp):
        return None  # only Docker's own network is known, not the laptop's LAN
    try:
        net = ipaddress.ip_network(str((lan_fp or {}).get("subnet") or ""), strict=False)
    except ValueError:
        return None  # the laptop's network is unknown: cannot tell, keep the result
    for host in hosts:
        try:
            if ipaddress.ip_address(host) in net:
                return None
        except ValueError:
            return None
    gateway = str((lan_fp or {}).get("gateway") or "").strip()
    return (
        f"Nothing was assessed: none of the {len(hosts)} IPs answered on any probed TCP port, and none of "
        f"them is on this laptop's network ({net}{', gateway ' + gateway if gateway else ''}). Connect the "
        "laptop to the targets' network (or launch the scan on a laptop that is there) and run it again."
    )
