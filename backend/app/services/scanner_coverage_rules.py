"""V1.10.3: central re-check of the scanner agent's per-host coverage verdict.

Agents up to 1.10.2 treated every Greenbone check with "nmap" in its name as a
port scanner. "Nmap OS Identification (NASL wrapper)" only fingerprints the
operating system. When it timed out (90 s through the Docker Desktop loopback),
the host was reported as ``degraded_port_scan_failed`` although Greenbone had
enumerated its ports and run the service checks on them (jobs b6b7f60c and
ccf22aa0 on 192.168.0.163: ports 445/8090, SMB and TLS findings, 38 results).
The job then read "Completed · coverage incomplete".

The central server applies the corrected rule to every upload and when it
reads stored jobs, so results from agents that are not yet updated are shown
correctly. A genuine port-scanner failure (Nmap NASL wrapper, OpenVAS TCP
scanner, Ping Host, Services ...) or a host with no enumerated port is left
incomplete: that remains an honest "not fully assessed".
"""
from __future__ import annotations

import re
from typing import Any

PORT_SCANNER_OIDS = frozenset({
    "1.3.6.1.4.1.25623.1.0.14259",   # Nmap (NASL wrapper)
    "1.3.6.1.4.1.25623.1.0.100315",  # Ping Host
    "1.3.6.1.4.1.25623.1.0.10330",   # Services
    "1.3.6.1.4.1.25623.1.0.900239",  # Open TCP Port (legacy)
    "1.3.6.1.4.1.25623.1.0.108521",  # Nmap UDP
    "1.3.6.1.4.1.25623.1.0.11219",   # SYN Scan
    "1.3.6.1.4.1.25623.1.0.10335",   # OpenVAS TCP scanner
})
NOT_PORT_SCANNER_OIDS = frozenset({
    "1.3.6.1.4.1.25623.1.0.108021",  # Nmap OS Identification (NASL wrapper)
    "1.3.6.1.4.1.25623.1.0.108525",  # Service Detection (wrapped) with nmap
    "1.3.6.1.4.1.25623.1.0.66286",   # Service Detection (unknown) with nmap
})
_NOT_SCANNER_NAME_RE = re.compile(
    r"\bos (identification|detection|fingerprint)|service detection|\bnse\b|with nmap", re.I
)
_SCANNER_NAME_RE = re.compile(
    r"^nmap \(nasl wrapper\)$|^nmap udp|^ping host$|port ?scan|^services$|open tcp port|"
    r"openvasd port|tcp scanner|^syn scan", re.I
)
_SCANNER_DESC_RE = re.compile(r"nmap \(nasl wrapper\)|port ?scan|ping host|tcp scanner", re.I)
_TIMEOUT_RE = re.compile(r"time ?out|timed out|killed|exceeded|took too long|was interrupted", re.I)


def is_port_scanner_error(oid: Any, name: Any, description: Any = "") -> bool:
    """True only when the failed check is one that enumerates ports."""
    oid_s = str(oid or "").strip()
    name_s = str(name or "").strip()
    desc_s = str(description or "")
    if oid_s in NOT_PORT_SCANNER_OIDS or (name_s and _NOT_SCANNER_NAME_RE.search(name_s)):
        return False
    if oid_s in PORT_SCANNER_OIDS or (name_s and _SCANNER_NAME_RE.search(name_s)):
        return True
    return bool(_TIMEOUT_RE.search(desc_s) and _SCANNER_DESC_RE.search(desc_s))


def _ports(cov: dict[str, Any], key: str) -> list[int]:
    out: set[int] = set()
    for raw in cov.get(key) or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(raw, bool) and 1 <= port <= 65535:
            out.add(port)
    return sorted(out)


def normalize_host_coverage(cov: Any) -> Any:
    """Return the coverage with a false port-scan failure reclassified (else unchanged)."""
    if not isinstance(cov, dict) or str(cov.get("verdict") or "") != "degraded_port_scan_failed":
        return cov
    if cov.get("time_limited"):
        return cov
    errors = [e for e in (cov.get("port_scanner_errors") or []) if isinstance(e, dict)]
    # Reclassify only with evidence: at least one error row, and none of them a port scanner.
    if not errors or any(is_port_scanner_error(e.get("nvt_oid"), e.get("nvt_name"), e.get("description"))
                         for e in errors):
        return cov
    tcp, udp = _ports(cov, "open_tcp_ports"), _ports(cov, "open_udp_ports")
    if not tcp and not udp:
        return cov
    out = dict(cov)
    warnings = [str(w) for w in (out.get("warnings") or []) if str(w).strip()]
    names: list[str] = []
    for err in errors:
        label = str(err.get("nvt_name") or err.get("nvt_oid") or "check")
        names.append(label)
        desc = str(err.get("description") or "").strip()
        text = f"{label}: {desc.splitlines()[0][:160] if desc else 'error'}"[:240]
        if text not in warnings:
            warnings.append(text)
    named = ", ".join(sorted(set(names)))[:160] or "the failed check"
    out.update({
        "port_scanner_errors": [],
        "warnings": warnings[-20:],
        "verdict": "observed_unverified",
        "network_scan_complete": True,
        "reclassified_from": "degraded_port_scan_failed",
        "reason": (
            f"Network scan finished: {len(tcp)} open TCP / {len(udp)} UDP port(s); {named} is not a port "
            "scanner, so its timeout is a check warning, not an incomplete port scan"
        ),
    })
    return out


def normalize_coverage_map(host_cov: Any) -> Any:
    if not isinstance(host_cov, dict):
        return host_cov
    return {host: normalize_host_coverage(cov) for host, cov in host_cov.items()}


def effective_degraded_hosts(orch: dict[str, Any] | None) -> list[str]:
    """Stored degraded hosts minus those the corrected rule no longer counts as incomplete."""
    orch = orch or {}
    degraded = [str(h) for h in (orch.get("degraded_hosts") or [])]
    cov = orch.get("host_coverage") if isinstance(orch.get("host_coverage"), dict) else {}
    keep: list[str] = []
    for host in degraded:
        row = cov.get(host)
        if isinstance(row, dict) and normalize_host_coverage(row).get("reclassified_from"):
            continue
        keep.append(host)
    return keep


def effective_network_complete_hosts(orch: dict[str, Any] | None) -> list[str]:
    orch = orch or {}
    done = {str(h) for h in (orch.get("network_complete_hosts") or [])}
    degraded = {str(h) for h in (orch.get("degraded_hosts") or [])}
    still = set(effective_degraded_hosts(orch))
    return sorted(done | (degraded - still))
