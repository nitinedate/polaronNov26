"""Fast pre-scan TCP discovery for the portable Greenbone scanner.

The purpose is not to decide whether an authorized host is alive.  It records
which candidate service ports answer so the scan log can show them.  The
OpenVAS task still scans the Nessus-style catalog in vuln_ports.json, using
SYN inside OpenVAS.  A short connect probe that only sees 135/139/445, or
that sees nothing, must not drop SSH, TLS, SMB, or the rest of that catalog.
"""

from __future__ import annotations

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

DEFAULT_FAST_RANGE = (
    "T:21-23,T:25,T:53,T:80,T:81,T:88,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:631,T:993,T:995,T:1433,T:1521,T:1723,T:2049,"
    "T:3000,T:3306,T:3389,T:5432,T:5672,T:5900,T:5985,T:6379,T:6443,"
    "T:8080,T:8443,T:9000,T:9418,T:27017"
)


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def enabled() -> bool:
    return _env_bool("PORT_DISCOVERY_ENABLED", True)


def parse_tcp_ports(spec: str) -> list[int]:
    raw = (spec or "").strip()
    if raw.upper().startswith("T:"):
        raw = raw[2:]
    out: list[int] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if token.upper().startswith("T:"):
            token = token[2:]
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.extend(range(max(1, lo), min(65535, hi) + 1))
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            out.append(port)
    return sorted(set(out))


def ports_to_gvm_range(ports: list[int]) -> str:
    clean = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    if not clean:
        return DEFAULT_FAST_RANGE
    return ",".join(f"T:{p}" for p in clean)


def _timeout_sec() -> float:
    try:
        return max(0.05, min(2.0, float(os.environ.get("PORT_DISCOVERY_TIMEOUT_SEC") or 1.0)))
    except (TypeError, ValueError):
        return 1.0


def _workers(total_probes: int) -> int:
    try:
        configured = int(os.environ.get("PORT_DISCOVERY_WORKERS") or 32)
    except (TypeError, ValueError):
        configured = 32
    return max(1, min(max(8, configured), max(1, total_probes), 96))


def port_semaphore_limit() -> int:
    """Connects to ONE IP in flight at once (V1.10.3, SCAN_PORT_SEMAPHORE, default 6)."""
    try:
        from agent.scan_performance import port_semaphore

        return port_semaphore()
    except Exception:
        return 6


def candidate_range() -> str:
    profile = (os.environ.get("PORT_PROFILE") or "").strip().lower()
    if profile in {"nexus", "catalog"}:
        # V1.7.0: probe exactly the TCP ports of the service port policy; the
        # probe is the closed/filtered evidence per service, so the separate
        # PORT_DISCOVERY_RANGE list must not narrow it for these profiles.
        from agent.service_policy import policy_ports

        tcp, _udp = policy_ports()
        if tcp:
            return ",".join(f"T:{p}" for p in tcp)
    if profile in {"vuln", "nessus"}:
        from agent.vuln_ports import tcp_gmp_range

        return tcp_gmp_range()
    return (os.environ.get("PORT_DISCOVERY_RANGE") or DEFAULT_FAST_RANGE).strip() or DEFAULT_FAST_RANGE


def probe_tcp_port_states(
    hosts: list[str],
    *,
    port_range: str | None = None,
    timeout: float | None = None,
) -> dict[str, dict[str, list[int]]]:
    """TCP connect probe that keeps the three outcomes apart (V1.7.0).

    open      the connection was accepted
    closed    refused (TCP reset): the host is up and nothing listens there
    filtered  no answer before the timeout, or the host/network was unreachable:
              a firewall dropped it, or the host is offline
    """
    clean_hosts = [str(h).strip() for h in hosts if str(h).strip()]
    ports = parse_tcp_ports(port_range or candidate_range())
    result: dict[str, dict[str, list[int]]] = {
        host: {"open": [], "closed": [], "filtered": []} for host in clean_hosts
    }
    if not clean_hosts or not ports:
        return result
    to = _timeout_sec() if timeout is None else max(0.05, float(timeout))

    def _one(host: str, port: int) -> tuple[str, int, str]:
        try:
            with socket.create_connection((host, int(port)), timeout=to):
                return host, int(port), "open"
        except ConnectionRefusedError:
            return host, int(port), "closed"
        except OSError:
            return host, int(port), "filtered"

    # V1.10.3: one port semaphore per IP. At most port_semaphore_limit()
    # (default 6) connects to the same IP are in flight; several IPs are probed
    # at once, each under its own semaphore, bounded by PORT_DISCOVERY_WORKERS.
    per_ip = port_semaphore_limit()
    semaphores = {host: threading.BoundedSemaphore(per_ip) for host in clean_hosts}

    def _guarded(host: str, port: int) -> tuple[str, int, str]:
        with semaphores[host]:
            return _one(host, port)

    total = len(clean_hosts) * len(ports)
    workers = max(1, min(_workers(total), per_ip * len(clean_hosts)))
    # Round-robin order so one IP's queued ports cannot hold every worker
    # thread while they wait on that IP's semaphore.
    order = [(host, port) for port in ports for host in clean_hosts]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="aetheris-port") as pool:
        futs = [pool.submit(_guarded, host, port) for host, port in order]
        for fut in as_completed(futs):
            host, port, state = fut.result()
            result[host][state].append(port)
    for states in result.values():
        for key in states:
            states[key] = sorted(set(states[key]))
    return result


def probe_open_tcp_ports(
    hosts: list[str],
    *,
    port_range: str | None = None,
    timeout: float | None = None,
) -> dict[str, list[int]]:
    """Compatibility wrapper: open ports only (see probe_tcp_port_states)."""
    states = probe_tcp_port_states(hosts, port_range=port_range, timeout=timeout)
    return {host: list(st.get("open") or []) for host, st in states.items()}


def discovery_plan(hosts: list[str], *, port_range: str | None = None) -> dict[str, Any]:
    """Build an *observation-only* TCP probe plan. Never narrow Greenbone scope.

    ``port_range`` (V1.10.2) is the job policy's TCP list; without it the
    laptop's PORT_PROFILE default list is probed as before.
    """
    fallback = (port_range or "").strip() or candidate_range()
    if not enabled():
        return {
            "enabled": False,
            "port_range": fallback,
            "open_ports": {},
            "open_port_count": 0,
            "observed_port_range": "",
            "fallback": True,
        }

    states = probe_tcp_port_states(hosts, port_range=fallback)
    observed = {host: list(st.get("open") or []) for host, st in states.items()}
    union = sorted({p for vals in observed.values() for p in vals})
    if not union:
        return {
            "enabled": True,
            "port_range": fallback,
            "open_ports": observed,
            "port_states": states,
            "open_port_count": 0,
            "observed_port_range": "",
            "fallback": True,
        }
    return {
        "enabled": True,
        "port_range": fallback,
        "observed_port_range": ports_to_gvm_range(union),
        "open_ports": observed,
        "port_states": states,
        "open_port_count": len(union),
        "fallback": False,
    }
