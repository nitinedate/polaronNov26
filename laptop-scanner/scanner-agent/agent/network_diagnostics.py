"""Defensive Docker-side TCP reachability diagnostic for explicitly authorized IPs.

Run *inside scanner-agent*; the Windows host's connectivity is not proof that
Docker/OSPd can reach the same network. TCP connect proves a listener only, NOT
service identity, executed vulnerability tests, or security severity.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

DEFAULT_PORTS = (22, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443)


def _ports(value: str) -> list[int]:
    result: set[int] = set()
    for token in (value or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo, hi = token.split("-", 1)
            lower, upper = int(lo), int(hi)
            if lower > upper or upper - lower > 256:
                raise ValueError("Invalid port range (maximum 257 ports per range)")
            result.update(range(lower, upper + 1))
        else:
            result.add(int(token))
    if not result or any(p < 1 or p > 65535 for p in result) or len(result) > 256:
        raise ValueError("Specify 1-256 valid TCP ports")
    return sorted(result)


def probe_target(host: str, ports: list[int] | None = None, timeout: float = 1.0) -> dict[str, Any]:
    ip = str(ipaddress.ip_address(host.strip()))
    ports = list(DEFAULT_PORTS) if ports is None else _ports(",".join(str(p) for p in ports))
    timeout = max(0.1, min(5.0, float(timeout)))

    def check(port: int) -> dict[str, Any]:
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                state = "open"
                error_type = None
        except ConnectionRefusedError:
            state, error_type = "refused", "ConnectionRefusedError"
        except TimeoutError:
            state, error_type = "timeout_or_filtered", "TimeoutError"
        except OSError as exc:
            error_type = type(exc).__name__
            if getattr(exc, "errno", None) in {101, 113, 10051, 10065}:
                state = "network_or_host_unreachable"
            else:
                state = "error"
        return {"port": port, "state": state, "error": error_type, "latency_ms": int((time.monotonic() - start) * 1000)}

    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        rows = sorted(pool.map(check, ports), key=lambda row: row["port"])
    counts = {k: sum(r["state"] == k for r in rows) for k in
              ("open", "refused", "timeout_or_filtered", "network_or_host_unreachable", "error")}
    return {
        "ip": ip,
        "source": "scanner_agent_tcp_connect",
        "protocol": "tcp",
        "ports_checked": ports,
        "results": rows,
        "counts": counts,
        "open_ports": [r["port"] for r in rows if r["state"] == "open"],
        "routing_evidence": "tcp_connection_test_only",
        "vulnerability_checks_verified": False,
        "note": "Connection refused is a response, not an open service. Timeouts can reflect filtering, host downtime, or routing. No vulnerability severity is inferred.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnostic TCP probes from the scanner Docker network")
    parser.add_argument("ips", nargs="+", help="Authorized literal IP addresses; no implicit subnet expansion")
    parser.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)))
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()
    ports = _ports(args.ports)
    data = [probe_target(ip, ports, args.timeout) for ip in args.ips]
    print(json.dumps(data if len(data) > 1 else data[0], indent=2))


if __name__ == "__main__":
    main()
