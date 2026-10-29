"""Read-only TCP reachability probe from inside the OSPd container.

Run with source piped to ``python3 -`` via docker compose exec -T, because
Windows PowerShell's native-argument quoting can corrupt ``python3 -c`` code.
No extra dependencies or files in the OSPd image are required.
"""
from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def parse_ports(value: str) -> list[int]:
    result: set[int] = set()
    for raw in value.split(","):
        part = raw.strip()
        if not part:
            continue
        if "-" in part:
            sides = part.split("-")
            if len(sides) != 2 or not all(side.strip().isdigit() for side in sides):
                raise ValueError("Invalid port range: " + part)
            lo, hi = (int(side.strip()) for side in sides)
            if lo < 1 or hi > 65535 or lo > hi or hi - lo >= 256:
                raise ValueError("Invalid or oversized port range: " + part)
            result.update(range(lo, hi + 1))
        elif part.isdigit():
            result.add(int(part))
        else:
            raise ValueError("Invalid TCP port: " + part)
        if len(result) > 256:
            raise ValueError("Maximum 256 diagnostic TCP ports")
    if not result or any(not (1 <= p <= 65535) for p in result):
        raise ValueError("Specify 1 to 256 valid TCP ports")
    return sorted(result)


def run_probe(ip: str, ports: list[int], timeout: float) -> dict:
    ip = str(ipaddress.ip_address(ip))
    timeout = max(0.1, min(5.0, float(timeout)))

    def check(port: int) -> dict:
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                state, error = "open", None
        except ConnectionRefusedError:
            state, error = "refused", "ConnectionRefusedError"
        except TimeoutError:
            state, error = "timeout_or_filtered", "TimeoutError"
        except OSError as exc:
            error = type(exc).__name__
            if getattr(exc, "errno", None) in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                                                  10051, 10065):
                state = "network_or_host_unreachable"
            else:
                state = "error"
        return {"port": port, "state": state, "error": error,
                "latency_ms": round((time.monotonic() - start) * 1000)}

    with ThreadPoolExecutor(max_workers=min(len(ports), 16)) as pool:
        results = sorted(pool.map(check, ports), key=lambda r: r["port"])
    states = ("open", "refused", "timeout_or_filtered", "network_or_host_unreachable", "error")
    return {
        "ip": ip,
        "source": "ospd_container_tcp_connect",
        "protocol": "tcp",
        "ports_checked": ports,
        "results": results,
        "counts": {state: sum(row["state"] == state for row in results) for state in states},
        "open_ports": [row["port"] for row in results if row["state"] == "open"],
        "vulnerability_checks_verified": False,
        "note": "TCP reachability only. Closed, filtered, and unreachable are not vulnerabilities; NVT execution is not verified.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="OSPd-container TCP reachability comparator")
    parser.add_argument("ip", help="Explicitly authorized literal target IP; no CIDR expansion")
    parser.add_argument("--ports", default="22,80,135,139,443,445,3389,8080,8443")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    try:
        data = run_probe(args.ip, parse_ports(args.ports), args.timeout)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
