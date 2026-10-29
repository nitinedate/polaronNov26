"""Nessus-style service catalog loaded from vuln_ports.json.

The list is the Aetheris scanning-service specification: core and platform
services, plus the other ports that can produce a vulnerability severity.
UDP entries are that specification's targeted probes, not a full UDP sweep.
A pre-probe that sees nothing does not shrink this catalog.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATH = Path(__file__).with_name("vuln_ports.json")


@lru_cache(maxsize=1)
def port_document() -> dict[str, list[dict[str, str]]]:
    raw = json.loads(_PATH.read_text(encoding="utf-8"))
    tcp = [dict(item) for item in raw.get("tcp") or []]
    udp = [dict(item) for item in raw.get("udp") or []]
    # Site-specific extensions are additive; never silently overwrite the
    # built-in 52-family Nexus baseline. Invalid configurations fail loudly.
    for family, env_key, rows in (
        ("tcp", "SERVICE_EXTRA_TCP_PORTS", tcp),
        ("udp", "SERVICE_EXTRA_UDP_PORTS", udp),
    ):
        for port in parse_ports(__import__("os").environ.get(env_key, "")):
            if not any(port in _port_values(str(row.get("ports") or "")) for row in rows):
                rows.append({"ports": str(port), "service": "custom-" + family, "priority": "Unclassified"})
    return {"tcp": tcp, "udp": udp}


def _gmp_side(items: list[dict[str, Any]], prefix: str) -> str:
    parts: list[str] = []
    for item in items:
        spec = str(item.get("ports") or "").strip()
        if spec:
            parts.append(f"{prefix}:{spec}")
    return ",".join(parts)


def tcp_gmp_range() -> str:
    return _gmp_side(port_document()["tcp"], "T")


def gmp_range() -> str:
    doc = port_document()
    tcp = _gmp_side(doc["tcp"], "T")
    udp = _gmp_side(doc["udp"], "U")
    return f"{tcp},{udp}" if udp else tcp


def _port_values(value: str) -> set[int]:
    ports: set[int] = set()
    for part in (value or "").split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            x, y = token.split("-", 1)
            lo, hi = int(x), int(y)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError("Port interval outside 1..65535")
            ports.update(range(lo, hi + 1))
        else:
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError("Port outside 1..65535")
            ports.add(port)
    return ports


def parse_ports(value: str) -> list[int]:
    """Validate custom port entries, without expanding beyond the TCP/UDP range."""
    return sorted(_port_values(value))


@lru_cache(maxsize=1)
def service_registry() -> list[dict[str, Any]]:
    """Compatibility accessor for the versioned, 52-family service catalog."""
    source = Path(__file__).with_name("service_catalog.json")
    return list(json.loads(source.read_text(encoding="utf-8")).get("services") or [])
