"""V1.10.0 — which laptop this agent runs on, sent to the central server.

The emailed access token identifies a user, and every laptop of that user binds the
same token. With only the token the central server could not tell the laptops apart
(all of them heartbeated as one scanner record; the others showed "offline"). Every
request now also carries the Windows computer name and the configured scanner name;
the per-install instance id is already sent (X-Aetheris-Agent-Instance).

The computer name comes from HOST_COMPUTERNAME (docker-compose passes the live Windows
COMPUTERNAME) or, when compose ran without it, AGENT_COMPUTER_NAME (written to .env by
Start-Laptop and the upgrade script). The live value wins: a folder copied from another
PC carries that PC's .env. Inside the container the hostname is only the container id.
"""
from __future__ import annotations

import os
import re

COMPUTER_HEADER = "X-Aetheris-Agent-Computer"
NAME_HEADER = "X-Aetheris-Agent-Name"
INSTANCE_HEADER = "X-Aetheris-Agent-Instance"


def clean_computer_name(value: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "", str(value or "").strip())[:63]


def clean_scanner_name(value: str | None) -> str:
    # HTTP header values must be plain ASCII here; drop anything else.
    return "".join(ch for ch in str(value or "").strip() if 32 <= ord(ch) < 127)[:120]


def computer_name() -> str:
    for key in ("HOST_COMPUTERNAME", "AGENT_COMPUTER_NAME"):
        value = clean_computer_name(os.environ.get(key))
        if value:
            return value
    return ""


def identity_headers(instance_id: str = "", scanner_name: str | None = None,
                     computer: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if instance_id:
        headers[INSTANCE_HEADER] = str(instance_id).strip()[:128]
    comp = clean_computer_name(computer) if computer is not None else computer_name()
    if comp:
        headers[COMPUTER_HEADER] = comp
    name = clean_scanner_name(os.environ.get("SCANNER_NAME") if scanner_name is None else scanner_name)
    if name:
        headers[NAME_HEADER] = name
    return headers
