"""V1.10.2 — say why IPs that answered nothing were not assessed.

Field: a job on 192.168.0.x returned 41 findings for the gateway 192.168.0.254
(open 22/80/443) and "Completed, 0 findings" for every other IP. Those IPs had
dropped every policy TCP port (no SYN-ACK, no reset) for both the agent's connect
probe and Greenbone's SYN scan, so nothing on them was assessed. The causes
differ, and each needs a different fix:

* host_firewall              the host answers ICMP echo, so it is up; its firewall
                             drops the scanner (Windows Public profile, default deny)
* client_isolation_suspected only the default gateway answered anything and the
                             silent IPs do not even answer ping: Wi-Fi client (AP)
                             isolation, a guest network or another VLAN
* no_answer                  no ping reply either: offline, or dropping everything

The ping is an unprivileged ICMP datagram socket (Docker sets
net.ipv4.ping_group_range for containers) with a raw-socket fallback; when
neither can be opened the state is "unavailable" and no cause is guessed.

Control ping: some virtual network stacks answer ICMP echo for any address
themselves. Before trusting a reply, 192.0.2.1 (RFC 5737 TEST-NET-1, never a
real host) is pinged; if it "answers", ping evidence is unreliable on this
laptop and every state becomes "unavailable" (no cause is guessed).
"""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

_PAYLOAD = b"aetheris-reachability"
CONTROL_ADDRESS = "192.0.2.1"  # RFC 5737 TEST-NET-1: must never answer


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_echo(host: str, timeout: float = 1.0) -> str:
    """One ICMP echo: "reply" | "no_reply" | "unavailable"."""
    try:
        if ipaddress.ip_address(str(host)).version != 4:
            return "unavailable"
    except ValueError:
        return "unavailable"
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError:
            continue
        with sock:
            sock.settimeout(timeout)
            ident = os.getpid() & 0xFFFF
            header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
            packet = struct.pack("!BBHHH", 8, 0, _checksum(header + _PAYLOAD), ident, 1) + _PAYLOAD
            try:
                sock.sendto(packet, (str(host), 0))
            except OSError:
                return "no_reply"  # no route / host unreachable
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(2048)
                except (socket.timeout, OSError):
                    return "no_reply"
                if addr[0] != str(host):
                    continue
                if kind == socket.SOCK_RAW and data:
                    data = data[(data[0] & 0x0F) * 4:]
                if data[:1] == b"\x00":  # echo reply
                    return "reply"
            return "no_reply"
    return "unavailable"


def _is_silent(cov: Any) -> bool:
    return (
        isinstance(cov, dict)
        and str(cov.get("verdict") or "") == "no_exposed_services"
        and not cov.get("host_responded")
        and not cov.get("open_tcp_ports")
        and not cov.get("open_udp_ports")
        and not cov.get("self_scan")
    )


def diagnose_silent_hosts(
    evidence: dict[str, Any],
    lan_fp: dict[str, Any] | None,
    *,
    ping: Callable[[str], str] = icmp_echo,
    max_hosts: int = 512,
) -> dict[str, Any] | None:
    """Annotate silent hosts in ``evidence['host_coverage']`` in place; return a summary."""
    cov_map = evidence.get("host_coverage") if isinstance(evidence.get("host_coverage"), dict) else {}
    silent = sorted(h for h, c in cov_map.items() if _is_silent(c))
    if not silent:
        return None
    answered = sorted(h for h in cov_map if h not in silent)
    gateway = str((lan_fp or {}).get("gateway") or "").strip()
    try:
        subnet = ipaddress.ip_network(str((lan_fp or {}).get("subnet") or ""), strict=False)
    except ValueError:
        subnet = None

    probe = silent[:max_hosts]
    control = ping(CONTROL_ADDRESS)
    ping_unreliable = control == "reply"
    if ping_unreliable:
        states = {h: "unavailable" for h in probe}
    else:
        with ThreadPoolExecutor(max_workers=max(1, min(32, len(probe))), thread_name_prefix="aetheris-ping") as pool:
            states = dict(zip(probe, pool.map(ping, probe)))
    gateway_only = bool(gateway) and answered == [gateway] and len(silent) >= 2

    for host in silent:
        cov = cov_map[host]
        state = states.get(host, "unavailable")
        counts = cov.get("port_state_counts") if isinstance(cov.get("port_state_counts"), dict) else {}
        total = int(counts.get("filtered") or 0) + int(counts.get("closed") or 0)
        on_lan = False
        if subnet is not None:
            try:
                on_lan = ipaddress.ip_address(host) in subnet
            except ValueError:
                on_lan = False
        cov["icmp_echo"] = state
        cov["assessed"] = False
        if state == "reply":
            cov["silent_cause"] = "host_firewall"
            note = (
                f"Not assessed: the host answers ping (it is up) but dropped all {total} policy TCP ports, so "
                "its firewall blocks the scanner. Allow the scanner laptop's IP in the host firewall "
                "(Private/Domain profile, File and Printer Sharing / Remote Service Management) and scan again"
            )
        elif state == "no_reply" and gateway_only and on_lan:
            cov["silent_cause"] = "client_isolation_suspected"
            note = (
                f"Not assessed: no answer to ping or to any of {total} policy TCP ports, while the gateway "
                f"{gateway} answered. Wi-Fi client (AP) isolation, a guest network or another VLAN is the "
                "likely cause: scan from a wired port on the targets' network"
            )
        elif state == "no_reply":
            cov["silent_cause"] = "no_answer"
            note = (
                f"Not assessed: no answer to ping or to any of {total} policy TCP ports. The host is offline, "
                "or a firewall drops everything including ping"
            )
        else:
            cov["silent_cause"] = None
            why = (
                "this laptop's network answers ping for any address" if ping_unreliable
                else "ping could not be sent from the scanner"
            )
            note = (
                f"Not assessed: none of {total} policy TCP ports answered ({why}, so offline and firewalled "
                "hosts cannot be told apart)"
            )
        notes = [n for n in (cov.get("notes") or []) if not str(n).startswith("Not assessed:")]
        notes.insert(0, note)
        cov["notes"] = notes[:20]

    summary = {
        "silent_hosts": silent,
        "answered_hosts": answered,
        "gateway": gateway or None,
        "subnet": str(subnet) if subnet is not None else None,
        "gateway_only": gateway_only,
        "icmp": {h: states.get(h, "unavailable") for h in silent},
        "ping_replies": sum(1 for h in silent if states.get(h) == "reply"),
        "ping_control": control,
        "ping_unreliable": ping_unreliable,
    }
    evidence["reachability"] = summary
    return summary
