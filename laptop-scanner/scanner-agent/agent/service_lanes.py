"""Per-IP service concurrency for the Nexus catalog.

Six IPs stay in the outer semaphore. Each IP is one OpenVAS task covering the
catalog, with three or four service checks at a time. Splitting one address
into four tasks made every slice finish after hostname, OS, and traceroute
when that slice had no listener, so the vulnerability checks never ran.
"""

from __future__ import annotations

import os
from typing import Any


def service_parallelism() -> int:
    """Checks run at once against one IP (OpenVAS max_checks), 1-32.

    V1.9.3: no longer clamped to 3-4. That band came from the old design that
    split one IP into 3-4 port-slice tasks; since V1.7 one task scans the whole
    catalog and this value is its per-IP check concurrency. The profile's own
    value (FAST_MAX_CHECKS=5) still applies when it is higher, see
    scan_performance.per_ip_check_concurrency().
    """
    # V1.10.3: the per-IP port semaphore (SCAN_PORT_SEMAPHORE, default 6).
    from agent.scan_performance import port_semaphore

    return port_semaphore()


def _spans(token: str) -> tuple[str, list[tuple[int, int]]]:
    raw = token.strip()
    prefix = "T"
    body = raw
    if len(raw) >= 3 and raw[1] == ":" and raw[0].upper() in {"T", "U"}:
        prefix = raw[0].upper()
        body = raw[2:]
    spans: list[tuple[int, int]] = []
    for part in body.split(","):
        piece = part.strip()
        if not piece:
            continue
        if "-" in piece:
            left, right = piece.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
        else:
            try:
                lo = hi = int(piece)
            except ValueError:
                continue
        if lo > hi:
            lo, hi = hi, lo
        lo = max(1, lo)
        hi = min(65535, hi)
        spans.append((lo, hi))
    return prefix, spans


def _format_span(prefix: str, lo: int, hi: int) -> str:
    if lo == hi:
        return f"{prefix}:{lo}"
    return f"{prefix}:{lo}-{hi}"


def _overlaps(left: list[tuple[int, int]], right: list[tuple[int, int]]) -> bool:
    for lo, hi in left:
        for other_lo, other_hi in right:
            if lo <= other_hi and other_lo <= hi:
                return True
    return False


def _split_span(lo: int, hi: int, lanes: int) -> list[tuple[int, int]]:
    width = hi - lo + 1
    pieces = max(1, min(lanes, width))
    size = (width + pieces - 1) // pieces
    out: list[tuple[int, int]] = []
    start = lo
    while start <= hi and len(out) < pieces:
        end = min(hi, start + size - 1)
        out.append((start, end))
        start = end + 1
    return out


def _catalog_names() -> list[tuple[str, str, list[tuple[int, int]]]]:
    from agent.vuln_ports import port_document

    named: list[tuple[str, str, list[tuple[int, int]]]] = []
    doc = port_document()
    for side, prefix in (("tcp", "T"), ("udp", "U")):
        for item in doc.get(side) or []:
            spec = str(item.get("ports") or "").strip()
            name = str(item.get("service") or spec or side).strip()
            if not spec or not name:
                continue
            _prefix, spans = _spans(f"{prefix}:{spec}")
            if spans:
                named.append((prefix, name, spans))
    return named


def lanes_for_port_range(port_range: str, lanes: int | None = None) -> list[dict[str, Any]]:
    """Return port-range slices and the catalog service names that fall in each."""
    count = service_parallelism() if lanes is None else max(1, int(lanes))
    tokens = [token.strip() for token in (port_range or "").split(",") if token.strip()]
    buckets: list[list[str]] = [[] for _ in range(max(1, count))]
    cursor = 0
    for token in tokens:
        prefix, spans = _spans(token)
        if not spans:
            continue
        for lo, hi in spans:
            if hi - lo + 1 > 32 and count > 1:
                for piece_lo, piece_hi in _split_span(lo, hi, count):
                    buckets[cursor % len(buckets)].append(_format_span(prefix, piece_lo, piece_hi))
                    cursor += 1
            else:
                buckets[cursor % len(buckets)].append(_format_span(prefix, lo, hi))
                cursor += 1
    named = _catalog_names()
    lanes_out: list[dict[str, Any]] = []
    for bucket in buckets:
        if not bucket:
            continue
        covered: list[tuple[str, list[tuple[int, int]]]] = []
        for token in bucket:
            prefix, spans = _spans(token)
            covered.append((prefix, spans))
        services: list[str] = []
        seen: set[str] = set()
        for prefix, name, spans in named:
            if name in seen:
                continue
            if any(prefix == side and _overlaps(spans, lane_spans) for side, lane_spans in covered):
                seen.add(name)
                services.append(name)
        lanes_out.append({"port_range": ",".join(bucket), "services": services})
    return lanes_out or [{"port_range": port_range, "services": []}]


def merge_service_lane_polls(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """One IP is finished only after every service lane has finished."""
    usable = [part for part in parts if isinstance(part, dict)]
    if not usable:
        return {"status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}
    if len(usable) == 1:
        return usable[0]
    statuses = [str(part.get("status") or "running").lower() for part in usable]
    # Completion requires *every* lane to have completed. The old any-done
    # branch silently swallowed failed/stopped lanes and claimed 100% success.
    if any(state == "running" for state in statuses):
        status = "running"
    elif any(state == "failed" for state in statuses):
        status = "failed"
    elif any(state == "stopped" for state in statuses):
        status = "stopped"
    elif all(state == "completed" for state in statuses):
        status = "completed"
    else:
        status = "running"
    progress = sum(float(part.get("progress") or 0) for part in usable) / len(usable)
    vulnerabilities: list[Any] = []
    for part in usable:
        vulnerabilities.extend(part.get("vulnerabilities") or [])
    evidence: dict[str, Any] = {}
    coverage_by_host: dict[str, list[dict[str, Any]]] = {}
    for part in usable:
        incoming = dict(part.get("evidence") or {})
        for host, coverage in (incoming.get("host_coverage") or {}).items():
            if isinstance(coverage, dict):
                coverage_by_host.setdefault(str(host), []).append(coverage)
        if not evidence:
            evidence = incoming
            continue
        evidence["report_result_count"] = int(evidence.get("report_result_count") or 0) + int(
            incoming.get("report_result_count") or 0
        )
        evidence["plugin_error_count"] = int(evidence.get("plugin_error_count") or 0) + int(
            incoming.get("plugin_error_count") or 0
        )
        if not evidence.get("report_id") and incoming.get("report_id"):
            evidence["report_id"] = incoming.get("report_id")
    merged_coverage: dict[str, Any] = {}
    for host, rows in coverage_by_host.items():
        merged_coverage[host] = _merge_coverage(rows)
    if merged_coverage:
        evidence["host_coverage"] = merged_coverage
    evidence["service_lanes"] = len(usable)
    evidence["service_lane_states"] = statuses
    if status != "completed":
        evidence["assessment_complete"] = False
        evidence["service_lane_limitation"] = "Not all Greenbone service lanes completed"
    return {
        "status": status,
        "gmp_status": status,
        "progress": progress,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence,
    }


def _merge_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    base = dict(rows[0])
    tcp: set[int] = set()
    udp: set[int] = set()
    nvts = 0
    errors: list[Any] = []
    for row in rows:
        tcp.update(int(port) for port in (row.get("open_tcp_ports") or []) if str(port).isdigit())
        udp.update(int(port) for port in (row.get("open_udp_ports") or []) if str(port).isdigit())
        nvts += int(row.get("nvts_launched") or 0)
        errors.extend(row.get("port_scanner_errors") or [])
    base["open_tcp_ports"] = sorted(tcp)[:512]
    base["open_udp_ports"] = sorted(udp)[:128]
    base["nvts_launched"] = nvts
    base["port_scanner_errors"] = errors[:8]
    useful = [
        row for row in rows
        if str(row.get("verdict") or "")
        and not str(row.get("verdict") or "").startswith("degraded")
        and (
            list(row.get("open_tcp_ports") or [])
            or list(row.get("open_udp_ports") or [])
            or int(row.get("nvts_launched") or 0) >= 30
        )
    ]
    degraded = [row for row in rows if str(row.get("verdict") or "").startswith("degraded")]
    # Preserve positive observations while keeping all-lane coverage incomplete.
    # The lane-level state below prevents a failed lane from being accepted as Done.
    chosen = useful[0] if useful else (degraded[0] if degraded else None)
    if chosen is not None:
        base["verdict"] = chosen.get("verdict") or base.get("verdict")
        if chosen.get("reason"):
            base["reason"] = chosen.get("reason")
    base["service_checks_verified"] = bool(rows) and all(
        row.get("service_checks_verified") is True for row in rows
    )
    base["coverage_complete"] = bool(rows) and all(
        row.get("coverage_complete") is True for row in rows
    )
    return base
