"""Cross-check observed TCP listeners versus native Greenbone report evidence.

Only actual observations count as endpoints. Never synthesize vulnerabilities.
"""
from __future__ import annotations
from typing import Any


def _merge_port_states(coverage: dict[str, Any], native: list[int], states: dict[str, Any]) -> dict[str, int]:
    """Per-port TCP state from the agent's connect probe, upgraded to open by Greenbone."""
    merged: dict[int, str] = {}
    for state in ("filtered", "closed", "open"):
        for raw in states.get(state) or []:
            if str(raw).isdigit():
                merged[int(raw)] = state
    for port in native:
        merged[port] = "open"  # Greenbone's SYN scan saw a listener
    coverage["port_states"] = {"tcp": {str(p): st for p, st in sorted(merged.items())}}
    counts = {st: sum(1 for v in merged.values() if v == st) for st in ("open", "closed", "filtered")}
    coverage["port_state_counts"] = counts
    return counts


def reconcile_host_observations(
    details: dict[str, Any],
    host: str,
    preprobe_ports: list[int] | None,
    preprobe_states: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = details.get("evidence") or {}
    coverages = evidence.get("host_coverage") or {}
    coverage = coverages.get(host)
    if not isinstance(coverage, dict):
        return details
    preprobe = sorted({int(x) for x in (preprobe_ports or []) if str(x).isdigit() and 1 <= int(x) <= 65535})
    coverage["preprobe_tcp_ports"] = preprobe
    coverage["preprobe_source"] = "scanner_agent_tcp_connect"
    coverage["preprobe_is_not_vulnerability_evidence"] = True
    native = sorted({int(x) for x in coverage.get("open_tcp_ports") or [] if str(x).isdigit() and 1 <= int(x) <= 65535})
    coverage["greenbone_tcp_ports"] = native
    counts = _merge_port_states(coverage, native, preprobe_states) if isinstance(preprobe_states, dict) else None
    if (coverage.get("verdict") == "degraded_port_scan_failed" and native and preprobe
            and set(preprobe) <= set(native) and not coverage.get("time_limited")):
        # V1.10.3: a port-scanner check reported an error, yet Greenbone reported
        # every TCP port the agent's connect probe of the policy ports found open,
        # and results exist for them. The listeners were enumerated and checked:
        # this is a finished network scan with a warning, not an incomplete one.
        errs = [e for e in (coverage.get("port_scanner_errors") or []) if isinstance(e, dict)]
        names = ", ".join(sorted({str(e.get("nvt_name") or e.get("nvt_oid") or "port scanner") for e in errs}))
        warnings = list(coverage.get("warnings") or [])
        warnings.append(
            f"{names or 'A port-scanner check'} reported an error, but Greenbone enumerated every TCP port "
            f"the agent's probe found open ({preprobe}); the service checks ran on those ports"[:240]
        )
        coverage["warnings"] = warnings[-20:]
        coverage["verdict"] = "observed_unverified"
        coverage["network_scan_complete"] = True
        coverage["port_scan_reconciled"] = True
        coverage["reason"] = (
            f"Network scan finished: {len(native)} open TCP port(s) {native[:16]}; the port-scanner warning "
            "was reconciled against the agent's TCP probe of the policy ports"
        )
        return details
    if (counts is not None and not preprobe and not native
            and coverage.get("verdict") == "degraded_no_ports"
            and not coverage.get("port_scanner_errors") and not coverage.get("time_limited")
            and (counts["closed"] + counts["filtered"]) > 0):
        # V1.7.0: Greenbone finished without a port-scanner error and the agent's
        # probe of every policy port agrees nothing is open. That is a result,
        # not "not tested": say exactly what was seen.
        closed, filtered = counts["closed"], counts["filtered"]
        total = closed + filtered
        coverage["verdict"] = "no_exposed_services"
        coverage["network_scan_complete"] = True
        coverage["host_responded"] = closed > 0
        if closed:
            coverage["reason"] = (
                f"No policy service is exposed: {closed} of {total} policy TCP ports refused the connection "
                f"(host is up, nothing listening) and {filtered} did not answer"
            )
        else:
            coverage["reason"] = (
                f"No policy service answered: all {total} policy TCP ports were dropped "
                "(a firewall is blocking them, or the host is offline)"
            )
            # V1.8.0: an observation, not a scan failure. It no longer turns the
            # job amber; the UI shows it as a note next to the verdict.
            notes = list(coverage.get("notes") or [])
            # V1.10.1: only the policy's ports were probed; say so, and that
            # credentials need SMB/SSH reachable first.
            notes.append(
                f"None of the {total} TCP ports in this policy's port list answered (a firewall dropped them, "
                "or the host is offline). Ports outside the list were not probed: an all-ports policy "
                "(Advanced) may find services there. Credentials need SMB 445 / SSH 22 reachable first"
            )
            coverage["notes"] = notes[-20:]
        return details
    if preprobe and not native and coverage.get("time_limited"):
        # V1.6.7: the per-IP time limit stopped the scan before Greenbone reported
        # ports; that is the cause, so keep its verdict and record the probe.
        warnings = list(coverage.get("warnings") or [])
        warnings.append(f"TCP connect pre-probe saw port(s) {preprobe} open before the time limit stopped the scan")
        coverage["warnings"] = warnings[-20:]
        coverage["network_scan_complete"] = False
    elif preprobe and not native:
        coverage["verdict"] = "degraded_discovery_mismatch"
        coverage["reason"] = (
            f"Scanner agent established TCP connections on {preprobe}, but Greenbone did not report "
            "any open TCP ports. Investigate OSPd network route, Nmap preferences, container permissions, "
            "and native scan errors. Vulnerability coverage remains unverified"
        )
        coverage["service_checks_verified"] = False
        coverage["coverage_complete"] = False
        coverage["network_scan_complete"] = False
    elif preprobe and native and set(preprobe) - set(native):
        missing = sorted(set(preprobe) - set(native))
        coverage["preprobe_only_ports"] = missing
        warnings = list(coverage.get("warnings") or [])
        note = (
            f"TCP connect pre-probe saw port(s) {missing} open, but Greenbone reported no port detail "
            "or result for them; those listeners may be untested"
        )
        if note not in warnings:
            warnings.append(note)
        coverage["warnings"] = warnings
    elif not preprobe and not native and coverage.get("verdict") == "degraded_no_ports":
        coverage["reason"] = (
            "Neither the fast scanner-agent TCP connect probe nor Greenbone evidenced an open listener. "
            "This does not prove the host is down or that every port was tested. Compare Windows host "
            "and Docker reachability, verify firewall/ACL and Nmap/OpenVAS port-scanner logs"
        )
    # Pre-probe results are corroborating context, not verified service coverage.
    return details
