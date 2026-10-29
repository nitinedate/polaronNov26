"""Evidence-backed service audit log for authorized Greenbone laptop scans.

A catalog entry in a port policy is *requested*, not proof that NVTs ran.  The
logger therefore distinguishes requested / observed / finding / not-tested and
retains the source result identifier for severity attribution.  This module is
read-only: it never changes scanner tasks, results, or coverage verdicts.
"""
from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any

from agent.ip_audit import emit_ip_event
from agent.service_policy import analyze_services, service_catalog
from agent.severity_policy import cvss_severity

log = logging.getLogger("scanner_agent.service")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info", "Unscored")
ORDER = {name: index for index, name in enumerate(SEVERITIES)}


def _enabled(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _severity(row: dict[str, Any]) -> str:
    """Use custom numeric CVSS bands for all scored service findings."""
    score = row.get("cvss", row.get("score"))
    if score is not None and not isinstance(score, bool):
        try:
            value = float(score)
            if 0 <= value <= 10:
                label = cvss_severity(value)
                return "Info" if label == "None" else label
        except (TypeError, ValueError, OverflowError):
            pass
    raw = str(row.get("severity") or "").strip().lower()
    aliases = {"critical": "Critical", "high": "High", "medium": "Medium",
               "moderate": "Medium", "low": "Low", "info": "Info",
               "informational": "Info", "information": "Info", "log": "Info",
               "unscored": "Unscored", "unknown": "Unscored"}
    return aliases.get(raw, "Unscored")


def _row_id(row: dict[str, Any]) -> str:
    return str(row.get("source_result_id") or row.get("result_id") or row.get("plugin_id") or "").strip()


def _row_host(row: dict[str, Any]) -> str:
    return str(row.get("host") or "").strip().casefold()


def service_audit_rows(host: str, details: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one audit record per catalog family, without altering evidence.

    Positive severity is attributed only through a native result ID referenced
    by that service's existing evidence mapping, never by port numbers alone.
    """
    evidence = details.get("evidence") or {}
    cov_map = evidence.get("service_coverage") or {}
    coverage = cov_map.get(host)
    if (not isinstance(coverage, dict)
            or not isinstance(coverage.get("services"), list)
            or len(coverage["services"]) != len(service_catalog()["services"])):
        coverage = analyze_services(
            list(details.get("vulnerabilities") or []),
            host=host, coverage=(evidence.get("host_coverage") or {}).get(host),
        )
    native_rows = [r for r in (details.get("vulnerabilities") or [])
                   if isinstance(r, dict) and _row_host(r) == host.casefold()]
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in native_rows:
        rid = _row_id(row)
        if rid:
            by_id.setdefault(rid, []).append(row)

    scan_state = str(details.get("status") or "unknown").lower()
    task_state = str(evidence.get("task_status") or details.get("gmp_status") or "unknown")
    result: list[dict[str, Any]] = []
    for service in coverage.get("services") or []:
        if not isinstance(service, dict):
            continue
        ids = list(dict.fromkeys(str(x) for x in (service.get("source_result_ids") or []) if x))
        native: list[dict[str, Any]] = []
        seen: set[int] = set()
        for rid in ids:
            for row in by_id.get(rid, []):
                if id(row) not in seen:
                    seen.add(id(row))
                    native.append(row)
        counts = Counter(_severity(row) for row in native)
        # Never map zero findings to 'clean' or 'passed'; native execution is
        # not independently proven by the service catalog and an open port.
        max_severity = next((sev for sev in SEVERITIES if counts.get(sev)), "Not verified")
        item = {
            "attribution": list(service.get("attribution") or []),
            "service_id": str(service.get("service_id") or ""),
            "service": str(service.get("name") or ""),
            "status": str(service.get("status") or "not-tested"),
            "scan_status": scan_state,
            "task_status": task_state,
            "max_severity": max_severity,
            "severity_counts": {sev: int(counts.get(sev, 0)) for sev in SEVERITIES},
            "native_result_count": len(native),
            "finding_count": sum(counts.get(s, 0) for s in ("Critical", "High", "Medium", "Low")),
            "observed_endpoints": int(service.get("endpoint_count") or 0),
            "port_hint_count": int(service.get("port_hint_count") or 0),
            "observed_port_hints": list(service.get("port_hints") or [])[:64],
            "source_result_ids": ids[:60],
            "reason": str(service.get("reason") or "")[:350],
            "_native_rows": native,
        }
        result.append(item)
    # V1.6.5: results with no catalog family are still evidence. Host-level
    # rows (general/tcp, ICMP, OS, CPE) and open ports outside the catalog get
    # their own audit rows so no Medium/Low can disappear from the log again.
    for key in ("host_level", "other_ports"):
        bucket = coverage.get(key)
        if not isinstance(bucket, dict):
            continue
        ids = [str(x) for x in (bucket.get("source_result_ids") or []) if x]
        if not ids:
            continue  # the 52 catalog rows stay the contract; buckets only when evidenced
        native = [row for rid in ids for row in by_id.get(rid, [])]
        counts = Counter(_severity(row) for row in native)
        result.append({
            "attribution": ["bucket"],
            "service_id": str(bucket.get("service_id") or key.upper()),
            "service": str(bucket.get("name") or key),
            "status": "finding" if bucket.get("finding_result_ids") else ("observation" if ids else "none"),
            "scan_status": scan_state,
            "task_status": task_state,
            "max_severity": next((sev for sev in SEVERITIES if counts.get(sev)), "None"),
            "severity_counts": {sev: int(counts.get(sev, 0)) for sev in SEVERITIES},
            "native_result_count": len(native),
            "finding_count": sum(counts.get(s, 0) for s in ("Critical", "High", "Medium", "Low")),
            "observed_endpoints": 0,
            "port_hint_count": 0,
            "observed_port_hints": list(bucket.get("ports") or [])[:64],
            "source_result_ids": ids[:60],
            "reason": "Results not tied to a catalog service family",
            "_native_rows": native,
        })
    return result


def emit_service_plan(job_id: str, host: str, task_id: str) -> None:
    """Print requested families AFTER the native task has been created."""
    if not _enabled("SERVICE_AUDIT_ENABLED"):
        return
    catalog = service_catalog()["services"]
    log.info("SERVICE_PLAN IP=%s task=%s requested_families=%d; requested is not tested", host, task_id, len(catalog))
    emit_ip_event(job_id, host, "service_plan_summary", task_id=task_id, requested_families=len(catalog),
                  status="REQUESTED_NOT_VERIFIED")
    for svc in catalog:
        log.info("SERVICE_PLAN IP=%s id=%s service=%s status=REQUESTED_NOT_VERIFIED", host, svc["key"], svc["name"])
        emit_ip_event(job_id, host, "service_planned", task_id=task_id,
                      service_id=svc["key"], service=svc["name"], status="requested_not_verified")


def emit_service_results(job_id: str, host: str, details: dict[str, Any], task_id: str = "") -> None:
    """Print each service status, native severities, and optional finding details.

    Meant for terminal IP states, not every 15-second GMP poll.  Best-effort
    evidence logging must never turn a successful upload into a failed job.
    """
    if not _enabled("SERVICE_AUDIT_ENABLED"):
        return
    rows = service_audit_rows(host, details)
    log.info("SERVICE_AUDIT_BEGIN job=%s IP=%s task=%s families=%d", job_id, host, task_id, len(rows))
    for row in rows:
        native_rows = row.pop("_native_rows", [])
        if row["status"] == "none":
            continue
        if not _enabled("SERVICE_AUDIT_INCLUDE_UNTESTED") and row["status"] in {
            "not-tested", "unsupported", "not-observed", "not-in-scope",
        }:
            continue
        counts = ",".join(f"{key}={row['severity_counts'][key]}" for key in SEVERITIES)
        log.info(
            "SERVICE_RESULT IP=%s id=%s service=%s status=%s severity=%s native_results=%d "
            "findings=%d ports=%s [%s]",
            host, row["service_id"], row["service"], row["status"],
            row["max_severity"], row["native_result_count"], row["finding_count"],
            ",".join(row["observed_port_hints"]) or "none", counts,
        )
        emit_ip_event(job_id, host, "service_result", task_id=task_id, **row)
        if _enabled("SERVICE_AUDIT_LOG_FINDINGS"):
            try:
                limit = max(0, min(10000, int(os.environ.get("SERVICE_AUDIT_MAX_FINDING_LINES") or 100)))
            except ValueError:
                limit = 100
            for finding in native_rows[:limit]:
                severity = _severity(finding)
                # Includes Info observations. Never derive a risk rating from a
                # catalog's port priority; severity comes from the native result.
                payload = {
                    "task_id": task_id,
                    "service_id": row["service_id"],
                    "service": row["service"],
                    "result_id": _row_id(finding)[:128],
                    "plugin_name": str(finding.get("plugin_name") or "")[:250],
                    "nvt_oid": str(finding.get("nvt_oid") or finding.get("plugin_id") or "")[:100],
                    "port": finding.get("port"),
                    "protocol": finding.get("protocol"),
                    "severity": severity,
                    "cvss": finding.get("cvss", finding.get("score")),
                    "cves": list(finding.get("cves") or [])[:12],
                }
                log.info(
                    "SERVICE_FINDING IP=%s service=%s severity=%s CVSS=%s port=%s/%s nvt=%s title=%s",
                    host, row["service"], severity, payload["cvss"], payload["port"],
                    payload["protocol"], payload["nvt_oid"], payload["plugin_name"],
                )
                emit_ip_event(job_id, host, "service_finding", **payload)
            if len(native_rows) > limit:
                log.warning(
                    "SERVICE_FINDING_TRUNCATED IP=%s service=%s emitted=%d total=%d; "
                    "full totals and result IDs remain in SERVICE_RESULT",
                    host, row["service"], limit, len(native_rows),
                )
    mapped_ids = {result_id for service in rows for result_id in service["source_result_ids"]}
    unmapped = len([r for r in (details.get("vulnerabilities") or [])
                    if isinstance(r, dict) and _row_host(r) == host.casefold()
                    and _row_id(r) not in mapped_ids])
    log.info("SERVICE_AUDIT_END job=%s IP=%s families=%d unmapped_native_results=%d",
             job_id, host, len(rows), unmapped)
    emit_ip_event(job_id, host, "service_audit_summary", task_id=task_id,
                  families=len(rows), unmapped_native_results=unmapped,
                  service_coverage_verified=bool((details.get("evidence") or {}).get("service_checks_verified", False)))
