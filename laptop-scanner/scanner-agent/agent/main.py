"""Poll the central API for edge scan jobs and run them on local OpenVAS."""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone

import httpx

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor
from concurrent.futures import wait as futures_wait

from pathlib import Path
from typing import Any

from agent.api_client import CentralApi
from agent.capacity import IP_WORKERS_MIN, probe_laptop_capacity
from agent.gmp_local import LocalOpenVAS
from agent.ip_audit import emit_ip_event
from agent.service_audit import emit_service_plan, emit_service_results
from agent.ip_semaphore import AdaptiveIPSemaphore
from agent.job_identity import (
    host_set,
    leftover_blocks_skip_complete,
    network_key,
    plan_resume_chunks,
    remaining_hosts,
    stored_task_entries,
)
from agent.lan_fingerprint import (
    capture_lan_fingerprint,
    is_docker_nat_fingerprint,
    lan_changed,
    should_watch_lan,
)
from agent.log_shipper import install_log_shipper, set_current_job_id
from agent.target_progress import build_target_progress
from agent.service_policy import clip_policy_snapshots

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("scanner_agent")


_LEGACY_WRITER_WARNED = {"at": 0.0}


def _warn_legacy_fingerprint_writer(reason: str) -> None:
    """Rate-limited (15 min) operator warning for the stale fingerprint writer."""
    import time as _time

    now = _time.monotonic()
    if now - _LEGACY_WRITER_WARNED["at"] < 900 and _LEGACY_WRITER_WARNED["at"]:
        return
    _LEGACY_WRITER_WARNED["at"] = now
    log.warning(
        "SELF-SCAN DISABLED: %s. A scan of this laptop's own IP goes through its firewall "
        "(services show as 'no answer'). Fix on the laptop: run Start-Laptop.cmd again.",
        reason,
    )


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _read_agent_token() -> str:
    token_file = Path(os.environ.get("AGENT_TOKEN_FILE") or "/run/aetheris-agent/agent-token")
    try:
        if token_file.is_file():
            value = token_file.read_text(encoding="utf-8-sig").strip()
            if value:
                return value
    except OSError:
        log.warning("Unable to read AGENT_TOKEN_FILE=%s; falling back to environment", token_file)
    return (os.environ.get("AGENT_TOKEN") or "").strip()


def _agent_build() -> str:
    try:
        from agent import AGENT_BUILD

        return str(AGENT_BUILD)
    except Exception:
        return "unknown"


def _read_agent_version() -> str:
    build = _agent_build()
    if build != "unknown":
        # Source build is authoritative; a retained deployment env/version file
        # must not advertise old code after a source-only laptop update.
        release, _, suffix = build.partition("-")
        return release + ("+" + suffix if suffix else "")
    version_file = Path(os.environ.get("AGENT_VERSION_FILE") or "/app/.agent-version")
    try:
        if version_file.is_file():
            value = version_file.read_text(encoding="utf-8-sig").strip()
            if value:
                return value
    except OSError:
        log.warning("Unable to read AGENT_VERSION_FILE=%s; falling back to environment", version_file)
    base = (os.environ.get("AGENT_VERSION") or "1.5.3").strip() or "1.5.3"
    return base if build == "unknown" or base.endswith(build.split("-", 1)[-1]) else f"{base}+{build.split('-', 1)[-1]}"


def _cfg() -> dict[str, Any]:
    base = (os.environ.get("CENTRAL_API_URL") or "").strip()
    tenant = (os.environ.get("TENANT_SLUG") or "").strip()
    token = _read_agent_token()
    if not base or not tenant or not token:
        log.error("CENTRAL_API_URL, TENANT_SLUG, and AGENT_TOKEN/AGENT_TOKEN_FILE are required")
        sys.exit(1)
    return {
        "api": CentralApi(
            base_url=base,
            tenant=tenant,
            token=token,
            verify_tls=_env_bool("VERIFY_TLS", True),
        ),
        "openvas": LocalOpenVAS(),
        "poll": max(5, int(os.environ.get("POLL_INTERVAL_SEC") or 15)),
        "heartbeat": max(15, int(os.environ.get("HEARTBEAT_INTERVAL_SEC") or 60)),
        # Queue dispatch is intentionally separate from GMP polling. A short
        # dispatcher interval lets a newly queued job fill an available worker
        # slot without waiting for an unrelated scan's next GMP poll.
        "queue_poll": max(1, min(30, int(os.environ.get("QUEUE_POLL_INTERVAL_SEC") or 3))),
        "progress_report_interval": max(15, min(180, int(os.environ.get("PROGRESS_REPORT_INTERVAL_SEC") or 45))),
        # Bounded concurrency prevents head-of-line blocking without spawning an
        # unbounded number of OpenVAS scans. Tune for laptop capacity; 1..8.
        "max_concurrent_jobs": max(1, min(8, int(os.environ.get("MAX_CONCURRENT_SCAN_JOBS") or 1))),
        # A Greenbone task at 90-99% is often still evaluating NVTs or writing
        # its report. Never treat a partial report as terminal just because
        # progress did not change. This value is diagnostic only (0 disables).
        "high_progress_warn_sec": max(60, int(os.environ.get("HIGH_PROGRESS_WARN_SEC") or 300)),
        "high_progress_stall_sec": _env_stall_sec(),
        "high_progress_stall_pct": max(80, min(99, int(os.environ.get("HIGH_PROGRESS_STALL_PCT") or 90))),
        # Optional absolute safety ceiling. This is NOT a progress-based timeout.
        # Set to 0 to disable. Default is disabled; configure explicitly if desired.
        # V1.9.3: MAX_SCAN_RUNTIME_SEC is applied per IP (scan_performance.ip_runtime_limit);
        # the whole-job cap is MAX_JOB_RUNTIME_SEC (default off).
        "max_scan_runtime_sec": max(0, int(os.environ.get("MAX_SCAN_RUNTIME_SEC") or 0)),
        "max_job_runtime_sec": max(0, int(os.environ.get("MAX_JOB_RUNTIME_SEC") or 0)),
        "version": _read_agent_version(),
    }


def _env_stall_sec() -> int:
    raw = os.environ.get("HIGH_PROGRESS_STALL_SEC")
    if raw is None or str(raw).strip() == "":
        return 0
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def ip_tail_should_harvest(progress: float, unchanged_sec: float, *, stall_sec: int, stall_pct: int) -> bool:
    """True when one IP is frozen in the OpenVAS tail (typically 90-98%)."""
    if stall_sec <= 0:
        return False
    try:
        pct = int(float(progress))
    except (TypeError, ValueError):
        return False
    return pct >= int(stall_pct) and unchanged_sec >= float(stall_sec)


def seal_tail_harvest(details: dict[str, Any], host: str, *, reason: str) -> bool:
    """Reject automatic completion from a running/partial Greenbone report.

    This legacy helper is deliberately fail-closed. A report may already contain
    hostname, OS, ports and findings while NVTs are running. The authoritative
    terminal state comes ONLY from ``LocalOpenVAS.poll``'s GMP task status.
    Returning False ensures that callers cannot rewrite "running" into "done"
    or fire a background stop request after uploading partial results.
    """
    del details, host, reason
    return False


_last_progress_failure_log: dict[str, float] = {}
_progress_failure_lock = threading.Lock()


def _patch_job_best_effort(api: CentralApi, job_id: str, payload: dict[str, Any]) -> bool | None:
    """Bounded, retryable status update. Never block Greenbone's poll loop on WAN outages.

    None is reserved for a definitive 404; transient connectivity failures must
    never stop live local OpenVAS tasks. Only one short HTTP attempt is made.
    """
    try:
        api.patch_job(job_id, payload)
        with _progress_failure_lock:
            _last_progress_failure_log.pop(job_id, None)
        return True
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 404:
            log.error("Central API has no job %s for this scanner; progress cannot be saved", job_id)
            return None
        failure = f"HTTP {status}"
    except Exception as exc:
        failure = exc.__class__.__name__
    now = time.monotonic()
    with _progress_failure_lock:
        last = _last_progress_failure_log.get(job_id, 0.0)
        should_log = now - last >= 60.0 or last == 0.0
        if should_log:
            _last_progress_failure_log[job_id] = now
    if should_log:
        log.warning(
            "Central progress PATCH unavailable for %s (%s). Local scan is continuing; retry at next status interval.",
            job_id, failure,
        )
    return False


def _upload_results_reliably(api: CentralApi, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    delay = 2.0
    while True:
        try:
            return api.upload_results(job_id, payload)
        except Exception as exc:
            if not api.is_retryable(exc):
                raise
            log.warning(
                "Central API result upload temporarily unavailable for job %s; retrying in %.0fs",
                job_id,
                delay,
                exc_info=True,
            )
            time.sleep(delay)
            delay = min(delay * 2.0, 60.0)


def _result_payload(
    *,
    details: dict[str, Any],
    task_id: str,
    status: str,
    partial: bool = False,
    partial_reason: str | None = None,
    error: str | None = None,
    skipped_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = dict(details.get("evidence") or {})
    if status == "completed":
        # V1.10.1: every target silent and none on this laptop's network means the
        # laptop could not reach them - fail with the reason instead of "completed".
        from agent.reach_guard import unreachable_network_error

        try:
            from agent.lan_fingerprint import capture_lan_fingerprint

            lan_fp = capture_lan_fingerprint()
        except Exception:
            lan_fp = {}
        unreachable = unreachable_network_error(evidence, lan_fp)
        if unreachable:
            log.error("Job result marked failed: %s", unreachable)
            status, error, partial, partial_reason = "failed", unreachable, False, None
        else:
            # V1.10.2: IPs that answered nothing were not assessed; find out why
            # (ping + which IPs answered) so the result does not read as clean.
            try:
                from agent.reachability_diagnosis import diagnose_silent_hosts

                reach = diagnose_silent_hosts(evidence, lan_fp)
                if reach:
                    log.warning(
                        "Not assessed (no port answered): %d IP(s) %s; answered: %s; ping replies: %d; "
                        "gateway-only: %s",
                        len(reach["silent_hosts"]), reach["silent_hosts"][:20], reach["answered_hosts"][:20],
                        reach["ping_replies"], reach["gateway_only"],
                    )
            except Exception:
                log.warning("Silent-host diagnosis failed; result kept as is", exc_info=True)
    raw_task = str(
        evidence.get("task_status") or details.get("gmp_status") or ""
    ).strip().lower()
    # Central verifier expects GMP terminal statuses, not agent "completed".
    if raw_task in {"completed", "complete", "success"}:
        raw_task = "done"
    elif not raw_task and status == "completed":
        raw_task = "done"
    skipped = skipped_hosts if skipped_hosts is not None else (evidence.get("skipped_hosts") or [])
    return {
        "vulnerabilities": details.get("vulnerabilities") or [],
        "status": status,
        "external_scan_id": task_id,
        "partial": bool(partial),
        "partial_reason": partial_reason,
        "error": error,
        "report_id": evidence.get("report_id"),
        "task_status": raw_task or None,
        "hosts_attempted": int(evidence.get("hosts_attempted") or 0),
        "hosts_assessed": int(evidence.get("hosts_assessed") or 0),
        "assessed_hosts": evidence.get("assessed_hosts") or [],
        "skipped_hosts": skipped,
        "report_result_count": int(evidence.get("report_result_count") or 0),
        "plugin_error_count": int(evidence.get("plugin_error_count") or 0),
        "plugin_error_details": evidence.get("plugin_error_details") or [],
        "host_coverage": evidence.get("host_coverage") or {},
        "reachability": evidence.get("reachability") or None,
        "service_coverage": evidence.get("service_coverage") or {},
        "policy_snapshots": evidence.get("policy_snapshots") or {},
        "degraded_hosts": evidence.get("degraded_hosts") or [],
        "scan_start": evidence.get("scan_start"),
        "scan_end": evidence.get("scan_end"),
        "assessment_complete": bool(evidence.get("assessment_complete")),
        "assessment_verdict": evidence.get("assessment_verdict"),
        "alive_test": evidence.get("alive_test"),
        "report_read_error": evidence.get("report_read_error"),
    }


def _parse_external_task_ids(raw: Any) -> list[str]:
    """Accept a single task id string or a JSON list of chunk task ids."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            import json

            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass
    return [text]


def _encode_external_task_ids(task_ids: list[str]) -> str:
    import json

    clean = [str(t).strip() for t in task_ids if str(t).strip()]
    if len(clean) <= 1:
        return clean[0] if clean else ""
    return json.dumps(clean)


def _merge_chunk_details(
    chunk_results: list[tuple[list[str], dict[str, Any]]],
    *,
    all_targets: list[str],
    skipped_hosts: list[dict[str, Any]] | None = None,
    prior_assessed: list[str] | None = None,
) -> dict[str, Any]:
    """Merge per-chunk OpenVAS poll payloads into one upload-shaped details dict.

    ``prior_assessed`` (V1.9.9): IPs of this job that an earlier attempt already
    assessed. A Resume scans only the remaining IPs, so without them a resumed
    job reported "assessed 1 of 10" and the nine finished IPs as missing
    (field job fcbb90c0). Their findings were uploaded by that earlier attempt.
    """
    import ipaddress

    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_report_ids: set[str] = set()
    assessed: set[str] = set()
    target_set = {str(t).strip() for t in all_targets}
    prior_kept = sorted({str(h).strip() for h in (prior_assessed or []) if str(h).strip() in target_set})
    assessed.update(prior_kept)
    plugin_errors: list[Any] = []
    host_coverage: dict[str, dict[str, Any]] = {}
    service_coverage: dict[str, Any] = {}
    policy_snapshots: dict[str, Any] = {}
    report_ids: list[str] = []
    gmp_statuses: list[str] = []
    statuses: list[str] = []
    progresses: list[float] = []
    scan_starts: list[str] = []
    scan_ends: list[str] = []
    alive_test = ""
    report_read_errors: list[str] = []
    result_count = 0
    plugin_error_total = 0
    complete_chunks = 0
    skipped = [dict(x) for x in (skipped_hosts or []) if isinstance(x, dict)]
    skipped_set: set[str] = set()
    for item in skipped:
        host = str(item.get("host") or "").strip()
        if not host:
            continue
        try:
            skipped_set.add(str(ipaddress.ip_address(host)))
        except ValueError:
            skipped_set.add(host.casefold())

    for _chunk_targets, details in chunk_results:
        ev = details.get("evidence") or {}
        report_key = str(ev.get("report_id") or "").strip()
        if report_key and report_key in seen_report_ids:
            # Resume/retry can accidentally surface the exact same Greenbone
            # report twice. Skip the duplicate report as a unit while preserving
            # all distinct rows inside the first copy.
            continue
        if report_key:
            seen_report_ids.add(report_key)
        status = str(details.get("status") or "running")
        statuses.append(status)
        progresses.append(float(details.get("progress") or 0))
        for v in details.get("vulnerabilities") or []:
            # Forensic completeness: Greenbone can legitimately emit multiple
            # distinct result rows with the same plugin/host/port summary.  Only
            # dedupe when the scanner supplied a stable result identifier.
            result_id = str(
                v.get("result_id") or v.get("greenbone_result_id") or v.get("id") or ""
            ).strip()
            if result_id:
                key = f"result:{result_id}"
                if key in seen:
                    continue
                seen.add(key)
            vulns.append(v)
        for h in ev.get("assessed_hosts") or []:
            assessed.add(str(h).strip())
        result_count += int(ev.get("report_result_count") or 0)
        plugin_errors.extend(ev.get("plugin_error_details") or [])
        plugin_error_total += int(ev.get("plugin_error_count") or 0)
        for cov_host, cov in (ev.get("host_coverage") or {}).items():
            if isinstance(cov, dict):
                host_coverage[str(cov_host)] = cov
        for cov_host, cov in (ev.get("service_coverage") or {}).items():
            if cov_host in all_targets and isinstance(cov, dict):
                service_coverage[str(cov_host)] = cov
        policy_snapshots.update(clip_policy_snapshots(ev.get("policy_snapshots"), all_targets))
        if ev.get("report_id"):
            report_ids.append(str(ev["report_id"]))
        raw_task = str(ev.get("task_status") or details.get("gmp_status") or "").strip().lower()
        if raw_task:
            gmp_statuses.append(raw_task)
        if ev.get("scan_start"):
            scan_starts.append(str(ev["scan_start"]))
        if ev.get("scan_end"):
            scan_ends.append(str(ev["scan_end"]))
        if ev.get("alive_test") and not alive_test:
            alive_test = str(ev["alive_test"])
        if ev.get("report_read_error"):
            report_read_errors.append(str(ev["report_read_error"])[:400])
        if status == "completed" and ev.get("assessment_complete"):
            complete_chunks += 1

    if any(s == "failed" for s in statuses) and not any(s == "running" for s in statuses):
        mapped = "failed"
    elif any(s == "stopped" for s in statuses) and not any(s == "running" for s in statuses):
        mapped = "stopped"
    elif statuses and all(s == "completed" for s in statuses):
        mapped = "completed"
    elif not chunk_results and skipped:
        # All targets eliminated as unreachable — nothing to scan.
        mapped = "completed"
    else:
        mapped = "running"

    terminal_gmp = {"done", "finished", "succeeded"}
    if not chunk_results and skipped:
        merged_task_status = "done"
    elif gmp_statuses and all(s in terminal_gmp for s in gmp_statuses):
        merged_task_status = "done"
    elif gmp_statuses and any(s in {"failed", "internal error"} for s in gmp_statuses):
        merged_task_status = next(s for s in gmp_statuses if s in {"failed", "internal error"})
    elif mapped == "completed":
        merged_task_status = "done"
    else:
        merged_task_status = gmp_statuses[0] if gmp_statuses else mapped

    required_targets: list[str] = []
    for target in all_targets:
        try:
            tip = str(ipaddress.ip_address(str(target).strip()))
        except ValueError:
            tip = str(target).strip()
            if tip.casefold() in skipped_set:
                continue
            required_targets.append(tip)
            continue
        if tip in skipped_set:
            continue
        required_targets.append(tip)

    normalized_assessed: set[str] = set()
    for host in assessed:
        try:
            normalized_assessed.add(str(ipaddress.ip_address(host)))
        except ValueError:
            if host:
                normalized_assessed.add(host.casefold())
    missing = [t for t in required_targets if t not in normalized_assessed]

    # A missing report host is NOT proof of unreachability or assessment.
    # Explicit skips remain in the original target scope and block a clean result.
    missing = [t for t in all_targets if t not in normalized_assessed]

    coverage_ok = (
        mapped == "completed"
        and not missing
        and not report_read_errors
        and (
            (bool(report_ids) and bool(scan_starts) and bool(scan_ends))
            or (not required_targets and bool(skipped))
        )
    )
    assessment_complete = coverage_ok and (
        not required_targets
        or complete_chunks == len(chunk_results)
        or (len(chunk_results) > 0 and not missing)
    )

    progress = sum(progresses) / max(len(progresses), 1) if progresses else (100.0 if assessment_complete else 0.0)
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "status": mapped,
        "gmp_status": merged_task_status,
        "progress": progress,
        "vulnerabilities": vulns,
        "evidence": {
            "report_id": report_ids[0] if report_ids else ("skipped-unreachable" if skipped and not required_targets else None),
            "report_ids": report_ids,
            "task_status": merged_task_status,
            "progress": progress,
            "hosts_attempted": len(all_targets),
            "hosts_assessed": len(normalized_assessed) if normalized_assessed else 0,
            "assessed_hosts": sorted(assessed),
            "assessed_in_earlier_attempt": prior_kept,
            "skipped_hosts": skipped,
            "missing_ip_targets": missing,
            "report_result_count": result_count,
            # Declared GMP <errors><count> survives even when error rows were not readable.
            "plugin_error_count": max(plugin_error_total, len(plugin_errors)),
            "plugin_error_details": plugin_errors[:50],
            "host_coverage": host_coverage,
            "service_coverage": service_coverage,
            "policy_snapshots": policy_snapshots,
            "degraded_hosts": sorted(
                h for h, c in host_coverage.items()
                if str((c or {}).get("verdict") or "") != "full"
                and (c or {}).get("network_scan_complete") is not True
            ),
            "network_complete_hosts": sorted(
                h for h, c in host_coverage.items() if (c or {}).get("network_scan_complete") is True
            ),
            "scan_start": min(scan_starts) if scan_starts else (now_iso if assessment_complete and skipped else None),
            "scan_end": max(scan_ends) if scan_ends else (now_iso if assessment_complete and skipped else None),
            "assessment_complete": assessment_complete,
            "assessment_verdict": (
                "all_targets_unreachable_skipped"
                if assessment_complete and not required_targets and skipped
                else ("assessed" if assessment_complete else ("partial_or_running" if mapped == "running" else "incomplete_coverage"))
            ),
            "alive_test": alive_test or None,
            "report_read_error": "; ".join(report_read_errors[:3]) if report_read_errors else None,
            "chunk_count": len(chunk_results),
        },
    }


def _refresh_service_coverage(details: dict[str, Any], host: str) -> None:
    """Recompute per-service states after pre-probe evidence was merged (V1.7.0)."""
    from agent.service_policy import analyze_services

    ev = details.get("evidence")
    if not isinstance(ev, dict):
        return
    cov = (ev.get("host_coverage") or {}).get(host)
    snapshot = next(iter((ev.get("policy_snapshots") or {}).values()), {}) or {}
    try:
        services = dict(ev.get("service_coverage") or {})
        services[host] = analyze_services(list(details.get("vulnerabilities") or []), host=host,
                                          coverage=cov, scanned_port_range=snapshot.get("port_range"))
        ev["service_coverage"] = services
    except Exception:
        log.debug("Service coverage refresh failed for %s", host, exc_info=True)


def _ip_worker_limit(capacity: dict[str, Any], chunk_count: int) -> int:
    """How many IPs may scan at once.

    V1.6.7: SCAN_IP_WORKERS_FIXED (default 4) gives a fixed pool, independent
    of CPU-based sizing (which never went below IP_WORKERS_MIN=5). 0 restores
    adaptive sizing. A critical thermal/memory state still pauses *new* starts.
    """
    from agent.scan_performance import fixed_ip_workers

    fixed = fixed_ip_workers()
    if fixed > 0:
        return max(1, min(fixed, max(1, chunk_count)))
    return max(1, min(max(IP_WORKERS_MIN, int(capacity["ip_workers"])), max(1, chunk_count)))


def _silent_preprobe(states: Any) -> int:
    """Number of probed ports if the pre-probe got no answer at all, else 0 (V1.9.7).

    "No answer" means no port accepted the connection and none refused it with
    a TCP reset: every probe timed out. A host that resets ports is up.
    """
    if not isinstance(states, dict):
        return 0
    if states.get("open") or states.get("closed"):
        return 0
    return len(states.get("filtered") or [])


def _apply_time_limit(details: dict[str, Any], host: str, info: dict[str, Any]) -> dict[str, Any]:
    """Turn a task stopped at the per-IP time limit into an honest finished result.

    Findings are kept. If ports were enumerated (port scanning had finished),
    the host is a finished network scan *with a warning* naming the limit and
    the progress at which checks were stopped. If the limit hit during port
    scanning, the host is degraded_time_limit (incomplete). Never clean.
    """
    from datetime import datetime, timezone

    from agent.service_policy import analyze_services

    out = dict(details)
    ev = dict(out.get("evidence") or {})
    host_cov = dict(ev.get("host_coverage") or {})
    cov = dict(host_cov.get(host) or {"verdict": "unverified", "open_tcp_ports": [], "open_udp_ports": []})
    limit = int(info.get("limit") or 0)
    pct = int(info.get("progress") or 0)
    no_response = info.get("kind") == "no_response"
    if no_response:
        note = (
            f"No response: none of the {int(info.get('probed_ports') or 0)} TCP ports the agent probed answered "
            f"(no open port, no reset), and OpenVAS found no open port in {limit // 60} min of port scanning. "
            "The host is offline or drops all traffic. It was stopped so its scan slot could go to the next IP; "
            "it was not assessed."
        )
    else:
        note = (
            f"Per-IP time limit ({limit // 60} min) reached at {pct}%: the task was stopped and checks still "
            "running did not finish. Findings found before the limit are kept."
        )
    warnings = [w for w in (cov.get("warnings") or []) if w != note] + [note]
    ports_done = bool(cov.get("open_tcp_ports") or cov.get("open_udp_ports")) and pct >= 10 \
        and not cov.get("port_scanner_errors")
    cov.update({
        "time_limited": True, "time_limit_sec": limit, "stopped_at_progress": pct,
        "warnings": warnings[-20:], "coverage_complete": False, "service_checks_verified": False,
    })
    if ports_done:
        cov["verdict"] = "observed_unverified"
        cov["network_scan_complete"] = True
        cov["reason"] = (
            f"Time limit reached at {pct}% after port scanning finished "
            f"({len(cov.get('open_tcp_ports') or [])} open TCP port(s)); unfinished checks were stopped"
        )
    elif no_response:
        cov["verdict"] = "no_response"
        cov["network_scan_complete"] = False
        cov["reason"] = (f"No response on any probed port; OpenVAS port scan found no open port in "
                         f"{limit // 60} min (host offline or all traffic dropped). Not assessed")
    else:
        cov["verdict"] = "degraded_time_limit"
        cov["network_scan_complete"] = False
        cov["reason"] = f"Per-IP time limit ({limit}s) reached at {pct}% before port scanning finished"
    host_cov[host] = cov
    ev["host_coverage"] = host_cov
    ev["time_limited"] = True
    ev["assessment_verdict"] = ("assessed_time_limited" if ports_done
                                else "no_response" if no_response else "time_limit_before_port_scan")
    ev["assessment_complete"] = bool(ports_done)
    if not ev.get("scan_end"):
        ev["scan_end"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev["scan_end_source"] = "agent_time_limit"
    snapshot = next(iter((ev.get("policy_snapshots") or {}).values()), {}) or {}
    services = dict(ev.get("service_coverage") or {})
    services[host] = analyze_services(list(out.get("vulnerabilities") or []), host=host, coverage=cov,
                                      scanned_port_range=snapshot.get("port_range"))
    ev["service_coverage"] = services
    out["evidence"] = ev
    out["status"] = "completed"
    out["progress"] = 100
    return out


def _skipped_ip_details(host: str, reason: str, *, error: str | None = None, task_id: str | None = None) -> dict[str, Any]:
    """Terminal synthetic result for one omitted IP without failing sibling IPs."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "status": "completed",
        "gmp_status": "done",
        "progress": 100.0,
        "vulnerabilities": [],
        "evidence": {
            "task_status": "done",
            "assessment_complete": True,
            "assessment_verdict": "skipped_ip_error",
            "hosts_attempted": 0,
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": now,
            "scan_end": now,
            "skip_reason": reason,
            "skip_error": error,
            "task_id": task_id,
            "host": host,
        },
        "_agent_skip_reason": reason,
        "_agent_skip_error": error,
    }


def _run_job(cfg: dict[str, Any], job: dict[str, Any]) -> None:
    set_current_job_id(str(job.get("id") or "") or None)
    try:
        _run_job_body(cfg, job)
    finally:
        shipper = cfg.get("log_shipper")
        if shipper is not None:
            try:
                shipper.maybe_flush(force=True)
            except Exception:
                pass
        set_current_job_id(None)


def _run_job_body(cfg: dict[str, Any], job: dict[str, Any]) -> None:
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    job_id = str(job["id"])
    selected_targets = [t["target"] for t in (job.get("targets") or []) if t.get("target")]
    if not selected_targets:
        _patch_job_best_effort(api, job_id, {"status": "failed", "error": "No targets in job"})
        return

    if hasattr(openvas, "policy_snapshots"):
        openvas.policy_snapshots.update(clip_policy_snapshots(job.get("policy_snapshots"), selected_targets))
    prior_seq = job.get("progress_event_seq") or 0
    prior_seq = prior_seq if isinstance(prior_seq, int) and not isinstance(prior_seq, bool) and 0 <= prior_seq < 2**53 - 1 else 0
    sequence = max([prior_seq] + [int(s["event_seq"]) for s in (job.get("target_progress") or {}).values()
                          if isinstance(s, dict) and isinstance(s.get("event_seq"), int)
                          and not isinstance(s["event_seq"], bool) and 0 <= s["event_seq"] < 2**53 - 1])

    def target_snapshot(**kwargs: Any) -> dict[str, Any]:
        nonlocal sequence
        sequence += 1
        return build_target_progress(selected_targets, event_seq=sequence, **kwargs)

    from agent.reachability import partition_targets

    reach = partition_targets(selected_targets, job_id=job_id)
    skipped_hosts: list[dict[str, Any]] = list(reach.get("skipped_hosts") or [])
    reachable = list(reach.get("reachable") or [])
    # Resume from leftover work: do not rescan hosts this job already assessed.
    targets = remaining_hosts(
        selected=reachable,
        assessed=list(job.get("assessed_hosts") or []),
    )
    scanner_role = str(
        job.get("scanner_role") or os.environ.get("SCANNER_ROLE") or "portable"
    ).strip().lower()
    watch_lan = should_watch_lan(scanner_role)
    origin_fp = capture_lan_fingerprint() if watch_lan else {}
    orig_reachable = list(reachable)
    lan_misses = 0
    if watch_lan:
        log.info(
            "Portable LAN fingerprint for job %s gateway=%s subnet=%s source=%s",
            job_id,
            origin_fp.get("gateway") or "unknown",
            origin_fp.get("subnet") or "unknown",
            origin_fp.get("source") or "none",
        )
    if skipped_hosts:
        log.info(
            "Job %s eliminated %d unreachable IP(s); scanning %d reachable",
            job_id,
            len(skipped_hosts),
            len(targets),
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": 3,
                "message": (
                    f"Skipped {len(skipped_hosts)} unreachable IP(s); "
                    f"scanning {len(targets)} reachable"
                ),
            },
        )

    nets = network_key(selected_targets)
    if len(nets) > 1:
        log.warning(
            "Job %s targets span %d networks (%s); hosts off this LAN will be skipped",
            job_id,
            len(nets),
            ", ".join(sorted(nets)[:8]),
        )

    capacity = probe_laptop_capacity(force=True)
    stored = stored_task_entries(
        chunk_tasks=list(job.get("chunk_tasks") or []),
        external_scan_id=job.get("external_scan_id"),
    )
    live_hosts: dict[str, list[str] | None] = {}
    for item in stored:
        tid = str(item.get("task_id") or "").strip()
        if tid:
            live_hosts[tid] = openvas.get_task_hosts(tid)
    chunks, resume_map, dropped_tasks = plan_resume_chunks(
        job_hosts=selected_targets,
        remaining=targets,
        stored_tasks=stored,
        live_hosts=live_hosts,
        chunk_size=int(capacity["chunk_size"]),
    )
    if dropped_tasks:
        log.warning(
            "Job %s dropped %d OpenVAS task(s) that were missing or not this job's hosts: %s",
            job_id,
            len(dropped_tasks),
            ",".join(dropped_tasks[:6]),
        )

    if not chunks:
        if leftover_blocks_skip_complete(
            dropped_tasks=dropped_tasks,
            live_hosts=live_hosts,
            job_hosts=selected_targets,
        ):
            _patch_job_best_effort(
                api,
                job_id,
                {
                    "status": "failed",
                    "error": (
                        "Cannot resume: leftover OpenVAS task(s) belong to a different "
                        "host set or could not be read. Will not complete as skipped."
                    ),
                },
            )
            log.error(
                "Job %s refused to finish as skipped; leftover task(s) were the wrong network or unreadable: %s",
                job_id,
                ",".join(dropped_tasks[:6]),
            )
            return
        if dropped_tasks:
            log.info(
                "Job %s discarding %d stale OpenVAS task id(s) that no longer exist: %s",
                job_id,
                len(dropped_tasks),
                ",".join(dropped_tasks[:6]),
            )
            _patch_job_best_effort(
                api,
                job_id,
                {"external_scan_id": "", "chunk_tasks": []},
            )
        # Every selected IP was unreachable or already assessed, with nothing to harvest.
        merged = _merge_chunk_details([], all_targets=selected_targets, skipped_hosts=skipped_hosts)
        payload = _result_payload(
            details=merged,
            task_id="",
            status="completed",
            partial=False,
            skipped_hosts=skipped_hosts,
        )
        _upload_results_reliably(api, job_id, payload)
        log.info("Job %s completed with all %d target(s) skipped as unreachable", job_id, len(selected_targets))
        return

    # One permit == one IP.  Normal operation never drops below the requested
    # Capacity-aware IP concurrency; critical pressure pauses new admissions.
    ip_workers = _ip_worker_limit(capacity, len(chunks))
    for idx, chunk in enumerate(chunks):
        host = str(chunk[0]) if chunk else f"chunk-{idx}"
        emit_ip_event(job_id, host, "queued", chunk_index=idx, semaphore_limit=ip_workers)


    if resume_map:
        log.warning(
            "Resuming job %s with %d OpenVAS task(s) across %d host(s) from this job only",
            job_id,
            len(resume_map),
            sum(len(c) for c in chunks),
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": job.get("progress_pct"),
                "message": f"Resuming {len(resume_map)} OpenVAS task(s) for this network",
                "external_scan_id": _encode_external_task_ids(list(resume_map.values())),
                "chunk_tasks": [
                    {"task_id": tid, "hosts": chunks[idx]} for idx, tid in resume_map.items()
                ],
            },
        )
    else:
        log.info(
            "Claimed job %s targets=%d chunks=%d ip_workers=%d chunk_size=%d hot=%s",
            job_id,
            len(targets),
            len(chunks),
            ip_workers,
            capacity["chunk_size"],
            capacity["hot"],
        )
        _patch_job_best_effort(
            api,
            job_id,
            {
                "status": "running",
                "progress_pct": 5,
                "message": f"Starting local OpenVAS ({len(chunks)} capacity-sized chunk(s))",
            },
        )

    # Wave fan-out: at most ip_workers OpenVAS tasks in flight. On resume, all
    # known task ids are already running so they enter the active set first.
    task_ids: list[str | None] = [None] * len(chunks)
    done_details: dict[int, dict[str, Any]] = {}
    pending: list[int] = list(range(len(chunks)))
    # A truncated port scan is reported incomplete. Re-running the same host
    # repeats the same Nmap kill, so the automatic re-run is off unless
    # SCAN_DEGRADED_RETRY is set.
    degraded_retries: dict[int, int] = {}
    # V1.10.3: a task Greenbone reports "stopped"/"interrupted" although the
    # agent never stopped it (scanner or agent restart mid-scan; job 7fc54039
    # was at 94%) is started again instead of failing the IP. Once per IP.
    interrupted_restarts: dict[int, int] = {}
    interrupted_restart_budget = max(0, int(os.environ.get("SCAN_INTERRUPTED_RESTARTS") or 1))
    preprobe_by_host: dict[str, list[int]] = {}
    preprobe_states_by_host: dict[str, dict[str, list[int]]] = {}
    # V1.8.0: targets that are the scanner laptop itself (see agent/self_target.py).
    self_scan_by_host: dict[str, dict[str, Any]] = {}

    def _openvas_log_host(host: str) -> str:
        """The address OpenVAS itself scanned (and logs): the loopback alias for a self-scan."""
        return str((self_scan_by_host.get(host) or {}).get("scanned_via") or host)

    degraded_retry_budget = max(0, int(os.environ.get("SCAN_DEGRADED_RETRY") or 0))
    # Historical .env files frequently retain SCAN_IP_BUDGET_SEC=600.  It is
    # now a deprecated, diagnostic-only setting.  Never stop a Greenbone task,
    # harvest its report or assert 100% because of this legacy budget.
    old_ip_budget = (os.environ.get("SCAN_IP_BUDGET_SEC") or "").strip()
    if old_ip_budget not in {"", "0"}:
        log.warning(
            "LEGACY_IP_BUDGET_IGNORED: SCAN_IP_BUDGET_SEC=%s is obsolete; "
            "no per-IP Nexus time cutoff will be applied. Remove it from "
            ".env or set it to 0. Engine completion requires a terminal task state.",
            old_ip_budget[:30],
        )
    in_flight: dict[int, str] = {}
    lane_task_ids: dict[int, list[str]] = {}
    ip_started_mono: dict[int, float] = {}
    ip_last_state: dict[int, tuple[str, int]] = {}
    ip_progress_since: dict[int, tuple[int, float]] = {}
    # V1.6.6 stalled-task watchdog: (gmp_status, progress) and when it last changed.
    ip_change_since: dict[int, tuple[tuple[str, int], float]] = {}
    ip_stalled: dict[int, dict[str, Any]] = {}
    from agent.scan_performance import classify_stall, hang_registry, stall_decision, stall_limits

    ip_stall_noted: dict[int, float] = {}

    stall_cfg = stall_limits()
    from agent.scan_performance import (fixed_ip_workers, ip_runtime_limit, nvt_max_sec,
                                        per_ip_check_concurrency, resolve_profile)

    _policy_req = job.get("scan_policy_request") if isinstance(job.get("scan_policy_request"), dict) else None
    job_profile = resolve_profile(_policy_req)
    # V1.10.2: probe the job policy's own TCP ports (e.g. Polaron policy: 262), not
    # the laptop's PORT_PROFILE default list, so "no port answered" means exactly that.
    _job_probe_range: str | None = None
    try:
        if _policy_req:
            from agent.service_policy import effective_policy as _effective_policy

            _eff = _effective_policy(_policy_req)
            if _eff.get("port_profile") != "full" and 0 < int(_eff.get("tcp_port_count") or 0) <= 4096:
                _job_probe_range = ",".join(
                    t for t in str(_eff.get("port_range") or "").split(",") if t.upper().startswith("T:")
                ) or None
    except Exception:
        log.warning("Job %s: policy port list for the pre-probe could not be resolved", job_id, exc_info=True)
    # V1.9.3: each IP has its own clock, started when its OpenVAS task starts.
    # MAX_SCAN_RUNTIME_SEC used to be ONE clock for the whole job (job 3c4f45e0:
    # the 2nd IP got what the 1st IP left of 3600 s, and IPs still waiting got 0).
    ip_deadline, ip_deadline_source = ip_runtime_limit()
    ip_deadline_hit: dict[int, dict[str, Any]] = {}
    # V1.9.7: a host that answered none of the pre-probe ports (no open port, no
    # TCP reset) and is still in OpenVAS's port scan (0%) after this long is
    # stopped as "no response", so its slot goes to the next IP instead of being
    # held for the whole per-IP limit (job de53e2fe: 192.168.0.195, all 65,535
    # ports, 0% after 60 min). 0 = off.
    from agent.scan_performance import silent_host_sec
    silent_sec = silent_host_sec()
    last_parallel_log = time.monotonic()

    def _running_seconds(now_r: float | None = None) -> dict[int, int]:
        """Seconds each in-flight IP's OpenVAS task has run (V1.9.7, for the Activity column)."""
        now_r = time.monotonic() if now_r is None else now_r
        return {i: int(now_r - ip_started_mono[i]) for i in list(in_flight) if i in ip_started_mono}
    ip_tail_reported: dict[int, int] = {}
    per_ip_checks = per_ip_check_concurrency(job_profile)
    log.info(
        "Job %s speed profile=%s | parallel: up to %s IP(s) at once, %d checks at once per IP | "
        "per-IP time limit=%s (%s) | job limit=%s | per-check max=%s",
        job_id, job_profile, min(fixed_ip_workers() or ip_workers, max(1, len(chunks))), per_ip_checks,
        f"{ip_deadline}s" if ip_deadline else "off", ip_deadline_source,
        f"{cfg.get('max_job_runtime_sec')}s" if cfg.get("max_job_runtime_sec") else "off",
        f"{nvt_max_sec()}s" if nvt_max_sec() else "off",
    )
    from agent.scan_performance import fixed_ip_workers as _fixed_workers

    slot_sem = AdaptiveIPSemaphore(
        max_permits=_fixed_workers() or int(capacity.get("configured_ceiling") or 10)
    )

    for idx, tid in resume_map.items():
        ids = [part.strip() for part in str(tid).split(",") if part.strip()] or [str(tid)]
        task_ids[idx] = ids[0]
        lane_task_ids[idx] = ids
        in_flight[idx] = ids[0]
        ip_started_mono[idx] = time.monotonic()
        if idx in pending:
            pending.remove(idx)
        host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
        emit_ip_event(job_id, host, "resumed", task_id=",".join(ids), chunk_index=idx)
    slot_sem.restore(len(in_flight))

    # V1.9.3: IP starts run in parallel on their own threads. Starting one IP
    # (pre-probe, config lookup, target/task creation) took 45-55 s and used to
    # run on the polling thread, so IP 2 waited for IP 1's start and no IP was
    # polled meanwhile. Permits are still taken here, so the IP limit holds.
    start_pool = ThreadPoolExecutor(max_workers=max(1, slot_sem.max_permits), thread_name_prefix="aetheris-start")
    starting: dict[int, Any] = {}
    start_abort = threading.Event()

    def _ids_for(idx: int) -> list[str]:
        ids = [tid for tid in (lane_task_ids.get(idx) or []) if tid]
        if ids:
            return ids
        tid = in_flight.get(idx) or task_ids[idx]
        return [tid] if tid else []

    def _all_inflight_ids() -> list[str]:
        ids: list[str] = []
        for idx in list(in_flight):
            ids.extend(_ids_for(idx))
        return ids

    def _chunk_tasks_blob() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for idx, tid in enumerate(task_ids):
            ids = lane_task_ids.get(idx) or ([tid] if tid else [])
            for one in ids:
                if one:
                    rows.append({"task_id": one, "hosts": list(chunks[idx])})
        return rows

    def _append_skipped(host: str, reason: str, error: str | None = None) -> None:
        if not any(str(x.get("host") or "") == host for x in skipped_hosts):
            item: dict[str, Any] = {"host": host, "reason": reason}
            if error:
                item["error"] = error[:500]
            skipped_hosts.append(item)

    def _start_chunk(idx: int) -> str:
        existing = task_ids[idx]
        if existing:
            return existing
        if start_abort.is_set():
            raise RuntimeError("job is stopping; IP not started")
        chunk = list(chunks[idx])
        host = str(chunk[0]) if chunk else f"chunk-{idx}"
        if not host_set(chunk) <= host_set(selected_targets):
            raise RuntimeError(
                f"Refusing OpenVAS chunk {idx} for job {job_id}: hosts are not this job's targets"
            )
        emit_ip_event(job_id, host, "start_attempt", chunk_index=idx)

        # V1.8.0: is this authorized target the scanner laptop itself?
        scan_addresses: dict[str, str] = {}
        try:
            from agent.self_target import plan_self_targets

            self_plan = plan_self_targets(chunk)
            scan_addresses = dict(self_plan.get("aliases") or {})
            # V1.9.1: also record when the scanner could NOT tell whether the
            # target is itself (stale/legacy fingerprint). Jobs 320903ac and
            # 64b549f1 silently took the firewalled network path with no event.
            if scan_addresses or self_plan.get("host_ips") or self_plan.get("undetermined"):
                emit_ip_event(
                    job_id, host, "self_target_check",
                    is_self=host in scan_addresses, scan_address=scan_addresses.get(host),
                    host_ips=self_plan.get("host_ips"), source=self_plan.get("source"),
                    reason=self_plan.get("reason"), undetermined=bool(self_plan.get("undetermined")),
                    legacy_writer=bool(self_plan.get("legacy_writer")), chunk_index=idx,
                )
            if self_plan.get("legacy_writer"):
                _warn_legacy_fingerprint_writer(str(self_plan.get("reason") or ""))
        except Exception:
            log.warning("Self-target check failed for %s; scanning the network path", host, exc_info=True)
            scan_addresses = {}

        discovered_range: str | None = None
        if getattr(openvas, "port_profile", "full") != "full":
            try:
                from agent.port_discovery import discovery_plan

                port_plan = (
                    discovery_plan(chunk, port_range=_job_probe_range) if _job_probe_range
                    else discovery_plan(chunk)
                )
                # A fast probe only reports observations; it never changes GMP scope.
                observed_port_range = str(port_plan.get("observed_port_range") or "").strip()
                discovered_range = None
                open_by_host = port_plan.get("open_ports") or {}
                host_open = list(open_by_host.get(host) or [])
                preprobe_by_host[host] = host_open
                host_states = (port_plan.get("port_states") or {}).get(host)
                if isinstance(host_states, dict):
                    preprobe_states_by_host[host] = host_states
                emit_ip_event(
                    job_id,
                    host,
                    "port_discovery",
                    open_ports=host_open,
                    open_port_count=len(host_open),
                    closed_port_count=len((host_states or {}).get("closed") or []) if isinstance(host_states, dict) else None,
                    filtered_port_count=len((host_states or {}).get("filtered") or []) if isinstance(host_states, dict) else None,
                    observed_port_range=observed_port_range,
                    scan_range_source="Greenbone effective policy (not reduced by pre-probe)",
                    fallback=bool(port_plan.get("fallback")),
                    chunk_index=idx,
                )
                if host_open:
                    log.info(
                        "Job %s IP %s: discovery saw %d open TCP port(s) %s; "
                        "OpenVAS still scans the full Nessus-style service catalog",
                        job_id,
                        host,
                        len(host_open),
                        observed_port_range,
                    )
                else:
                    log.info(
                        "Job %s IP %s: no candidate port answered the pre-probe; "
                        "OpenVAS still scans the full Nessus-style service catalog",
                        job_id,
                        host,
                    )
                # Do not pass the narrowed discovery range. A partial answer
                # (SMB only) used to delete SSH and TLS from the assessment.
                discovered_range = None
                if host in scan_addresses:
                    from agent.port_discovery import candidate_range, probe_tcp_port_states
                    from agent.self_target import looks_like_accept_all

                    alias = scan_addresses[host]
                    local_states = probe_tcp_port_states([alias], port_range=candidate_range()).get(alias) or {}
                    network_states = dict(host_states) if isinstance(host_states, dict) else {}
                    if looks_like_accept_all(local_states):
                        # A proxy that accepts every port would make every service look
                        # open. Keep the honest network path instead.
                        scan_addresses.pop(host, None)
                        emit_ip_event(
                            job_id, host, "self_target_unreliable", scan_address=alias,
                            local_open_count=len(local_states.get("open") or []), chunk_index=idx,
                        )
                        log.warning(
                            "IP %s is this scanner, but %s accepted almost every port; scanning the network path",
                            host, alias,
                        )
                    else:
                        local_open = list(local_states.get("open") or [])
                        preprobe_by_host[host] = local_open
                        preprobe_states_by_host[host] = local_states
                        self_scan_by_host[host] = {
                            "scanned_via": alias,
                            "network_exposure": {
                                "address": host,
                                "open": list(network_states.get("open") or []),
                                "closed_count": len(network_states.get("closed") or []),
                                "filtered_count": len(network_states.get("filtered") or []),
                            },
                            "local_open_ports": local_open,
                        }
                        emit_ip_event(
                            job_id, host, "self_target", scan_address=alias,
                            local_open_ports=local_open,
                            network_open_ports=list(network_states.get("open") or []),
                            network_filtered_count=len(network_states.get("filtered") or []),
                            chunk_index=idx,
                        )
                        log.info(
                            "IP %s is this scanner laptop: network path shows %d open / %d no answer; "
                            "scanning the local view through %s (%d listening policy port(s))",
                            host, len(network_states.get("open") or []),
                            len(network_states.get("filtered") or []), alias, len(local_open),
                        )
            except Exception as exc:
                # Discovery is an optimization only. Never drop an authorized target
                # because a quick pre-probe or local socket operation failed.
                emit_ip_event(
                    job_id, host, "port_discovery_error",
                    error=f"{exc.__class__.__name__}: {exc}", chunk_index=idx,
                )
                log.warning("Port discovery failed for %s; continuing with configured OpenVAS profile", host, exc_info=True)

        if scan_addresses.get(host) and host not in self_scan_by_host:
            # Port discovery was off or failed: still label the local-view scan.
            self_scan_by_host[host] = {"scanned_via": scan_addresses[host], "network_exposure": None,
                                       "local_open_ports": None}
        policy = job.get("scan_policy_request")
        planned = ""
        resolver = getattr(openvas, "resolve_port_range", None)
        if callable(resolver):
            try:
                planned = str(resolver(chunk, discovered_range, policy) or "")
            except Exception:
                log.warning("Could not resolve the port range for %s; starting one OpenVAS task", host, exc_info=True)
                planned = ""
        from agent.service_lanes import lanes_for_port_range

        # One OpenVAS task scans the whole Nexus catalog. Four tasks used to
        # split that list, and each task ended after hostname/OS/traceroute
        # whenever its slice had no open port, so SSH, TLS, and SMB checks
        # never ran. In-IP parallelism is the service-check concurrency
        # (OpenVAS max_checks). V1.9.3: the value logged is the value used.
        checks = per_ip_checks
        catalog = (
            lanes_for_port_range(planned, lanes=1)[0]
            if planned
            else {"port_range": planned or "nexus catalog", "services": []}
        )
        log.info(
            "Nexus scope IP %s — one catalog scan, %d service checks at a time (%d services)",
            host,
            checks,
            len(catalog.get("services") or []),
        )
        # SERVICE_PLAN events are emitted only after Greenbone accepts the task.
        start_args = {
            "name": f"edge-{job_id[:8]}-c{idx}",
            "targets": chunk,
            "max_checks": checks,
        }
        if not planned and not callable(resolver):
            # Compatibility for local scan adapters exposing start_scan() but
            # not resolve_port_range(): supply the configured broad policy,
            # never the narrow fast pre-probe observation.
            from agent.gmp_local import _default_scan_port_range
            planned = _default_scan_port_range(str(getattr(openvas, "port_profile", "nexus") or "nexus"))
        if planned:
            start_args["port_range"] = planned
        if policy:
            start_args["scan_policy"] = policy
        if scan_addresses.get(host):
            start_args["scan_addresses"] = {host: scan_addresses[host]}
        # Older injectable scanner adapters may not expose the optional
        # per-task max_checks keyword. The native LocalOpenVAS implementation
        # does and retains the quality settings; omit only for a legacy adapter.
        import inspect
        try:
            params = inspect.signature(openvas.start_scan).parameters
            accepts_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
            if "max_checks" not in params and not accepts_kwargs:
                start_args.pop("max_checks", None)
            if "scan_addresses" not in params and not accepts_kwargs and start_args.pop("scan_addresses", None):
                log.warning("Scanner adapter cannot reroute self-targets; %s is scanned on the network path", host)
                self_scan_by_host.pop(host, None)
        except (TypeError, ValueError):
            pass
        tid = openvas.start_scan(**start_args)
        if start_abort.is_set():
            # The job was stopped while this IP was starting: do not leave a task running.
            try:
                openvas.stop(tid)
            except Exception:
                log.warning("stop_task for late-started task %s failed", tid, exc_info=True)
            raise RuntimeError("job stopped while this IP was starting")
        task_ids[idx] = tid
        lane_task_ids[idx] = [tid]
        ip_started_mono[idx] = time.monotonic()
        emit_ip_event(
            job_id, host, "started", task_id=",".join(lane_task_ids.get(idx) or [tid]),
            service_lanes=len(lane_task_ids.get(idx) or [tid]), chunk_index=idx,
        )
        try:
            emit_service_plan(job_id, host, str(tid))
        except Exception:
            log.warning("Could not emit service plan for %s", host, exc_info=True)
        return tid

    def _log_service_lane(host: str, chunk_index: int, lane_index: int, lane: dict[str, Any]) -> None:
        names = [str(name).strip() for name in (lane.get("services") or []) if str(name).strip()]
        port_range = str(lane.get("port_range") or "").strip()
        if not names:
            label = port_range or "service lane"
            log.info("Scanning IP %s service %s", host, label)
            emit_ip_event(
                job_id, host, "service_scan", service=label, ip=host,
                lane=lane_index, port_range=port_range, chunk_index=chunk_index,
            )
            return
        for service_name in names:
            log.info("Scanning IP %s service %s", host, service_name)
            emit_ip_event(
                job_id, host, "service_scan", service=service_name, ip=host,
                lane=lane_index, port_range=port_range, chunk_index=chunk_index,
            )

    def _fill_slots(workers: int, *, admission_paused: bool = False) -> None:
        if admission_paused or start_abort.is_set():
            return
        live_limit = max(0, int(workers))
        while pending:
            if not slot_sem.try_acquire(live_limit):
                break
            idx = pending.pop(0)
            starting[idx] = start_pool.submit(_start_chunk, idx)

    def _collect_starts(wait_sec: float = 0.0) -> None:
        """Move finished starts into in_flight (main thread only)."""
        if not starting:
            return
        if wait_sec > 0 and not any(f.done() for f in starting.values()):
            futures_wait(list(starting.values()), timeout=wait_sec, return_when=FIRST_COMPLETED)
        started_any = False
        for idx in [i for i, f in list(starting.items()) if f.done()]:
            fut = starting.pop(idx)
            host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
            try:
                tid = fut.result()
            except Exception as exc:
                # Per-IP best effort: omit only this IP, release its permit; the
                # next _fill_slots gives the slot to the next IP.
                slot_sem.release()
                err = f"{exc.__class__.__name__}: {exc}"
                _append_skipped(host, "start_error", err)
                done_details[idx] = _skipped_ip_details(host, "start_error", error=err)
                emit_ip_event(job_id, host, "start_error", error=err, chunk_index=idx)
                log.warning("Skipping IP %s after OpenVAS start error; next IP may use the released slot",
                            host, exc_info=exc)
                continue
            in_flight[idx] = tid
            started_any = True
        if started_any and getattr(openvas, "policy_snapshots", None):
            _patch_job_best_effort(api, job_id, {"policy_snapshots": clip_policy_snapshots(
                openvas.policy_snapshots, selected_targets)})

    def _scanning_ips() -> dict[int, str]:
        """IPs that hold a slot: started, or still starting (no task id yet)."""
        return {**{i: "" for i in starting}, **in_flight}

    def _abort_starts(timeout: float = 180.0) -> None:
        """Stop starting new IPs; hand any task that did start to the caller's stop loop."""
        start_abort.set()
        for idx, fut in list(starting.items()):
            try:
                tid = fut.result(timeout=timeout)
            except Exception:
                tid = None
            if tid:
                in_flight[idx] = tid
        starting.clear()
        start_pool.shutdown(wait=False)

    _fill_slots(ip_workers, admission_paused=bool(capacity.get("admission_paused")))
    _collect_starts()

    def _external_blob() -> str:
        ids: list[str] = []
        for idx, tid in enumerate(task_ids):
            lane_ids = lane_task_ids.get(idx) or ([tid] if tid else [])
            ids.extend(one for one in lane_ids if one)
        return _encode_external_task_ids(ids)

    external_blob = _external_blob()
    _patch_job_best_effort(
        api,
        job_id,
        {
            "status": "running",
            "progress_pct": 10,
            "message": (
                f"OpenVAS running ({len(in_flight) + len(starting)}/{len(chunks)} IP(s) starting or "
                f"in flight, {len(done_details)} done)"
            ),
            "external_scan_id": external_blob,
            "chunk_tasks": _chunk_tasks_blob(),
            "target_progress": target_snapshot(chunks=chunks,
                in_flight=_scanning_ips(), done_details=done_details, skipped_hosts=skipped_hosts,
                assessed_hosts=list(job.get("assessed_hosts") or []),
                running_sec=_running_seconds(), slots=slot_sem.max_permits),
        },
    )

    run_started = time.monotonic()
    last_progress = -1.0
    last_status_patch_at = 0.0
    last_ip_status_sig: tuple[tuple[str, str, int], ...] | None = None
    last_change = run_started
    last_high_progress_notice = 0.0
    poll = cfg["poll"]
    high_progress_warn_sec = cfg["high_progress_warn_sec"]
    high_progress_stall_sec = int(cfg.get("high_progress_stall_sec") or 0)
    high_progress_stall_pct = int(cfg.get("high_progress_stall_pct") or 90)
    # V1.9.3: whole-job cap is MAX_JOB_RUNTIME_SEC only (default off); the
    # per-IP limit above is what bounds each IP.
    max_job_runtime_sec = int(cfg.get("max_job_runtime_sec") or 0)

    while True:
        time.sleep(poll)
        # V1.9.3: pick up IPs whose start finished. With nothing to poll yet,
        # wait (bounded) for the first start instead of spinning.
        _collect_starts(wait_sec=0.0 if in_flight else max(1.0, float(poll or 0)))
        if watch_lan:
            current_fp = capture_lan_fingerprint()
            left_lan = lan_changed(origin_fp, current_fp)
            if not left_lan and is_docker_nat_fingerprint(origin_fp) and orig_reachable:
                from agent.reachability import partition_targets as _reprobe

                still = _reprobe(orig_reachable)
                if not still.get("reachable"):
                    lan_misses += 1
                    left_lan = lan_misses >= 2
                else:
                    lan_misses = 0
            if left_lan:
                log.error(
                    "Portable scanner left original LAN for job %s (was %s now %s); stopping OpenVAS",
                    job_id,
                    origin_fp.get("gateway"),
                    current_fp.get("gateway"),
                )
                _abort_starts()
                for tid in _all_inflight_ids():
                    try:
                        openvas.stop(tid)
                    except Exception:
                        log.warning("stop_task after LAN change failed for %s", tid, exc_info=True)
                _patch_job_best_effort(
                    api,
                    job_id,
                    {
                        "status": "failed",
                        "error": (
                            "Portable scanner left the original LAN mid-scan. OpenVAS was stopped. "
                            "Resume this same job after returning to the original network. "
                            "Targets were not merged with the new network."
                        ),
                    },
                )
                return
        capacity = probe_laptop_capacity()
        # Adaptive semaphore: 6 IP permits whenever admission is allowed. At a
        # critical thermal/memory state, new starts pause while in-flight IPs finish.
        ip_workers = _ip_worker_limit(capacity, len(chunks))

        # Poll in-flight chunks (bounded concurrency for GMP I/O).
        finished_idxs: list[int] = []
        poll_workers = max(1, min(ip_workers, len(in_flight) or 1))

        def _poll_one(idx: int) -> tuple[int, dict[str, Any]]:
            from agent.service_lanes import merge_service_lane_polls

            ids = _ids_for(idx)
            primary = ids[0] if ids else in_flight.get(idx)
            host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
            parts: list[dict[str, Any]] = []
            last_err = ""
            for tid in ids:
                try:
                    parts.append(openvas.poll(tid, expected_targets=chunks[idx]))
                except Exception as exc:
                    last_err = f"{exc.__class__.__name__}: {exc}"
                    emit_ip_event(job_id, host, "poll_error", task_id=tid, error=last_err, chunk_index=idx)
                    # A single GMP read failure is transient, particularly while
                    # gvmd is assembling a report. Do NOT stop the engine or
                    # classify the IP as scanned/failed; retry next polling cycle.
                    parts.append({
                        "status": "running", "progress": 0, "vulnerabilities": [],
                        "evidence": {"poll_warning": last_err, "assessment_complete": False},
                    })
            return idx, merge_service_lane_polls(parts)

        poll_results: dict[int, dict[str, Any]] = {}
        if in_flight:
            with ThreadPoolExecutor(max_workers=poll_workers, thread_name_prefix="aetheris-ip") as pool:
                futs = [pool.submit(_poll_one, idx) for idx in list(in_flight)]
                for fut in futs:
                    idx, details = fut.result()
                    host = str(chunks[idx][0]) if chunks[idx] else f"chunk-{idx}"
                    tid = in_flight.get(idx)
                    st = str(details.get("status") or "running").lower()
                    progress_i = int(float(details.get("progress") or 0))
                    state_key = (st, progress_i)
                    if ip_last_state.get(idx) != state_key:
                        ip_last_state[idx] = state_key
                        emit_ip_event(
                            job_id, host, "progress", task_id=tid, status=st,
                            progress=progress_i, chunk_index=idx,
                        )

                    # --- V1.6.6 stalled-task watchdog --------------------------------
                    # NVT hangs are bounded by plugins_timeout inside OpenVAS. This
                    # only acts when a task makes no progress for many multiples
                    # of that limit (scanner/process stuck, task never started).
                    gmp_state = str(details.get("gmp_status") or st).strip().lower()
                    change_key = (gmp_state, progress_i)
                    now_w = time.monotonic()
                    seen = ip_change_since.get(idx)
                    if seen is None or seen[0] != change_key:
                        ip_change_since[idx] = (change_key, now_w)
                    elif st == "running":
                        unchanged_w = now_w - seen[1]
                        stall_reason = classify_stall(gmp_state, progress_i, unchanged_w, stall_cfg)
                        prior = ip_stalled.get(idx)
                        decision = "wait"
                        activity_w: dict[str, Any] = {}
                        if stall_reason:
                            if gmp_state in {"new", "requested", "queued"}:
                                decision = "stop"  # never started: nothing to lose
                            else:
                                from agent.openvas_log import describe, host_activity

                                activity_w = host_activity(_openvas_log_host(host))
                                decision = stall_decision(activity_w)
                                if decision == "wait" and now_w - ip_stall_noted.get(idx, 0.0) >= 300:
                                    ip_stall_noted[idx] = now_w
                                    log.warning("IP %s: %s; NOT stopping (no time limit): %s",
                                                host, stall_reason, describe(activity_w))
                                    emit_ip_event(job_id, host, "stall_wait", task_id=tid, reason=stall_reason,
                                                  progress=progress_i, evidence=describe(activity_w),
                                                  running=activity_w.get("running"),
                                                  host_finished=activity_w.get("host_finished"))
                        if decision == "stop" and stall_reason and (prior is None or now_w - prior["stop_at"] >= 300):
                            if activity_w:
                                from agent.openvas_log import describe

                                stall_reason = f"{stall_reason}; {describe(activity_w)}"
                            ip_stalled[idx] = {"reason": stall_reason, "stop_at": now_w,
                                               "progress": progress_i, "gmp_status": gmp_state}
                            log.error(
                                "Job %s IP %s STALLED: %s. Stopping task %s; partial findings are kept "
                                "and the host is reported incomplete (stalled), not completed",
                                job_id, host, stall_reason, tid,
                            )
                            emit_ip_event(job_id, host, "stalled", task_id=tid, reason=stall_reason,
                                          progress=progress_i, gmp_status=gmp_state, chunk_index=idx)
                            for one in _ids_for(idx):
                                try:
                                    openvas.stop(one)
                                except Exception:
                                    log.warning("stop_task for stalled task %s failed", one, exc_info=True)

                    # --- V1.6.7 per-IP time limit -----------------------------------
                    if st == "running" and ip_deadline > 0 and idx not in ip_deadline_hit and idx not in ip_stalled:
                        elapsed_d = now_w - ip_started_mono.get(idx, now_w)
                        if elapsed_d >= ip_deadline:
                            ip_deadline_hit[idx] = {"limit": ip_deadline, "progress": progress_i,
                                                    "elapsed": int(elapsed_d)}
                            log.warning(
                                "Job %s IP %s reached the per-IP time limit (%ss) at %s%%; stopping task %s. "
                                "Findings are kept; the host is reported finished at the time limit",
                                job_id, host, ip_deadline, progress_i, tid,
                            )
                            emit_ip_event(job_id, host, "time_limit", task_id=tid, limit_sec=ip_deadline,
                                          progress=progress_i, chunk_index=idx)
                            for one in _ids_for(idx):
                                try:
                                    openvas.stop(one)
                                except Exception:
                                    log.warning("stop_task at time limit failed for %s", one, exc_info=True)
                    # --- V1.9.7 silent host: nothing answered, still port scanning -------
                    if (st == "running" and silent_sec > 0 and progress_i <= 0
                            and idx not in ip_deadline_hit and idx not in ip_stalled
                            and host not in self_scan_by_host):
                        probed = _silent_preprobe(preprobe_states_by_host.get(host))
                        elapsed_s = now_w - ip_started_mono.get(idx, now_w)
                        if probed and elapsed_s >= silent_sec:
                            ip_deadline_hit[idx] = {"limit": int(elapsed_s), "progress": 0, "elapsed": int(elapsed_s),
                                                    "kind": "no_response", "probed_ports": probed}
                            log.warning(
                                "Job %s IP %s: no response - none of %d probed TCP ports answered and OpenVAS "
                                "found no open port in %d min of port scanning; stopping task %s and reporting "
                                "the host as not assessed. Its slot goes to the next IP",
                                job_id, host, probed, int(elapsed_s) // 60, tid,
                            )
                            emit_ip_event(job_id, host, "no_response", task_id=tid, after_sec=int(elapsed_s),
                                          probed_ports=probed, chunk_index=idx)
                            for one in _ids_for(idx):
                                try:
                                    openvas.stop(one)
                                except Exception:
                                    log.warning("stop_task for silent host failed for %s", one, exc_info=True)
                    # --- V1.6.7 what is OpenVAS doing at 90 %+? ------------------------
                    seen_t = ip_change_since.get(idx)
                    if (st == "running" and progress_i >= 90 and seen_t is not None
                            and now_w - seen_t[1] >= 300 and ip_tail_reported.get(idx) != progress_i):
                        ip_tail_reported[idx] = progress_i
                        try:
                            from agent.openvas_log import describe, host_activity

                            activity = host_activity(_openvas_log_host(host))
                            # V1.9.2: a named running check (or a finished host) at 98 % is the
                            # normal tail of a scan, not a problem; only blind spots warn.
                            seen = bool(activity.get("running") or activity.get("host_finished"))
                            (log.info if seen else log.warning)(
                                "IP %s at %s%% for %ss: %s. OpenVAS log NVTs: %s; slow finished: %s",
                                host, progress_i, int(now_w - seen_t[1]), describe(activity),
                                ", ".join(activity.get("nvt_oids") or []) or "none found",
                                ", ".join(f"{x['name']} {x['seconds']}s" for x in (activity.get("slow_finished") or [])[:5])
                                or "none",
                            )
                            emit_ip_event(job_id, host, "tail_activity", task_id=tid, progress=progress_i,
                                          nvt_oids=activity.get("nvt_oids"), lines=(activity.get("lines") or [])[-8:],
                                          running=activity.get("running"), slow_finished=activity.get("slow_finished"),
                                          host_finished=activity.get("host_finished"),
                                          summary=describe(activity), log_available=activity.get("available"),
                                          whole_attack_logging=activity.get("whole_attack_logging"),
                                          host_started_seen=activity.get("host_started_seen"),
                                          debug_share=activity.get("debug_share"),
                                          log_host=_openvas_log_host(host))
                        except Exception:
                            log.debug("OpenVAS log diagnostics unavailable", exc_info=True)

                    skip_reason = str(details.get("_agent_skip_reason") or "").strip()
                    if skip_reason:
                        _append_skipped(host, skip_reason, str(details.get("_agent_skip_error") or "") or None)
                        poll_results[idx] = details
                        done_details[idx] = details
                        finished_idxs.append(idx)
                        continue

                    # Do not convert running tasks to completed because elapsed
                    # time reached a per-IP budget.  The old 600-second Nexus
                    # branch stopped service lanes and uploaded partial reports.
                    # Poll until GMP reports Done/Stopped/Failed, unless the
                    # separately configured job-wide safety ceiling is reached.

                    if st == "running" and high_progress_stall_sec > 0:
                        pct_i = int(float(details.get("progress") or 0))
                        mark = ip_progress_since.get(idx)
                        now_m = time.monotonic()
                        # Clock starts when this percent is first seen. Backdating
                        # made a live 94% look frozen and harvested the port scan
                        # before Nmap had written any ports.
                        if mark is None or pct_i > mark[0]:
                            ip_progress_since[idx] = (pct_i, now_m)
                        elif ip_tail_should_harvest(
                            pct_i,
                            now_m - mark[1],
                            stall_sec=high_progress_stall_sec,
                            stall_pct=high_progress_stall_pct,
                        ):
                            unchanged = now_m - mark[1]
                            log.warning(
                                "IP %s frozen at %s%% for %.0fs — reading the report already collected",
                                host,
                                pct_i,
                                unchanged,
                            )
                            harvested_box: dict[str, Any] = {}

                            lane_ids = list(_ids_for(idx))

                            def _read_report() -> None:
                                from agent.service_lanes import merge_service_lane_polls

                                try:
                                    parts = [
                                        openvas.poll(
                                            one,
                                            expected_targets=chunks[idx],
                                            include_running_report=True,
                                        )
                                        for one in lane_ids
                                    ]
                                    harvested_box["value"] = merge_service_lane_polls(parts)
                                except Exception as exc:
                                    harvested_box["error"] = exc

                            reader = threading.Thread(target=_read_report, daemon=True)
                            reader.start()
                            reader.join(40)
                            reason = f"frozen {int(unchanged)}s at {pct_i}%"
                            harvested = dict(harvested_box["value"]) if "value" in harvested_box else None
                            cov_verdict = ""
                            if harvested is not None:
                                cov = ((harvested.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                                cov_verdict = str(cov.get("verdict") or "")
                            if cov_verdict.startswith("degraded"):
                                log.warning(
                                    "IP %s is at %s%% and the port scan is still unfinished (%s); leaving the scan running",
                                    host,
                                    pct_i,
                                    cov_verdict,
                                )
                                ip_progress_since[idx] = (pct_i, now_m)
                            elif harvested is not None:
                                log.warning(
                                    "IP %s remains %s%%: partial report observed, but task is "
                                    "not GMP-terminal. %d provisional finding(s) retained by "
                                    "Greenbone; no stop_task or false completion",
                                    host, pct_i, len(harvested.get("vulnerabilities") or []),
                                )
                                # Do not hammer GMP every poll. A definite Done,
                                # Stopped or Failed response is required to finish.
                                ip_progress_since[idx] = (pct_i, now_m)
                            else:
                                log.warning(
                                    "IP %s is still at %s%% and the report has no host evidence yet; leaving the scan running",
                                    host,
                                    pct_i,
                                )
                                ip_progress_since[idx] = (pct_i, now_m - float(high_progress_stall_sec) + 20)

                    if st == "stopped" and idx in ip_deadline_hit and idx not in ip_stalled:
                        details = _apply_time_limit(details, host, ip_deadline_hit[idx])
                        st = "completed"
                    if st == "completed":
                        from agent.coverage_reconcile import reconcile_host_observations
                        details = reconcile_host_observations(
                            details, host, preprobe_by_host.get(host), preprobe_states_by_host.get(host),
                        )
                        if host in self_scan_by_host:
                            from agent.self_target import annotate_self_scan

                            details = annotate_self_scan(details, host, self_scan_by_host[host])
                        _refresh_service_coverage(details, host)
                    if st in {"completed", "failed", "stopped"}:
                        # V1.6.6: learn which NVTs hit their timeout so fast mode can
                        # cap repeat offenders instead of waiting 320 s on every host.
                        try:
                            hang_registry().record(
                                (details.get("evidence") or {}).get("plugin_error_details"),
                                host=host, job_id=job_id,
                            )
                        except Exception:
                            log.debug("NVT hang statistics not recorded for %s", host, exc_info=True)
                        # V1.9.5: name the check behind "completed with warnings".
                        try:
                            from agent.scan_performance import timed_out_check_notes

                            ev_n = details.get("evidence") if isinstance(details.get("evidence"), dict) else {}
                            cov_n = (ev_n.get("host_coverage") or {}).get(host)
                            via = (self_scan_by_host.get(host) or {}).get("scanned_via") if host in self_scan_by_host else None
                            extra = timed_out_check_notes(ev_n.get("plugin_error_details"), host,
                                                          self_scan_via=str(via) if via else None)
                            if extra and isinstance(cov_n, dict):
                                cov_n["notes"] = (list(cov_n.get("notes") or []) + extra)[-20:]
                                for note in extra:
                                    log.warning("Job %s IP %s: %s", job_id, host, note)
                        except Exception:
                            log.debug("Timed-out check notes not added for %s", host, exc_info=True)
                    if st == "completed":
                        cov_p = ((details.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                        if cov_p.get("verdict") == "discovery_not_alive":
                            # Ping-only discovery: a host that does not answer is a valid
                            # result, reported as skipped/not alive rather than a failed scan.
                            note = "No answer to ICMP, TCP-ACK or ARP ping (ping-only discovery)"
                            _append_skipped(host, "not_alive", note)
                            emit_ip_event(job_id, host, "not_alive", task_id=tid, chunk_index=idx)
                            normalized = _skipped_ip_details(host, "not_alive", error=note, task_id=tid)
                            poll_results[idx] = normalized
                            done_details[idx] = normalized
                            finished_idxs.append(idx)
                            continue
                    if (
                        st == "stopped"
                        and idx not in ip_deadline_hit
                        and idx not in ip_stalled
                        and not start_abort.is_set()
                        and interrupted_restarts.get(idx, 0) < interrupted_restart_budget
                    ):
                        interrupted_restarts[idx] = interrupted_restarts.get(idx, 0) + 1
                        stopped_pct = int(float(details.get("progress") or 0))
                        log.warning(
                            "Job %s IP %s: OpenVAS task %s is stopped at %s%% but the agent did not stop it "
                            "(scanner or agent restart); starting a fresh task (attempt %d of %d)",
                            job_id, host, tid, stopped_pct, interrupted_restarts[idx], interrupted_restart_budget,
                        )
                        emit_ip_event(
                            job_id, host, "interrupted_restart", task_id=tid, progress=stopped_pct,
                            attempt=interrupted_restarts[idx], chunk_index=idx,
                        )
                        lane_task_ids.pop(idx, None)
                        task_ids[idx] = None
                        poll_results.pop(idx, None)
                        in_flight.pop(idx, None)
                        ip_progress_since.pop(idx, None)
                        slot_sem.release()
                        pending.append(idx)
                        continue
                    if st in {"failed", "stopped"}:
                        # Do not let one bad IP fail 49 healthy peers. Preserve any
                        # partial findings in the per-IP log, mark the host skipped,
                        # then release the permit for the next queued IP.
                        ev = details.get("evidence") or {}
                        err = str(ev.get("report_read_error") or details.get("error") or f"OpenVAS {st}")
                        stall = ip_stalled.get(idx)
                        if stall:
                            err = (
                                f"Stalled: {stall['reason']}. The agent stopped the task; partial findings "
                                f"are kept and this host is not counted as assessed. ({err})"
                            )[:900]
                            st = "stalled"
                        _append_skipped(host, f"scan_{st}", err)
                        emit_ip_event(
                            job_id, host, "scan_failed", task_id=tid, status=st,
                            error=err, vulnerabilities=len(details.get("vulnerabilities") or []),
                            duration_sec=round(time.monotonic() - ip_started_mono.get(idx, time.monotonic()), 3),
                        )
                        try:
                            emit_service_results(job_id, host, details, str(tid or ""))
                        except Exception:
                            log.warning("Service audit failed for %s; original scan result retained", host, exc_info=True)
                        preserved = list(details.get("vulnerabilities") or [])
                        normalized = _skipped_ip_details(host, f"scan_{st}", error=err, task_id=tid)
                        normalized["vulnerabilities"] = preserved
                        # V1.9.8: the kept rows must be declared too. The synthetic
                        # skip sets report_result_count=0, so the job uploaded more
                        # rows than it declared and the central integrity check
                        # failed the whole job (fcbb90c0: 241 declared, 291 rows -
                        # the 50 partial findings of the failed IP). Keep the count
                        # OpenVAS declared for this IP's report; if none was read,
                        # declare the rows actually kept.
                        if preserved:
                            declared = int(ev.get("report_result_count") or 0)
                            normalized["evidence"]["report_result_count"] = declared or len(preserved)
                        poll_results[idx] = normalized
                        done_details[idx] = normalized
                        finished_idxs.append(idx)
                    else:
                        poll_results[idx] = details
                        if st == "completed":
                            cov = ((details.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                            cov_verdict = str(cov.get("verdict") or "unverified")
                            if (
                                cov_verdict.startswith("degraded")
                                and cov_verdict != "degraded_time_limit"
                                and degraded_retries.get(idx, 0) < degraded_retry_budget
                            ):
                                degraded_retries[idx] = degraded_retries.get(idx, 0) + 1
                                log.warning(
                                    "Job %s IP %s: scan DEGRADED (%s) — %s; re-running once",
                                    job_id, host, cov_verdict, cov.get("reason"),
                                )
                                emit_ip_event(
                                    job_id, host, "coverage_retry", task_id=tid, verdict=cov_verdict,
                                    reason=cov.get("reason"), attempt=degraded_retries[idx], chunk_index=idx,
                                )
                                # st == completed above: the old Greenbone task
                                # has already reached a terminal state and its
                                # evidence has been saved. Starting a fresh task
                                # is sufficient; do not issue stop_task on Done.
                                log.info(
                                    "Coverage retry for %s: preserving terminal Greenbone task %s; no stop_task",
                                    host, tid,
                                )
                                lane_task_ids.pop(idx, None)
                                task_ids[idx] = None
                                poll_results.pop(idx, None)
                                in_flight.pop(idx, None)
                                slot_sem.release()
                                pending.append(idx)
                                continue
                            if cov_verdict.startswith("degraded"):
                                log.error(
                                    "Job %s IP %s: scan INCOMPLETE (%s) — %s",
                                    job_id, host, cov_verdict, cov.get("reason"),
                                )
                                emit_ip_event(
                                    job_id, host, "coverage_incomplete", task_id=tid, verdict=cov_verdict,
                                    reason=cov.get("reason"), chunk_index=idx,
                                )
                            done_details[idx] = details
                            finished_idxs.append(idx)
                            try:
                                emit_service_results(job_id, host, details, str(tid or ""))
                            except Exception:
                                log.warning("Service audit failed for %s; original scan result retained", host, exc_info=True)
                            emit_ip_event(
                                job_id, host, "completed", task_id=tid, progress=100,
                                coverage=cov_verdict, agent_build=_agent_build(),
                                vulnerabilities=len(details.get("vulnerabilities") or []),
                                report_id=(details.get("evidence") or {}).get("report_id"),
                                report_results=(details.get("evidence") or {}).get("report_result_count"),
                                plugin_errors=(details.get("evidence") or {}).get("plugin_error_count"),
                                duration_sec=round(time.monotonic() - ip_started_mono.get(idx, time.monotonic()), 3),
                            )

        for idx in finished_idxs:
            in_flight.pop(idx, None)
            slot_sem.release()

        _fill_slots(ip_workers, admission_paused=bool(capacity.get("admission_paused")))

        external_blob = _external_blob()

        # Merge finished + still-running for progress; pending chunks count as 0%.
        live: list[tuple[list[str], dict[str, Any]]] = []
        for idx, chunk in enumerate(chunks):
            if idx in done_details:
                live.append((chunk, done_details[idx]))
            elif idx in poll_results:
                live.append((chunk, poll_results[idx]))
            elif idx in in_flight:
                live.append((chunk, {"status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}))
            else:
                live.append((chunk, {"status": "running", "progress": 0, "vulnerabilities": [], "evidence": {}}))

        merged = _merge_chunk_details(
            live, all_targets=selected_targets, skipped_hosts=skipped_hosts,
                prior_assessed=list(job.get("assessed_hosts") or []),
        )
        # Keep running skip list in sync when merge eliminates more unreachable hosts.
        skipped_hosts = list((merged.get("evidence") or {}).get("skipped_hosts") or skipped_hosts)
        # Job is only terminal once every chunk has a terminal poll result.
        all_terminal = len(done_details) == len(chunks) and not pending and not in_flight and not starting
        if not all_terminal:
            # Keep status running while waves remain, even if early chunks failed.
            if any(
                str((done_details.get(i) or poll_results.get(i) or {}).get("status") or "") == "failed"
                for i in range(len(chunks))
            ) and not in_flight and not pending and not starting:
                pass  # fall through with merged status
            else:
                merged["status"] = "running"
                merged["gmp_status"] = "running"
                (merged.get("evidence") or {}).update({"assessment_complete": False})

        status = merged["status"]
        progress = float(merged.get("progress") or 0)
        # Weight progress by chunk completion so pending waves don't look stuck at 0.
        if chunks:
            done_weight = sum(
                100.0 if i in done_details else float((poll_results.get(i) or {}).get("progress") or 0)
                for i in range(len(chunks))
            )
            progress = done_weight / len(chunks)
            merged["progress"] = progress

        now = time.monotonic()
        if progress != last_progress:
            last_progress = progress
            last_change = now

        # V1.9.7: one line every 5 min that shows the IP-level parallelism directly:
        # which IPs OpenVAS is scanning right now, for how long, and how many wait.
        if now - last_parallel_log >= 300 and (in_flight or pending or starting):
            last_parallel_log = now
            secs_now = _running_seconds(now)
            parts = []
            for i in sorted(in_flight):
                host_i = chunks[i][0] if chunks[i] else "?"
                pct_i = int(float((poll_results.get(i) or {}).get("progress") or 0))
                mins_i = secs_now.get(i, 0) // 60
                parts.append(f"{host_i} {'port scan' if pct_i <= 0 else f'{pct_i}%'} {mins_i}m")
            log.info(
                "Job %s parallel status: %d IP(s) scanning now [%s] | %d starting | %d waiting for a free slot "
                "(up to %d at once) | %d finished of %d",
                job_id, len(in_flight), ", ".join(parts) or "-", len(starting), len(pending),
                slot_sem.max_permits, len(done_details), len(chunks),
            )

        gmp_status = merged.get("gmp_status") or status
        target_progress = target_snapshot(chunks=chunks,
            in_flight=_scanning_ips(), done_details=done_details, poll_results=poll_results,
            skipped_hosts=skipped_hosts, assessed_hosts=list(job.get("assessed_hosts") or []),
            running_sec=_running_seconds(now), slots=slot_sem.max_permits)
        ip_rows = [{"ip": host, "status": state["status"], "progress": state["progress_pct"]}
                   for host, state in target_progress.items()]
        status_sig = tuple((row["ip"], row["status"], row["progress"]) for row in ip_rows)
        if status_sig != last_ip_status_sig:
            last_ip_status_sig = status_sig
            from agent.vuln_ports import port_document

            logging.getLogger("scanner_agent.ip").info(
                "IP_EVENT %s",
                json.dumps(
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "job_id": job_id,
                        "event": "scan_status",
                        "ports": port_document(),
                        "ips": ip_rows,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        unchanged_sec = max(0, int(now - last_change))
        message = (
            f"OpenVAS {gmp_status} ({len(in_flight)} in flight / "
            f"{len(done_details)}/{len(chunks)} IPs · semaphore={slot_sem.active}/{ip_workers})"
        )
        if capacity.get("admission_paused"):
            message += " · thermal admission pause"
        elif capacity.get("hot"):
            message += " · capacity floor=6"
        if status == "running" and progress >= 95 and unchanged_sec >= high_progress_warn_sec:
            message = (
                f"OpenVAS {gmp_status} at {progress:.0f}% - "
                f"waiting for Greenbone terminal status"
            )
            if now - last_high_progress_notice >= high_progress_warn_sec:
                log.info(
                    "Job %s still %s at %.0f%% for %ss; waiting for OpenVAS Done "
                    "(httpx PATCH lines are heartbeats, not progress)",
                    job_id,
                    gmp_status,
                    progress,
                    unchanged_sec,
                )
                last_high_progress_notice = now

        # The entire host progress snapshot can be large. Send at a bounded
        # interval, but always publish terminal status immediately. Local GMP
        # polling and IP-slot scheduling must not wait on repetitive PATCHes.
        if all_terminal or now - last_status_patch_at >= cfg.get("progress_report_interval", 45):
            last_status_patch_at = now
            if _patch_job_best_effort(
                api,
                job_id,
                {
                    "status": "running",
                    "progress_pct": progress,
                    "message": message,
                    "external_scan_id": external_blob,
                    "chunk_tasks": _chunk_tasks_blob(),
                    "target_progress": target_progress,
                },
            ) is None:
                log.error(
                    "Job %s is not on the central server for this scanner; stopping the local OpenVAS tasks",
                    job_id,
                )
                _abort_starts()
                for tid in _all_inflight_ids():
                    openvas.stop(tid)
                return

        if all_terminal:
            # Re-merge only finished chunks for upload.
            final_live = [(chunks[i], done_details[i]) for i in range(len(chunks))]
            merged = _merge_chunk_details(
                final_live, all_targets=selected_targets, skipped_hosts=skipped_hosts,
                prior_assessed=list(job.get("assessed_hosts") or []),
            )
            skipped_hosts = list((merged.get("evidence") or {}).get("skipped_hosts") or skipped_hosts)
            status = merged["status"]
            if status == "completed":
                evidence = merged.get("evidence") or {}
                complete = bool(evidence.get("assessment_complete"))
                missing = evidence.get("missing_ip_targets") or []
                if not complete and skipped_hosts and not missing:
                    complete = True
                    evidence["assessment_complete"] = True
                    merged["evidence"] = evidence
                payload = _result_payload(
                    details=merged,
                    task_id=external_blob,
                    status="completed",
                    partial=not complete,
                    partial_reason=(
                        None
                        if complete
                        else f"OpenVAS finished but assessed {int(evidence.get('hosts_assessed') or 0)} "
                        f"of {int(evidence.get('hosts_attempted') or len(targets))} target(s): "
                        f"{evidence.get('assessment_verdict') or 'missing host evidence'}"
                    ),
                    skipped_hosts=skipped_hosts,
                )
                _upload_results_reliably(api, job_id, payload)
                log.info(
                    "Job %s engine finished assessment_complete=%s service_checks_verified=%s "
                    "vulns=%d hosts_assessed=%d skipped=%d",
                    job_id,
                    complete,
                    bool((evidence.get("service_coverage") or {})) and all(
                        isinstance(item, dict) and item.get("coverage_complete") is True
                        for item in (evidence.get("service_coverage") or {}).values()
                    ),
                    len(merged.get("vulnerabilities") or []),
                    int(evidence.get("hosts_assessed") or 0),
                    len(skipped_hosts),
                )
                return

            vulns = merged.get("vulnerabilities") or []
            payload = _result_payload(
                details=merged,
                task_id=external_blob,
                status="failed",
                partial=bool(vulns) or status == "stopped",
                partial_reason=f"task {status} at {progress:.0f}%",
                error=f"OpenVAS ended with status {merged.get('gmp_status')}",
                skipped_hosts=skipped_hosts,
            )
            _upload_results_reliably(api, job_id, payload)
            return

        if max_job_runtime_sec > 0 and (now - run_started) >= max_job_runtime_sec:
            log.error(
                "Job %s exceeded MAX_JOB_RUNTIME_SEC=%ss; stopping in-flight IP task(s)",
                job_id,
                max_job_runtime_sec,
            )
            _abort_starts()
            for tid in _all_inflight_ids():
                openvas.stop(tid)
            time.sleep(3)
            for idx in list(in_flight):
                from agent.service_lanes import merge_service_lane_polls

                parts = [
                    openvas.poll(one, expected_targets=chunks[idx])
                    for one in _ids_for(idx)
                ]
                done_details[idx] = merge_service_lane_polls(parts) if parts else {
                    "status": "stopped",
                    "progress": 0,
                    "vulnerabilities": [],
                    "evidence": {},
                }
            in_flight.clear()
            pending.clear()
            final_live = [
                (chunks[i], done_details[i])
                for i in range(len(chunks))
                if i in done_details
            ]
            # Mark never-started chunks as stopped empty so merge stays coherent.
            for i in range(len(chunks)):
                if i not in done_details:
                    final_live.append(
                        (
                            chunks[i],
                            {
                                "status": "stopped",
                                "progress": 0,
                                "vulnerabilities": [],
                                "evidence": {},
                            },
                        )
                    )
            merged = _merge_chunk_details(
                final_live, all_targets=selected_targets, skipped_hosts=skipped_hosts,
                prior_assessed=list(job.get("assessed_hosts") or []),
            )
            # V1.9.0: the runtime cap often fires at 98% on a nearly-finished task
            # that OpenVAS left in "stopped" (a slow NVT at the tail, or the
            # scanner running low on memory). If real evidence was collected,
            # keep it as a PARTIAL / completed-with-warnings result instead of
            # hard-failing and discarding a usable scan. Only fail outright when
            # the cap fired with nothing usable (genuinely hung from the start).
            cap_evidence = dict(merged.get("evidence") or {})
            cap_vulns = merged.get("vulnerabilities") or []
            cap_progress = float(merged.get("progress") or 0)
            cap_open_ports = 0
            for _cov in (cap_evidence.get("host_coverage") or {}).values():
                if isinstance(_cov, dict):
                    cap_open_ports += len(_cov.get("open_tcp_ports") or []) + len(_cov.get("open_udp_ports") or [])
            has_usable_evidence = bool(cap_vulns) or cap_open_ports > 0 or int(cap_evidence.get("hosts_assessed") or 0) > 0
            cap_detail = (
                f"maximum job runtime {max_job_runtime_sec}s exceeded while "
                f"status={merged.get('gmp_status')} progress={cap_progress:.0f}%"
            )
            if has_usable_evidence:
                log.warning(
                    "Job %s hit the runtime cap at %.0f%% with usable evidence "
                    "(%d finding(s), %d open port(s)); keeping it as a partial result",
                    job_id, cap_progress, len(cap_vulns), cap_open_ports,
                )
                cap_evidence["completed_with_warnings"] = True
                cap_evidence["assessment_complete"] = False
                merged["evidence"] = cap_evidence
                payload = _result_payload(
                    details=merged,
                    task_id=external_blob,
                    status="completed",
                    partial=True,
                    partial_reason=cap_detail + "; partial coverage kept, not clean-eligible",
                    error=None,
                    skipped_hosts=list(cap_evidence.get("skipped_hosts") or skipped_hosts),
                )
            else:
                payload = _result_payload(
                    details=merged,
                    task_id=external_blob,
                    status="failed",
                    partial=True,
                    partial_reason=cap_detail,
                    error=f"OpenVAS exceeded maximum job runtime {max_job_runtime_sec}s " + cap_detail,
                    skipped_hosts=list(cap_evidence.get("skipped_hosts") or skipped_hosts),
                )
            _upload_results_reliably(api, job_id, payload)
            return


def main() -> None:
    cfg = _cfg()
    api: CentralApi = cfg["api"]
    openvas: LocalOpenVAS = cfg["openvas"]
    next_heartbeat = 0.0
    last_ready: bool | None = None
    configured_jobs = int(cfg["max_concurrent_jobs"])
    capacity = probe_laptop_capacity(force=True)
    max_workers = max(1, min(configured_jobs, int(capacity["max_concurrent_jobs"])))
    queue_poll = int(cfg["queue_poll"])
    log_shipper = install_log_shipper(api)
    cfg["log_shipper"] = log_shipper

    # Be defensive if a container was recreated from an older image between hotfixes.
    alive_test = getattr(openvas, "alive_test", None) or (os.environ.get("GVM_ALIVE_TEST") or "Consider Alive").strip()
    if not getattr(openvas, "alive_test", None):
        openvas.alive_test = alive_test

    log.info(
        "Scanner agent starting version=%s tenant=%s api=%s alive_test=%s agent_instance=%s",
        cfg["version"],
        os.environ.get("TENANT_SLUG"),
        os.environ.get("CENTRAL_API_URL"),
        alive_test,
        getattr(api, "agent_instance_id", ""),
    )
    log.info(
        "Progress policy: GMP task status is authoritative; no progress-based kill; "
        "high-progress warning=%ss per-IP limit=%s job limit=%s",
        cfg["high_progress_warn_sec"],
        cfg["max_scan_runtime_sec"] or os.environ.get("SCAN_IP_DEADLINE_SEC") or "off",
        cfg.get("max_job_runtime_sec") or "off",
    )
    # V45.4: unmistakable build + effective scan profile, then a hard self-check.
    # A truncating profile (port scanner killed before it finishes) produces 3
    # info results per host with plugin_errors=1 and looks "completed". Never run
    # that silently: refuse to claim jobs until the config is fixed.
    try:
        from agent import AGENT_BUILD
    except Exception:
        AGENT_BUILD = "unknown"
    degraded_retry = int(os.environ.get("SCAN_DEGRADED_RETRY") or 0)
    log.info(
        "AGENT BUILD %s | port_profile=%s udp_profile=%s plugins_timeout=%ss scanner_plugins_timeout=%ss "
        "optimize_test=%s max_checks=%s coverage_guard=on degraded_retry=%d",
        AGENT_BUILD,
        getattr(openvas, "port_profile", "?"),
        getattr(openvas, "udp_profile", "?"),
        getattr(openvas, "plugins_timeout", "?"),
        getattr(openvas, "scanner_plugins_timeout", "?"),
        getattr(openvas, "optimize_test", "?"),
        getattr(openvas, "max_checks", "?"),
        degraded_retry,
    )
    # V1.9.3: start reading the feed for checks with long own timeouts now, in
    # the background, so the first scan after a restart already gets the caps.
    try:
        from agent.nvt_timeouts import timeout_index
        from agent.scan_performance import nvt_max_sec

        if nvt_max_sec() > 0:
            timeout_index().get()
            log.info("NVT timeout index (SCAN_NVT_MAX_SEC=%ss): %s", nvt_max_sec(), timeout_index().status())
        else:
            log.info("NVT timeout index off (SCAN_NVT_MAX_SEC=0): checks keep their own timeouts")
    except Exception:
        log.warning("NVT timeout index could not start; static/learned caps still apply", exc_info=True)
    # V1.9.5: say at startup if OpenVAS logging is set up wrongly (DEBUG level, no
    # per-check lines), instead of first noticing it when a host waits at 98%.
    def _check_openvas_logging() -> None:
        try:
            from agent import openvas_log

            for warning in openvas_log.setup_warnings(openvas_log.log_health()):
                log.warning("OPENVAS_LOG_SETUP %s", warning)
        except Exception:
            log.debug("OpenVAS log setup check skipped", exc_info=True)

    threading.Thread(target=_check_openvas_logging, name="aetheris-openvas-log-check", daemon=True).start()
    allow_degraded = (os.environ.get("ALLOW_DEGRADED_SCAN") or "false").strip().lower() in {"1", "true", "yes", "on"}
    spt = int(getattr(openvas, "scanner_plugins_timeout", 0) or 0)
    pt = int(getattr(openvas, "plugins_timeout", 0) or 0)
    nexus_scope = str(getattr(openvas, "port_profile", "") or "") in {"nexus", "nessus", "vuln"}
    min_scanner_timeout = 120 if nexus_scope else 1800
    min_plugin_timeout = 60 if nexus_scope else 120
    while (spt < min_scanner_timeout or pt < min_plugin_timeout) and not allow_degraded:
        log.error(
            "DEGRADED SCAN CONFIG - scanner_plugins_timeout=%ss plugins_timeout=%ss is too short "
            "for this port scope. Not claiming jobs. Override: ALLOW_DEGRADED_SCAN=true",
            spt, pt,
        )
        time.sleep(60)
    log.info(
        "Capacity policy: jobs=%d (configured=%d) ip_workers=%d chunk_size=%d "
        "thermal=%s cpu_temp=%sC load_ratio=%.2f SCAN_IP_PARALLELISM=%s; queue-poll=%ss; "
        "throughput_target=%.1f-%.1f/h projected=%.1f/h expected_host=%.1fmin required_workers=%d",
        max_workers,
        configured_jobs,
        capacity["ip_workers"],
        capacity["chunk_size"],
        capacity.get("thermal_state"),
        capacity.get("cpu_temp_c") if capacity.get("cpu_temp_c") is not None else "?",
        float(capacity.get("load_ratio") or 0.0),
        os.environ.get("SCAN_IP_PARALLELISM") or "auto",
        queue_poll,
        float(capacity.get("throughput_min_hph") or 0.0),
        float(capacity.get("throughput_target_hph") or 0.0),
        float(capacity.get("projected_hosts_per_hour") or 0.0),
        float(capacity.get("expected_host_minutes") or 0.0),
        int(capacity.get("required_workers_for_slo") or 0),
    )
    if capacity.get("slo_at_risk"):
        log.warning(
            "Configured host concurrency projects %.1f IP/hour, below minimum SLO %.1f IP/hour; "
            "increase scanner CPU/RAM or reduce average host scan duration",
            float(capacity.get("projected_hosts_per_hour") or 0.0),
            float(capacity.get("throughput_min_hph") or 0.0),
        )

    # Future -> central job id. The active ids are sent with every claim so the
    # central API can resume orphaned running work without handing the same job
    # to two local threads. Network keys stay with the job so a second site's
    # RFC1918 range cannot start while another network is already scanning.
    active: dict[Future[None], str] = {}
    active_networks: dict[str, frozenset[str]] = {}

    with ThreadPoolExecutor(
        max_workers=max(configured_jobs, max_workers),
        thread_name_prefix="aetheris-scan",
    ) as pool:
        while True:
            now = time.monotonic()
            try:
                fresh = _read_agent_token()
                setter = getattr(api, "set_token", None)
                current = getattr(api, "_token", None) or ""
                if callable(setter) and fresh and fresh != current:
                    setter(fresh)
                    log.warning("Reloaded AGENT_TOKEN from token file")
                # Reap completed workers first so capacity is available to the
                # dispatcher immediately. Unexpected worker exceptions are left
                # recoverable: if an external_scan_id was already stored, the
                # central resume path will offer that same task again.
                for future, job_id in list(active.items()):
                    if not future.done():
                        continue
                    active.pop(future, None)
                    active_networks.pop(job_id, None)
                    try:
                        future.result()
                        log.info(
                            "Worker released slot for job %s (%d active)",
                            job_id,
                            len(active),
                        )
                    except Exception:
                        log.exception(
                            "Unhandled worker error for job %s; slot released and central resume logic may recover it",
                            job_id,
                        )

                capacity = probe_laptop_capacity()
                max_workers = max(1, min(configured_jobs, int(capacity["max_concurrent_jobs"])))
                try:
                    log_shipper.maybe_flush_async()
                except Exception:
                    pass

                ready = openvas.ready()
                readiness_detail = getattr(openvas, "last_readiness_detail", None)
                if now >= next_heartbeat or ready != last_ready:
                    try:
                        api.heartbeat(
                            version=cfg["version"],
                            openvas_ready=ready,
                            detail=readiness_detail,
                        )
                        last_ready = ready
                    except Exception as exc:
                        # Do not stall/crash the dispatcher on a slow central hop.
                        # Active OpenVAS workers keep running; claim attempts continue.
                        log.warning(
                            "Central heartbeat timed out or failed (%s); will retry — active=%d",
                            exc.__class__.__name__,
                            len(active),
                        )
                    next_heartbeat = now + cfg["heartbeat"]

                if not ready:
                    # Existing workers keep running; readiness only gates NEW
                    # claims. gvmd often takes minutes after compose-up before
                    # /run/gvmd/gvmd.sock accepts GMP (feed load). Retry quietly.
                    time.sleep(queue_poll)
                    continue

                if capacity.get("hot") and active:
                    # Do not claim a second job while the chassis is hot and a
                    # scan is already burning CPU/OpenVAS.
                    log.info(
                        "Capacity %s — holding new claims (active=%d ip_workers=%s temp=%sC load_ratio=%.2f)",
                        capacity.get("thermal_state") or "hot",
                        len(active),
                        capacity.get("ip_workers"),
                        capacity.get("cpu_temp_c") if capacity.get("cpu_temp_c") is not None else "?",
                        float(capacity.get("load_ratio") or 0.0),
                    )
                    time.sleep(queue_poll)
                    continue

                active_ids = list(active.values())
                slots = max_workers - len(active)
                # Fill every available worker slot in one pass. No queue item is
                # made to wait behind an unrelated active job when capacity is
                # available. The central claim itself is atomic/SKIP LOCKED.
                while slots > 0:
                    job = api.next_job(active_job_ids=active_ids)
                    if not job:
                        break

                    job_id = str(job.get("id") or "").strip()
                    if not job_id:
                        log.error(
                            "Central returned a scan job without an id; refusing claim payload=%r",
                            job,
                        )
                        break
                    if job_id in active_ids:
                        # Defensive compatibility guard for a stale/older central
                        # API that ignores active_job_ids. Do not start duplicate
                        # OpenVAS tasks from the same database job.
                        log.warning(
                            "Central returned already-active job %s; not starting a duplicate worker",
                            job_id,
                        )
                        break

                    job_targets = [
                        str(t.get("target") or "").strip()
                        for t in (job.get("targets") or [])
                        if str(t.get("target") or "").strip()
                    ]
                    incoming_key = network_key(job_targets)
                    active_keys = {active_networks[jid] for jid in active_ids if jid in active_networks}
                    if active_keys and incoming_key not in active_keys:
                        log.error(
                            "Refusing job %s — its network %s is not the in-flight network %s",
                            job_id,
                            ",".join(sorted(incoming_key)[:4]) or "(empty)",
                            ",".join(sorted(next(iter(active_keys)))[:4]),
                        )
                        break

                    future = pool.submit(_run_job, cfg, job)
                    active[future] = job_id
                    active_networks[job_id] = incoming_key
                    active_ids.append(job_id)
                    slots -= 1
                    log.info(
                        "Dispatched job %s (%d/%d active)",
                        job_id,
                        len(active),
                        max_workers,
                    )

                time.sleep(queue_poll)
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 401:
                    fresh = _read_agent_token()
                    setter = getattr(api, "set_token", None)
                    current = getattr(api, "_token", None) or (api.headers.get("Authorization") or "").replace("Bearer ", "", 1).strip()
                    if callable(setter) and fresh and fresh != current:
                        setter(fresh)
                        log.warning("Reloaded AGENT_TOKEN after 401")
                        continue
                    log.error(
                        "Central rejected AGENT_TOKEN (HTTP 401). Re-run Start-Laptop.cmd to auto-match it."
                    )
                    time.sleep(queue_poll)
                    continue
                retryable = False
                try:
                    retryable = bool(api.is_retryable(exc))
                except Exception:
                    retryable = False
                if retryable or status in {408, 425, 429, 500, 502, 503, 504}:
                    log.warning(
                        "Central request failed (%s); will retry — active=%d",
                        status or exc.__class__.__name__,
                        len(active),
                    )
                    time.sleep(queue_poll)
                    continue
                log.exception("Dispatcher loop error")
                time.sleep(queue_poll)


if __name__ == "__main__":
    main()
