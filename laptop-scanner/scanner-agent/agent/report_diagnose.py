"""Read one existing Greenbone report and print what it really contains.

Usage inside the scanner-agent container:

    python -m agent.report_diagnose 034bf5f5-ff36-4f9f-ac7f-3935036b3b99
    python -m agent.report_diagnose <report_id> --host 192.168.0.163 --json

Read-only: it never creates, stops or modifies tasks, and never uploads.
It prints every native result (port, severity, CVSS, NVT, title), every
scanner error row (which NVTs timed out), host port details, and the
V1.6.5 coverage verdict and service attribution for the same report.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable

from agent.gmp_local import (
    _coverage_includes_parsed_results,
    _harvest_report_bundle,
    _inner_report,
    _report_evidence_from_xml,
    _session,
    LocalOpenVAS,
)
from agent.service_policy import analyze_services


def diagnose_report(
    gmp: Any,
    report_id: str,
    host: str | None = None,
    port_range_lookup: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    meta, vulns, last_exc, detail = _harvest_report_bundle(gmp, report_id)
    if meta is None:
        return {"report_id": report_id, "error": str(last_exc or "report not readable")}
    source = detail if detail is not None else meta
    inner = _inner_report(source)
    hosts = sorted({str(x).strip() for x in inner.xpath(".//host/ip/text()") if str(x).strip()}
                   | {str(v.get("host") or "").strip() for v in vulns if v.get("host")})
    targets = [host] if host else hosts
    evidence = _report_evidence_from_xml(
        meta, report_id=report_id, task_status="done", progress=100.0,
        expected_targets=targets, alive_test="n/a", detail_response=detail,
    )
    _coverage_includes_parsed_results(evidence, vulns)
    task = inner.find("task") if hasattr(inner, "find") else None
    task_id = (task.get("id") if task is not None else None) or ""
    scanned = ""
    if task_id and port_range_lookup is not None:
        try:
            scanned = port_range_lookup(task_id) or ""
        except Exception:
            scanned = ""
    host_details: dict[str, dict[str, str]] = {}
    for node in inner.xpath(".//host"):
        ip = (node.findtext("ip") or "").strip()
        if not ip:
            continue
        for d in node.findall("detail"):
            name = (d.findtext("name") or "").strip()
            if name.lower() in {"ports", "tcp_ports", "udp_ports", "best_os_txt", "best_os_cpe", "hostname"}:
                host_details.setdefault(ip, {})[name] = (d.findtext("value") or "").strip()[:500]
    return {
        "report_id": report_id,
        "task_id": task_id or None,
        "scanned_port_range": scanned or None,
        "hosts": targets,
        "detail_page_available": detail is not None,
        "results": [
            {"host": v.get("host"), "port": f"{v.get('port')}/{v.get('protocol')}" if v.get("port") else "general",
             "severity": v.get("severity"), "cvss": v.get("cvss"), "nvt_oid": v.get("nvt_oid"),
             "title": v.get("plugin_name")}
            for v in sorted(vulns, key=lambda r: (-float(r.get("cvss") or 0), str(r.get("plugin_name"))))
        ],
        "errors": evidence.get("plugin_error_details") or [],
        "plugin_error_count": evidence.get("plugin_error_count"),
        "host_details": host_details,
        "coverage": evidence.get("host_coverage") or {},
        "services": {
            h: analyze_services(vulns, host=h, coverage=(evidence.get("host_coverage") or {}).get(h),
                                scanned_port_range=scanned or None)
            for h in targets
        },
    }


def _print_text(out: dict[str, Any]) -> None:
    print(f"Report {out['report_id']}  task {out.get('task_id') or '?'}  "
          f"detail page: {'yes' if out.get('detail_page_available') else 'NO'}")
    rng = out.get("scanned_port_range") or ""
    print(f"Scanned port range: {rng[:300] + ('...' if len(rng) > 300 else '') if rng else 'unknown'}")
    if out.get("error"):
        print("ERROR:", out["error"])
        return
    print(f"\nResults ({len(out['results'])}):")
    for r in out["results"]:
        print(f"  {str(r['severity']).upper():8} {float(r['cvss'] or 0):4.1f}  {r['port']:14} {r['nvt_oid']}  {r['title']}")
    print(f"\nScanner errors ({out.get('plugin_error_count')}):")
    for e in out["errors"] or [{"nvt_name": "(none listed)"}]:
        print(f"  {e.get('port') or '':10} {e.get('nvt_oid') or '':38} {e.get('nvt_name') or ''}: "
              f"{str(e.get('description') or '').strip()[:140]}")
    for h, d in out["host_details"].items():
        print(f"\nHost details {h}: " + "; ".join(f"{k}={v}" for k, v in d.items()))
    for h, cov in out["coverage"].items():
        print(f"\nV1.6.5 verdict {h}: {cov.get('verdict')}  network_scan_complete={cov.get('network_scan_complete')}")
        print(f"  {cov.get('reason')}")
        for w in cov.get("warnings") or []:
            print(f"  warning: {w}")
        svc = out["services"].get(h) or {}
        print(f"  service states: {svc.get('counts')}")
        for s in svc.get("services") or []:
            if s["status"] in {"finding", "observation"} or s.get("port_hints"):
                print(f"    {s['service_id']} {s['name']}: {s['status']} {s['source_result_ids']}")
        for key in ("host_level", "other_ports"):
            b = svc.get(key) or {}
            if b.get("source_result_ids"):
                print(f"    {b['service_id']} {b['name']}: {b['status']} {b['severity_counts']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report_id")
    ap.add_argument("--host")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    scanner = LocalOpenVAS()
    with _session(**scanner._session_kwargs()) as gmp:
        out = diagnose_report(gmp, args.report_id, args.host, port_range_lookup=scanner.task_port_range)
    if args.json:
        json.dump(out, sys.stdout, indent=2, default=str)
        print()
    else:
        _print_text(out)
    return 0 if not out.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
