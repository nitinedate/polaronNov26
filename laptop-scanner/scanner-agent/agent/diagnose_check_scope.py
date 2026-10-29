"""Read-only diagnostic: which checks do the Aetheris scan configs really run? (V1.9.1)

Run on the laptop:

    docker compose exec -T scanner-agent python -m agent.diagnose_check_scope
    docker compose exec -T scanner-agent python -m agent.diagnose_check_scope --json

It changes nothing in Greenbone. It reports:

* gvmd's "Max Rows Per Page" (the cap that truncated the V1.6.8 scope configs);
* every Aetheris scan config with its partial families (selected/available);
* whether known Windows/TCP findings (DCE/RPC reporting 10736, TCP/ICMP
  timestamps) are in each config, and which config recent tasks used;
* whether the stock "Full and fast" config and the Feed Import Owner exist;
* the LAN fingerprint the self-scan depends on;
* (V1.9.2) whether openvas.log is at DEBUG level and logs check launches.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from agent.gmp_local import (
    FULL_AND_FAST_ID,
    _config_family_stats,
    _nvt_feed_version,
    _nvt_info_type,
    _partial_families,
    _unselected_families,
)

MAX_ROWS_SETTING = "76374a7a-0569-11e6-b6da-28d24461215b"
FEED_IMPORT_OWNER_SETTING = "78eceaec-3385-11ea-b237-28d24461215b"
SENTINELS = {
    "1.3.6.1.4.1.25623.1.0.10736": "DCE/RPC and MSRPC Services Enumeration Reporting (Medium 5.0)",
    "1.3.6.1.4.1.25623.1.0.80091": "TCP Timestamps Information Disclosure (Low 2.6)",
    "1.3.6.1.4.1.25623.1.0.103190": "ICMP Timestamp Reply Information Disclosure (Low 2.1)",
}
# A V1.6.8 family selection cut by gvmd: 1000 rows, plus up to six essential OIDs.
_CAP_SIGNATURE = range(1000, 1007)


def _setting(gmp: Any, setting_id: str) -> str | None:
    try:
        resp = gmp.get_user_setting(setting_id)
        value = resp.findtext(".//setting/value")
        return None if value is None else value.strip()
    except Exception:
        return None


def _sentinel_families(gmp: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for oid in SENTINELS:
        try:
            fam = (gmp.get_info(oid, _nvt_info_type()).findtext(".//nvt/family") or "").strip()
            if fam:
                out[oid] = fam
        except Exception:
            continue
    return out


def _config_has(gmp: Any, config_id: str, family: str, oid: str) -> bool | None:
    try:
        resp = gmp.get_scan_config_nvts(details=False, config_id=config_id, family=family)
        return bool(resp.xpath(f'.//nvt[@oid="{oid}"]'))
    except Exception:
        return None


def _configs(gmp: Any) -> list[dict[str, Any]]:
    resp = gmp.get_scan_configs(filter_string="rows=200")
    out = []
    for node in resp.xpath("config"):
        name = (node.findtext("name") or "").strip()
        cid = str(node.get("id") or "").strip()
        if cid and (name.startswith("Aetheris") or cid == FULL_AND_FAST_ID or name == "Full and fast"):
            out.append({"id": cid, "name": name,
                        "in_use": (node.findtext("in_use") or "0").strip() not in {"0", ""}})
    return out


def _recent_tasks(gmp: Any, limit: int) -> list[dict[str, str]]:
    try:
        resp = gmp.get_tasks(filter_string=f"rows={limit} sort-reverse=created")
    except Exception:
        return []
    out = []
    for task in resp.xpath("task"):
        cfg = task.find("config")
        out.append({"task_id": str(task.get("id") or ""), "name": (task.findtext("name") or "").strip(),
                    "status": (task.findtext("status") or "").strip(),
                    "config_id": str(cfg.get("id") or "") if cfg is not None else "",
                    "config_name": (cfg.findtext("name") or "").strip() if cfg is not None else ""})
    return out


def _fingerprint() -> dict[str, Any]:
    try:
        from agent.lan_fingerprint import FINGERPRINT_PATHS
    except Exception:
        return {"available": False}
    for path in FINGERPRINT_PATHS:
        p = Path(path)
        if not p.is_file():
            continue
        try:
            raw = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            return {"available": True, "path": str(p), "error": f"unreadable: {exc}"}
        age = int(time.time() - p.stat().st_mtime)
        return {"available": True, "path": str(p), "age_sec": age, "keys": sorted(raw),
                "host_ips": raw.get("host_ips"), "writer_version": raw.get("writer_version"),
                "legacy_writer": "host_ips" not in raw}
    return {"available": False}


def diagnose(gmp: Any, *, check_sentinels: bool = True, task_limit: int = 8) -> dict[str, Any]:
    out: dict[str, Any] = {"max_rows_per_page": _setting(gmp, MAX_ROWS_SETTING),
                           "feed_import_owner": _setting(gmp, FEED_IMPORT_OWNER_SETTING),
                           "nvt_feed_version": _nvt_feed_version(gmp), "configs": [], "verdicts": []}
    sentinel_fams = _sentinel_families(gmp) if check_sentinels else {}
    out["sentinels_in_feed"] = {oid: sentinel_fams.get(oid) for oid in SENTINELS}
    configs = _configs(gmp)
    out["stock_full_and_fast_present"] = any(c["id"] == FULL_AND_FAST_ID or c["name"] == "Full and fast"
                                             for c in configs)
    for cfg in configs:
        try:
            stats, total = _config_family_stats(gmp, cfg["id"])
        except Exception as exc:
            cfg["error"] = str(exc)[:200]
            out["configs"].append(cfg)
            continue
        partial = _partial_families(stats)
        cfg["nvt_count"] = total
        cfg["partial_families"] = partial
        cfg["families_unselected"] = _unselected_families(stats)
        cfg["capped_families"] = sorted(f for f, v in partial.items() if int(v.split("/")[0]) in _CAP_SIGNATURE)
        cfg["sentinels"] = {oid: _config_has(gmp, cfg["id"], fam, oid) for oid, fam in sentinel_fams.items()}
        out["configs"].append(cfg)
    out["recent_tasks"] = _recent_tasks(gmp, task_limit)
    out["fingerprint"] = _fingerprint()
    try:
        from agent.openvas_log import log_health

        out["openvas_log"] = log_health()
    except Exception as exc:  # pragma: no cover - diagnostics must not fail
        out["openvas_log"] = {"available": False, "error": str(exc)[:200]}

    v = out["verdicts"]
    capped = [c for c in out["configs"] if c.get("capped_families")]
    if capped:
        v.append("TRUNCATED: " + "; ".join(f"{c['name']} ({', '.join(c['capped_families'])})" for c in capped)
                 + " - families cut at gvmd's 1000-row cap; these configs cannot report all findings")
    dce = "1.3.6.1.4.1.25623.1.0.10736"
    used = {t["config_id"] for t in out["recent_tasks"]}
    for c in out["configs"]:
        if c["id"] in used and c.get("sentinels", {}).get(dce) is False:
            v.append(f"MISSING CHECK: recent tasks used '{c['name']}', which does not contain {SENTINELS[dce]}")
    if not out["stock_full_and_fast_present"]:
        v.append("Stock 'Full and fast' config is missing: gvmd is not importing data objects "
                 "(set the Feed Import Owner: scripts/Repair-Greenbone-Feed-v1.4.1.ps1)")
    if not out["feed_import_owner"]:
        v.append("Feed Import Owner is not set (or not readable via GMP)")
    fp = out["fingerprint"]
    if fp.get("legacy_writer"):
        v.append("SELF-SCAN OFF: .lan-fingerprint has no host_ips key (a pre-1.8.0 writer loop is running); "
                 "run Start-Laptop.cmd again")
    elif fp.get("available") and isinstance(fp.get("age_sec"), int) and fp["age_sec"] > 300:
        v.append(f"SELF-SCAN OFF: .lan-fingerprint is {fp['age_sec']} s old (writer loop not running)")
    lg = out["openvas_log"]
    if lg.get("available"):
        if float(lg.get("debug_share") or 0) >= 0.5:
            v.append(f"OPENVAS DEBUG LOGGING: {int(float(lg['debug_share']) * 100)}% of openvas.log lines are DEBUG "
                     f"({int(lg.get('bytes') or 0) // 1048576} MB); the agent cannot see running checks and DEBUG may "
                     "log passwords. Set OPENVAS_LOG_LEVEL=127, then: docker compose up -d configure-openvas")
        if lg.get("hosts_started") and not lg.get("whole_attack_logging"):
            v.append("OPENVAS PER-CHECK LOGGING OFF: hosts were scanned but no check launches are logged; "
                     "set OPENVAS_LOG_WHOLE_ATTACK=yes, then: docker compose up -d configure-openvas")
    if not v:
        v.append("OK: no truncated Aetheris configs, sentinel checks present, self-scan fingerprint usable")
    return out


def _print_text(out: dict[str, Any]) -> None:
    print("== Aetheris check-scope diagnostic (read-only) ==")
    print(f"gvmd Max Rows Per Page : {out['max_rows_per_page'] or 'unknown (default 1000)'}")
    print(f"Feed Import Owner      : {out['feed_import_owner'] or 'NOT SET / unknown'}")
    print(f"NVT feed version       : {out['nvt_feed_version']}")
    print(f"Stock 'Full and fast'  : {'present' if out['stock_full_and_fast_present'] else 'MISSING'}")
    print()
    for c in out["configs"]:
        print(f"- {c['name']}  [{c['id']}]{'  (in use)' if c.get('in_use') else ''}")
        if c.get("error"):
            print(f"    error: {c['error']}")
            continue
        print(f"    checks: {c.get('nvt_count')}")
        partial = c.get("partial_families") or {}
        if partial:
            shown = ", ".join(f"{k} {v}" for k, v in sorted(partial.items())[:12])
            print(f"    partial families: {shown}{' ...' if len(partial) > 12 else ''}")
        if c.get("capped_families"):
            print(f"    CUT AT 1000 ROWS: {', '.join(c['capped_families'])}")
        if c.get("families_unselected"):
            print(f"    not selected: {', '.join(c['families_unselected'])}")
        for oid, present in (c.get("sentinels") or {}).items():
            mark = {True: "yes", False: "NO", None: "?"}[present]
            print(f"    {mark:>3}  {SENTINELS[oid]}")
    print()
    print("Recent tasks:")
    for t in out["recent_tasks"]:
        print(f"  {t['name']:<22} {t['status']:<10} config={t['config_name']}")
    fp = out["fingerprint"]
    print()
    print(f"LAN fingerprint: {json.dumps(fp)}")
    print(f"OpenVAS log    : {json.dumps(out.get('openvas_log') or {})}")
    print()
    for line in out["verdicts"]:
        print(f">> {line}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-sentinels", action="store_true", help="skip the per-config NVT membership lookups")
    args = ap.parse_args(argv)
    from agent.gmp_local import LocalOpenVAS, _session

    scanner = LocalOpenVAS()
    with _session(**scanner._session_kwargs()) as gmp:
        out = diagnose(gmp, check_sentinels=not args.no_sentinels)
    if args.json:
        json.dump(out, sys.stdout, indent=2, default=str)
        print()
    else:
        _print_text(out)
    return 1 if any(v.startswith(("TRUNCATED", "MISSING CHECK")) for v in out["verdicts"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
