"""V1.10.3 one-off repair: re-check stored scanner jobs marked "coverage incomplete".

Jobs uploaded by agents up to 1.10.2 counted a timeout of "Nmap OS
Identification (NASL wrapper)" as a failed port scan (e.g. b6b7f60c and
ccf22aa0). The job list already re-checks these at read time; this script also
rewrites each job's stored per-IP rows so the Scan details panel shows the IP as
Completed. Genuine port-scanner failures are left unchanged.

Usage (inside the backend container):
    python scripts/repair_scanner_coverage_v1103.py            # dry run
    python scripts/repair_scanner_coverage_v1103.py --apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchall
from app.services.scanner_agent_jobs import classify_host_coverage
from app.services.scanner_coverage_rules import normalize_coverage_map


def _obj(raw):
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _schemas() -> list[str]:
    with firm_session("public") as db:
        rows = fetchall(db, """SELECT DISTINCT table_schema AS s FROM information_schema.tables
                                WHERE table_name='vuln_scan_jobs'""")
    return [str(r["s"]) for r in rows]


def repair(schema: str, *, apply: bool) -> list[str]:
    changed: list[str] = []
    with firm_session(schema) as db:
        rows = fetchall(db, """SELECT id, orchestration_json FROM vuln_scan_jobs
            WHERE status='completed' AND orchestration_json->>'edge_agent'='true'
              AND jsonb_array_length(COALESCE(orchestration_json->'degraded_hosts','[]'::jsonb)) > 0""")
        for row in rows:
            orch = _obj(row.get("orchestration_json"))
            host_cov = normalize_coverage_map(orch.get("host_coverage"))
            if not isinstance(host_cov, dict) or not host_cov:
                continue
            tp, degraded_now, network_complete = classify_host_coverage(host_cov, orch.get("target_progress"))
            if set(degraded_now) == {str(h) for h in (orch.get("degraded_hosts") or [])}:
                continue
            orch.update({"host_coverage": host_cov, "target_progress": tp, "degraded_hosts": degraded_now,
                         "network_complete_hosts": network_complete, "coverage_repaired": "v1.10.3"})
            if not degraded_now:
                orch.pop("partial", None)
                orch.pop("partial_reason", None)
                orch["edge_progress"] = {"pct": 100.0, "message": "Network scan complete"}
            changed.append(str(row["id"]))
            if apply:
                execute(db, """UPDATE vuln_scan_jobs SET orchestration_json=CAST(:o AS jsonb), updated_at=NOW()
                               WHERE id=CAST(:id AS uuid)""", {"o": json.dumps(orch, default=str), "id": str(row["id"])})
        if apply:
            db.commit()
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    parser.add_argument("--schema", help="one firm schema (default: every schema with vuln_scan_jobs)")
    args = parser.parse_args()
    for schema in ([args.schema] if args.schema else _schemas()):
        ids = repair(schema, apply=args.apply)
        print(f"{schema}: {len(ids)} job(s) {'repaired' if args.apply else 'would be repaired'}: {', '.join(ids)}")


if __name__ == "__main__":
    main()
