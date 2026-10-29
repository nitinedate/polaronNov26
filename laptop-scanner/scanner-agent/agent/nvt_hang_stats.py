"""Show (or reset) which NVTs keep timing out, and which are capped in fast mode.

    python -m agent.nvt_hang_stats            # table
    python -m agent.nvt_hang_stats --json
    python -m agent.nvt_hang_stats --reset 1.3.6.1.4.1.25623.1.0.XXXXX
    python -m agent.nvt_hang_stats --reset-all

Reading never changes Greenbone. Resetting only clears the local statistics;
the next fast-mode scan then builds a config without those caps.
"""
from __future__ import annotations

import argparse
import json
import sys

from agent.scan_performance import hang_registry, profile_settings, resolve_profile


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NVT timeout statistics")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--reset", metavar="OID")
    ap.add_argument("--reset-all", action="store_true")
    args = ap.parse_args(argv)
    reg = hang_registry()
    if args.reset or args.reset_all:
        removed = reg.reset(None if args.reset_all else args.reset)
        print(f"Removed {removed} NVT record(s) from {reg.path}")
        return 0
    rows = reg.summary()
    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return 0
    profile = resolve_profile(None)
    caps_on = profile_settings(profile)["hang_caps"]
    print(f"Statistics: {reg.path}   default profile: {profile}   timeout caps: {'on' if caps_on else 'off'}")
    if not rows:
        print("No NVT timeouts recorded yet.")
        return 0
    print(f"{'Timeouts':>8}  {'Capped':>7}  {'Last seen':19}  NVT")
    for r in rows:
        capped = f"{r['capped_at_sec']}s" if r["capped_at_sec"] else ("never" if r["never_capped"] else "-")
        print(f"{r['timeouts']:>8}  {capped:>7}  {r['last_seen'] or '':19}  {r['nvt_oid']}  {r['name'] or ''}")
        print(f"{'':39}hosts: {', '.join(r['hosts'][-5:])}   ports: {', '.join(r['ports'][-5:])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
