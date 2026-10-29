"""Build or inspect the known-good (NSRL) hash index used during extraction.

    # 1. Download the NSRL RDS (modern, SQLite) from NIST and unpack it into the
    #    known-good folder of the job data directory, e.g.
    #    <AETHERIS_BACKUP_DIR>/forensic-data/job-data/known-good/RDS_2024.12.1_modern_minimal.db
    # 2. Build the index inside the disk worker (same folder is /app/data/known-good):
    python -m app.services.known_good_cli build /app/data/known-good/RDS_2024.12.1_modern_minimal.db
    # 3. Check it:
    python -m app.services.known_good_cli status

The index is a sorted binary file searched by memory map: exact (no false
positives that could discard evidence) and close to zero resident memory.
New extractions pick it up automatically; nothing needs a restart.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    from app.services.known_good_filter import EXTRACT_HASH_ALGORITHM, index_path, status

    parser = argparse.ArgumentParser(prog="known_good_cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    build = sub.add_parser("build", help="build the index from an NSRL RDS file (SQLite, CSV or a list of hashes)")
    build.add_argument("source", type=Path)
    build.add_argument("--out", type=Path, default=None, help=f"default: {index_path()}")
    sub.add_parser("status", help="show whether extraction will use the index")
    args = parser.parse_args(argv)

    if args.cmd == "status":
        print(json.dumps(status(), indent=2))
        return 0

    from app.services.extract_known_good import build_index

    out = args.out or index_path()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".building")
    summary = build_index(args.source, tmp, algorithm=EXTRACT_HASH_ALGORITHM)
    tmp.replace(out)  # atomic: running extractions never see a half-written index
    print(json.dumps({"index": str(out), "summary": getattr(summary, "as_dict", lambda: str(summary))()}, indent=2,
                     default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
