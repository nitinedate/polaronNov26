#!/usr/bin/env python3
"""Read-only source + scratch throughput preflight for the V53 60GB/35min target.

Usage inside backend container or host Python:
  python scripts/verify_60gb_sla_v53.py --source /host/e/case/image.E01 --scratch /scratch

The source probe only READS the source. The scratch probe creates and deletes a
bounded temporary file in the destination/scratch directory.
"""
from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path

TARGET_GB = 60.0
TARGET_MIN = 35.0
TARGET_MIB_S = TARGET_GB * 1024.0 / (TARGET_MIN * 60.0)


def read_probe(path: Path, mib: int) -> float:
    amount = mib * 1024 * 1024
    done = 0
    t0 = time.perf_counter()
    with path.open('rb', buffering=8 * 1024 * 1024) as fh:
        while done < amount:
            chunk = fh.read(min(8 * 1024 * 1024, amount - done))
            if not chunk:
                break
            done += len(chunk)
    return (done / 1024 / 1024) / max(time.perf_counter() - t0, 1e-6)


def write_probe(directory: Path, mib: int) -> float:
    directory.mkdir(parents=True, exist_ok=True)
    block = b'\0' * (8 * 1024 * 1024)
    remain = mib * 1024 * 1024
    fd, name = tempfile.mkstemp(prefix='aetheris-v53-', suffix='.probe', dir=directory)
    os.close(fd)
    path = Path(name)
    t0 = time.perf_counter()
    try:
        with path.open('wb', buffering=8 * 1024 * 1024) as fh:
            while remain > 0:
                n = min(len(block), remain)
                fh.write(block[:n])
                remain -= n
            fh.flush()
            os.fsync(fh.fileno())
        written = mib
        return written / max(time.perf_counter() - t0, 1e-6)
    finally:
        path.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--scratch', required=True, type=Path)
    ap.add_argument('--read-mib', type=int, default=1024)
    ap.add_argument('--write-mib', type=int, default=512)
    args = ap.parse_args()

    if not args.source.is_file():
        raise SystemExit(f'source not found: {args.source}')
    r = read_probe(args.source, max(args.read_mib, 64))
    w = write_probe(args.scratch, max(args.write_mib, 64))
    print(f'Target effective throughput: {TARGET_MIB_S:.1f} MiB/s for 60GB in 35min')
    print(f'Source sequential read:     {r:.1f} MiB/s')
    print(f'Scratch sequential write:   {w:.1f} MiB/s')
    # Extraction has TAR/Zstd/MinIO overhead; require a conservative 1.5x raw margin.
    raw_floor = TARGET_MIB_S * 1.5
    ok = r >= raw_floor and w >= raw_floor
    print(f'Recommended raw floor:      {raw_floor:.1f} MiB/s')
    print('Preflight: PASS' if ok else 'Preflight: BELOW TARGET - hardware/storage path may prevent 35min SLA')
    return 0 if ok else 2


if __name__ == '__main__':
    raise SystemExit(main())
