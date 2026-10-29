"""Drop files that are byte-identical to a known-good reference set (NSRL RDS) after hashing.

Extraction computes each file's SHA-256 while reading it. A file whose hash is
in the known-good index (operating-system and software files published by NIST
NSRL) is removed from the extraction index, so parsing, OCR, search, RAG and
the report never see it. It is still listed - path, size, hash - in
``known_good.jsonl.zst`` next to the manifest, and counted under
``known_good_hash`` in the filter statistics, so the exclusion is defensible.

Hash matching needs the whole file to be read, so for evidence on the
examiner's PC it reduces noise in the results, not upload.

The index is optional. Default location ``/app/data/known-good/nsrl-sha256.hgi``
(override with ``FORENSIC_KNOWN_GOOD_INDEX``); build it with
``python -m app.services.known_good_cli build``. A missing or unreadable index,
or one built for another hash algorithm, disables the filter - it never fails
an extraction.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_INDEX = "/app/data/known-good/nsrl-sha256.hgi"
EXTRACT_HASH_ALGORITHM = "sha256"   # what the shard workers compute while reading

_lock = threading.Lock()
_cached: tuple[str, float, Any] | None = None


def index_path() -> Path:
    return Path(os.environ.get("FORENSIC_KNOWN_GOOD_INDEX") or DEFAULT_INDEX)


def load_index():
    """The known-good index for this process, or None (filter off). Reloaded when the file changes."""
    global _cached
    if os.environ.get("FORENSIC_KNOWN_GOOD_ENABLED", "true").strip().lower() in {"0", "false", "no", "off"}:
        return None
    path = index_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    with _lock:
        if _cached and _cached[0] == str(path) and _cached[1] == mtime:
            return _cached[2]
        try:
            from app.services.extract_known_good import KnownGoodIndex

            index = KnownGoodIndex(path)
        except Exception as exc:
            log.warning("known-good index %s unusable: %s", path, exc)
            _cached = (str(path), mtime, None)
            return None
        if index.algorithm.lower().replace("-", "") != EXTRACT_HASH_ALGORITHM:
            log.warning("known-good index %s uses %s; extraction hashes with %s - filter off",
                        path, index.algorithm, EXTRACT_HASH_ALGORITHM)
            index = None
        _cached = (str(path), mtime, index)
        return index


def split_known_good(entries: list[dict], index=None) -> tuple[list[dict], list[dict]]:
    """``(kept, known_good)`` for extraction index entries carrying a ``sha256``."""
    index = index if index is not None else load_index()
    if index is None or not entries:
        return list(entries or []), []
    kept: list[dict] = []
    known: list[dict] = []
    for entry in entries:
        digest = str(entry.get("sha256") or "")
        if len(digest) == 64 and index.contains(digest):
            known.append({"path": entry.get("path"), "size_bytes": entry.get("size_bytes"), "sha256": digest})
        else:
            kept.append(entry)
    return kept, known


def status() -> dict[str, Any]:
    index = load_index()
    if index is None:
        return {"active": False, "path": str(index_path())}
    return {"active": True, "path": str(index_path()), "hashes": len(index), "algorithm": index.algorithm}
