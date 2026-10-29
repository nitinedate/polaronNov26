"""Document text extraction and bounded universal binary fallback.

The goal is coverage, not speculative decoding. Structured formats use their
native parsers when available; otherwise binary evidence is still indexed with
magic/type metadata, entropy, hashes and bounded readable strings so an unknown
extension never becomes an unsearchable black box.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import PurePosixPath
from typing import Any

from app.parsers.communications import iter_binary_strings

_DOCUMENT_EXTS = {
    ".pdf", ".doc", ".docx", ".docm", ".dot", ".dotx", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".xltx", ".xltm",
    ".ppt", ".pptx", ".pptm", ".pps", ".ppsx", ".ppsm", ".pot", ".potx", ".potm",
    ".rtf", ".odt", ".ods", ".odp", ".epub", ".pages", ".numbers", ".key",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _magic_kind(data: bytes) -> tuple[str, str]:
    h = data[:16]
    if data.startswith(b"%PDF"):
        return "pdf", "document"
    if data.startswith(b"PK\x03\x04"):
        return "zip/ooxml", "container"
    if data.startswith(b"\x7fELF"):
        return "elf", "executable"
    if data.startswith(b"MZ"):
        return "pe/dos", "executable"
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite", "database"
    if data.startswith(b"regf"):
        return "registry_hive", "registry"
    if data.startswith(b"bplist00"):
        return "binary_plist", "structured"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z", "container"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar", "container"
    if data.startswith(b"\x1f\x8b"):
        return "gzip", "container"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")):
        return "mach-o", "executable"
    return (h.hex() if h else "empty"), "binary"


def parse_document_file(data: bytes, path: str) -> list[dict[str, Any]]:
    """Extract searchable text from common office/PDF containers.

    Legacy/OLE and vendor-specific formats fall through to the universal binary
    parser, which still indexes readable strings and type metadata.
    """
    ext = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    text = None
    try:
        from app.services.artifact_preview import _extract_document_preview_text
        text = _extract_document_preview_text(data, ext=ext, path=path)
    except Exception:
        text = None
    if text and text.strip():
        body = text.strip()
        return [{
            "record_type": "document_text",
            "path": path,
            "extension": ext,
            "size_bytes": len(data),
            "text": body,
            "preview": body[:1200],
            "sha256": hashlib.sha256(data).hexdigest(),
            "parser_scope": "native_document_text",
        }]
    return parse_universal_binary(data, path, declared_kind="document")


def parse_universal_binary(
    data: bytes,
    path: str,
    *,
    declared_kind: str | None = None,
    max_strings: int | None = None,
) -> list[dict[str, Any]]:
    """Bounded evidence-safe parser for unknown/binary files.

    It never guesses message semantics. It records type/magic/entropy and readable
    byte spans with offsets, which provides searchable coverage for binary blobs,
    proprietary app files and extensionless data while keeping DB growth bounded.
    """
    limit = max(1, int(max_strings or os.getenv("BINARY_STRING_MAX_RECORDS", "200")))
    scan_cap = max(64 * 1024, int(os.getenv("BINARY_STRING_SCAN_BYTES", str(8 * 1024 * 1024))))
    sample = data[:scan_cap]
    magic, kind = _magic_kind(sample)
    digest = hashlib.sha256(data).hexdigest()
    records: list[dict[str, Any]] = [{
        "record_type": "binary_metadata",
        "path": path,
        "size_bytes": len(data),
        "sha256": digest,
        "magic": magic,
        "kind": declared_kind or kind,
        "entropy": round(_entropy(sample[:256 * 1024]), 4),
        "scanned_bytes": len(sample),
        "text": f"Binary evidence {path} ({len(data)} bytes), type={magic}",
        "preview": f"binary evidence; type={magic}; sha256={digest}",
    }]
    count = 0
    seen: set[tuple[int, str]] = set()
    for item in iter_binary_strings(sample, path):
        key = (int(item.get("source_offset") or 0), str(item.get("text") or "")[:128])
        if key in seen:
            continue
        seen.add(key)
        item["record_type"] = "binary_string"
        item["binary_sha256"] = digest
        item["bounded_scan"] = len(data) > len(sample)
        records.append(item)
        count += 1
        if count >= limit:
            break
    records[0]["readable_string_records"] = count
    records[0]["bounded_scan"] = len(data) > len(sample)
    return records


def is_document_extension(path: str) -> bool:
    return PurePosixPath(path.replace("\\", "/")).suffix.lower() in _DOCUMENT_EXTS
