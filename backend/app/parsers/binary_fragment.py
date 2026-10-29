"""Examiner view of binary fragments: strings, indicators and a hex dump.

Used for signature-carved hits that are not decodable objects (pagefile.sys /
hiberfil.sys / unallocated), and for opaque binaries that have no structured
parser.  Never decodes binary as a text body: it extracts printable ASCII and
UTF-16LE runs *with their byte offsets* (the same output an examiner gets from
``strings -t d`` / ``strings -el``), plus a bounded hex dump, so every value is
traceable to a source offset.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
_URL_RE = re.compile(r"https?://[A-Za-z0-9][\w\-.:@/%?#=&+~!,;]{4,400}")
_WINPATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,120}\\){0,24}[^\\/:*?\"<>|\r\n]{1,120}")
_JSON_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{2,40})"\s*:')

DEFAULT_SCAN_BYTES = 2 * 1024 * 1024
DEFAULT_HEX_BYTES = 2048


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(
    data: bytes,
    *,
    min_len: int = 6,
    max_strings: int = 3000,
    base_offset: int = 0,
    scan_bytes: int = DEFAULT_SCAN_BYTES,
) -> list[dict[str, Any]]:
    """Printable ASCII and UTF-16LE runs, sorted by absolute offset."""
    buf = data[:scan_bytes] if scan_bytes else data
    min_len = max(int(min_len), 3)
    out: list[dict[str, Any]] = []
    ascii_re = re.compile(_ASCII_RUN.pattern % min_len)
    utf16_re = re.compile(_UTF16_RUN.pattern % min_len)
    for m in ascii_re.finditer(buf):
        out.append({
            "offset": base_offset + m.start(),
            "encoding": "ascii",
            "text": m.group(0).decode("ascii", errors="replace")[:1000],
        })
        if len(out) >= max_strings * 2:
            break
    for m in utf16_re.finditer(buf):
        out.append({
            "offset": base_offset + m.start(),
            "encoding": "utf-16le",
            "text": m.group(0).decode("utf-16-le", errors="replace")[:1000],
        })
        if len(out) >= max_strings * 3:
            break
    out.sort(key=lambda s: s["offset"])
    return out[:max_strings]


def hexdump(data: bytes, *, base_offset: int = 0, limit: int = DEFAULT_HEX_BYTES) -> str:
    """Canonical 16-byte hex + ASCII dump with absolute offsets."""
    view = data[:limit]
    width = max(8, len(f"{base_offset + len(view):x}"))
    lines = []
    for i in range(0, len(view), 16):
        row = view[i:i + 16]
        hexes = " ".join(f"{b:02x}" for b in row)
        if len(row) > 8:
            hexes = hexes[:23] + " " + hexes[23:]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{base_offset + i:0{width}x}  {hexes:<48}  |{text}|")
    return "\n".join(lines)


def fragment_indicators(strings: list[dict[str, Any]], *, limit: int = 60) -> dict[str, list[str]]:
    emails: dict[str, None] = {}
    urls: dict[str, None] = {}
    paths: dict[str, None] = {}
    keys: Counter[str] = Counter()
    for s in strings:
        text = s.get("text") or ""
        for m in _EMAIL_RE.finditer(text):
            emails.setdefault(m.group(0).strip(".").lower(), None)
        for m in _URL_RE.finditer(text):
            urls.setdefault(m.group(0).rstrip(".,;)\"'"), None)
        for m in _WINPATH_RE.finditer(text):
            paths.setdefault(m.group(0), None)
        for m in _JSON_KEY_RE.finditer(text):
            keys[m.group(1)] += 1
    return {
        "emails": list(emails)[:limit],
        "urls": list(urls)[:limit],
        "windows_paths": list(paths)[:limit],
        "json_keys": [k for k, _ in keys.most_common(limit)],
    }


def classify_fragment(data: bytes, strings: list[dict[str, Any]], indicators: dict[str, list[str]]) -> str:
    sample = data[:65536]
    ent = shannon_entropy(sample)
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / max(len(sample), 1)
    utf16 = sum(1 for s in strings if s["encoding"] == "utf-16le")
    if ent > 7.6 and printable < 0.45:
        return "High-entropy data (compressed or encrypted); no readable structure"
    if len(indicators.get("json_keys") or []) >= 5:
        return "Application state / JSON or JavaScript held in memory"
    if utf16 > len(strings) * 0.6 and utf16 >= 5:
        return "UTF-16LE (Windows) strings in memory / binary structure"
    if printable > 0.85:
        return "Mostly printable text fragment"
    return "Mixed binary structure with embedded strings"


def build_fragment_view(
    data: bytes,
    *,
    base_offset: int = 0,
    source: str = "",
    reason: str = "",
    min_len: int = 6,
    max_strings: int = 1500,
    hex_bytes: int = DEFAULT_HEX_BYTES,
) -> dict[str, Any]:
    """Structured fragment report (JSON-safe) plus a plain-text rendering."""
    strings = extract_strings(data, min_len=min_len, max_strings=max_strings, base_offset=base_offset)
    indicators = fragment_indicators(strings)
    sample = data[:65536]
    stats = {
        "size_bytes": len(data),
        "scanned_bytes": min(len(data), DEFAULT_SCAN_BYTES),
        "entropy": round(shannon_entropy(sample), 3),
        "printable_ratio": round(
            sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / max(len(sample), 1), 3
        ),
        "string_count": len(strings),
        "utf16_string_count": sum(1 for s in strings if s["encoding"] == "utf-16le"),
    }
    classification = classify_fragment(data, strings, indicators)
    hex_text = hexdump(data, base_offset=base_offset, limit=hex_bytes)

    lines = [
        f"Binary fragment — {classification}",
        f"Source: {source}" if source else "",
        f"Start offset: {base_offset:,} (0x{base_offset:x})  ·  {len(data):,} bytes  ·  "
        f"entropy {stats['entropy']}  ·  {stats['string_count']:,} strings",
        f"Why not shown as text: {reason}" if reason else "",
        "",
    ]
    for label, key in (("E-mail addresses", "emails"), ("URLs", "urls"), ("Windows paths", "windows_paths")):
        vals = indicators.get(key) or []
        if vals:
            lines.append(f"{label} ({len(vals)}):")
            lines.extend(f"  {v}" for v in vals[:25])
            lines.append("")
    lines.append("Strings (offset · encoding · text):")
    for s in strings[:300]:
        lines.append(f"  {s['offset']:>12,}  {s['encoding']:<8}  {s['text'][:240]}")
    if len(strings) > 300:
        lines.append(f"  … {len(strings) - 300:,} more strings")
    text = "\n".join(line for line in lines if line is not None)

    return {
        "classification": classification,
        "reason": reason,
        "source": source,
        "base_offset": base_offset,
        "stats": stats,
        "indicators": indicators,
        "strings": strings,
        "hex": hex_text,
        "hex_bytes": min(len(data), hex_bytes),
        "text": text,
    }
