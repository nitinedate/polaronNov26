"""Strict RFC 5322 header-block validation for carved / unallocated mail.

Why this exists
---------------
Python's ``email`` parser accepts almost any byte string as a "message", so a
successful ``BytesParser`` call proves nothing about a signature-carved hit.
The old carver accepted ``From: `` when ``to:`` appeared anywhere in the next
2 KiB; in ``pagefile.sys`` that substring is everywhere (``proto:``,
``photo:``, JSON such as ``"mailTo":``), so Outlook/OWA application state in
memory was listed and previewed as "EML" files.

A real message begins with a contiguous block of header fields
(``Name: value`` lines, folded continuations) that ends at an empty line.  This
module checks exactly that, bounded and side-effect free, so the carver can
reject false hits and the preview can decide between "email" and "memory
fragment".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Field names commonly present in transported or stored messages.
KNOWN_HEADERS = frozenset({
    "from", "to", "cc", "bcc", "subject", "date", "message-id", "received",
    "return-path", "mime-version", "content-type", "content-transfer-encoding",
    "reply-to", "sender", "in-reply-to", "references", "delivered-to",
    "x-mailer", "user-agent", "thread-topic", "thread-index", "importance",
    "x-originating-ip", "authentication-results", "dkim-signature",
    "arc-seal", "x-ms-exchange-organization-authas", "content-language",
    "accept-language", "x-priority", "list-id", "list-unsubscribe",
})
# At least one originator/transport header ...
_ORIGIN_HEADERS = frozenset({"from", "received", "return-path", "sender", "delivered-to"})
# ... and at least one message-identity header.
_IDENTITY_HEADERS = frozenset({"date", "subject", "message-id", "to"})

# RFC 5322 ftext: printable US-ASCII except ':' (33-57, 59-126).
_FIELD_LINE = re.compile(rb"^([!-9;-~]{1,76}):[ \t]?(.*)$")
_MBOX_FROM = re.compile(rb"^From [^\r\n]{3,200}$")
_HEADER_LINE_FOR_BACKTRACK = re.compile(rb"^(?:[!-9;-~]{1,76}:|[ \t]\S)")

MAX_HEADER_BYTES = 32 * 1024


@dataclass
class Rfc822Check:
    valid: bool
    reason: str = ""
    start: int = 0
    header_end: int = -1          # offset just after the blank separator line
    header_names: list[str] = field(default_factory=list)
    known_headers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "start": self.start,
            "header_end": self.header_end,
            "header_names": self.header_names[:40],
            "known_headers": self.known_headers,
        }


def _value_ok(value: bytes) -> bool:
    # Header values may carry 8-bit UTF-8, but never NUL or raw control bytes.
    for b in value:
        if b < 0x20 and b not in (0x09,):
            return False
        if b == 0x7F:
            return False
    return True


def validate_rfc822(data: bytes, *, max_header_bytes: int = MAX_HEADER_BYTES) -> Rfc822Check:
    """Validate that ``data`` starts with an RFC 5322 header block.

    Leading CR/LF (at most 4 bytes) and an mbox ``From `` envelope line are
    tolerated.  The block must end with an empty line inside
    ``max_header_bytes`` and contain >= 3 distinct known header fields,
    including one originator and one identity header.
    """
    if not data:
        return Rfc822Check(False, "empty")
    start = 0
    while start < min(len(data), 4) and data[start:start + 1] in (b"\r", b"\n"):
        start += 1
    window = data[start:start + max_header_bytes]

    names: list[str] = []
    pos = 0
    line_no = 0
    header_end = -1
    prev_was_field = False
    while pos < len(window):
        nl = window.find(b"\n", pos)
        if nl < 0:
            return Rfc822Check(False, "header block not terminated", start=start,
                               header_names=names)
        line = window[pos:nl]
        if line.endswith(b"\r"):
            line = line[:-1]
        next_pos = nl + 1
        if not line:
            header_end = start + next_pos
            break
        if line_no == 0 and _MBOX_FROM.match(line):
            line_no += 1
            pos = next_pos
            continue
        if line[:1] in (b" ", b"\t"):
            if not prev_was_field:
                return Rfc822Check(False, "continuation without field", start=start,
                                   header_names=names)
            if not _value_ok(line):
                return Rfc822Check(False, "control bytes in folded header", start=start,
                                   header_names=names)
        else:
            m = _FIELD_LINE.match(line)
            if not m:
                return Rfc822Check(False, f"line {line_no + 1} is not a header field", start=start,
                                   header_names=names)
            if not _value_ok(m.group(2)):
                return Rfc822Check(False, "control bytes in header value", start=start,
                                   header_names=names)
            names.append(m.group(1).decode("ascii").lower())
            prev_was_field = True
        line_no += 1
        pos = next_pos
    if header_end < 0:
        return Rfc822Check(False, "header block exceeds bound", start=start, header_names=names)

    known = sorted({n for n in names if n in KNOWN_HEADERS})
    if len(known) < 3:
        return Rfc822Check(False, "fewer than 3 known header fields", start=start,
                           header_end=header_end, header_names=names, known_headers=known)
    if not (_ORIGIN_HEADERS & set(known)):
        return Rfc822Check(False, "no originator/transport header", start=start,
                           header_end=header_end, header_names=names, known_headers=known)
    if not (_IDENTITY_HEADERS & set(known)):
        return Rfc822Check(False, "no date/subject/message-id/to header", start=start,
                           header_end=header_end, header_names=names, known_headers=known)
    return Rfc822Check(True, "ok", start=start, header_end=header_end,
                       header_names=names, known_headers=known)


def find_header_block_start(buf: bytes, idx: int, *, max_back: int = MAX_HEADER_BYTES) -> int:
    """Walk back from a header hit (e.g. ``MIME-Version:``) to the block start.

    Stops at an empty line, a non-header line, or ``max_back`` bytes.  Returns
    the offset of the first header line of the block containing ``idx``.
    """
    if idx <= 0:
        return 0
    # Align idx to the start of its line.
    line_start = buf.rfind(b"\n", 0, idx) + 1
    floor = max(0, idx - max_back)
    start = line_start
    while start > floor:
        prev_end = start - 1                      # the '\n' ending the previous line
        prev_start = buf.rfind(b"\n", 0, prev_end) + 1
        if prev_start < floor:
            break
        prev = buf[prev_start:prev_end]
        if prev.endswith(b"\r"):
            prev = prev[:-1]
        if not prev:
            break
        if not (_HEADER_LINE_FOR_BACKTRACK.match(prev) or _MBOX_FROM.match(prev)):
            break
        start = prev_start
    return start


def readable_text_ratio(text: str, *, sample: int = 4000) -> float:
    """Share of plain ASCII text characters in a decoded body sample."""
    probe = (text or "")[:sample]
    if not probe:
        return 0.0
    good = sum(1 for c in probe if 32 <= ord(c) <= 126 or c in "\r\n\t")
    return good / len(probe)


def is_readable_body(text: str) -> bool:
    """Gate used before showing a decoded body as text (mirrors the preview gate)."""
    probe = (text or "")[:4000]
    if not probe.strip():
        return False
    if "\ufffd" in probe:
        return False
    n = len(probe)
    control = sum(1 for c in probe if ord(c) < 32 and c not in "\r\n\t")
    letters = sum(1 for c in probe if c.isalpha() or c.isspace())
    return readable_text_ratio(probe) >= 0.90 and control / n <= 0.02 and letters / n >= 0.55
