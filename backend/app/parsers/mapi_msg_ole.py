"""Read Outlook .msg (MS-OXMSG) with ``olefile`` only.

``outlook_msg_parser`` relied on ``extract-msg``, which is not in
``requirements.txt``; in the shipped images every .msg preview therefore
failed.  ``olefile`` *is* a dependency, and the .msg layout is a documented
compound file (MS-OXMSG):

* string/binary properties:  ``__substg1.0_<TAG:4hex><TYPE:4hex>``
  (``001F`` UTF-16LE, ``001E`` 8-bit string, ``0102`` binary)
* fixed-size properties:     ``__properties_version1.0`` (16-byte entries
  after a 32-byte header for the top-level message, 8 bytes for attachments
  and recipients, 24 bytes for embedded messages)
* recipients:                ``__recip_version1.0_#XXXXXXXX``
* attachments:               ``__attach_version1.0_#XXXXXXXX``

Read-only: the evidence bytes are parsed in memory and never written.
"""

from __future__ import annotations

import io
import struct
from datetime import datetime, timedelta, timezone
from typing import Any

PT_UNICODE = "001F"
PT_STRING8 = "001E"
PT_BINARY = "0102"
PT_SYSTIME = 0x0040
PT_LONG = 0x0003

TAG_SUBJECT = "0037"
TAG_SENDER_NAME = "0C1A"
TAG_SENDER_EMAIL = "0C1F"
TAG_SENDER_SMTP = "5D01"
TAG_SENT_REPR_EMAIL = "0065"
TAG_DISPLAY_TO = "0E04"
TAG_DISPLAY_CC = "0E03"
TAG_DISPLAY_BCC = "0E02"
TAG_BODY = "1000"
TAG_HTML = "1013"
TAG_HEADERS = "007D"
TAG_MESSAGE_ID = "1035"
TAG_MESSAGE_CLASS = "001A"
TAG_ATT_LONG_NAME = "3707"
TAG_ATT_NAME = "3704"
TAG_ATT_DISPLAY = "3001"
TAG_ATT_DATA = "3701"
TAG_ATT_MIME = "370E"
TAG_RECIP_DISPLAY = "3001"
TAG_RECIP_SMTP = "39FE"
TAG_RECIP_EMAIL = "3003"

PROP_CLIENT_SUBMIT_TIME = 0x0039
PROP_DELIVERY_TIME = 0x0E06
PROP_RECIPIENT_TYPE = 0x0C15
PROP_ATTACH_METHOD = 0x3705

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _open(data_or_ole: Any):
    if hasattr(data_or_ole, "openstream"):
        return data_or_ole, False
    import olefile  # type: ignore

    return olefile.OleFileIO(io.BytesIO(data_or_ole)), True


def _read(ole, path: list[str]) -> bytes | None:
    try:
        if not ole.exists("/".join(path)):
            return None
        return ole.openstream(path).read()
    except Exception:
        return None


def _prop_string(ole, prefix: list[str], tag: str) -> str:
    raw = _read(ole, prefix + [f"__substg1.0_{tag}{PT_UNICODE}"])
    if raw is not None:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
    raw = _read(ole, prefix + [f"__substg1.0_{tag}{PT_STRING8}"])
    if raw is not None:
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                return raw.decode(enc).rstrip("\x00").strip()
            except UnicodeDecodeError:
                continue
    return ""


def _prop_binary(ole, prefix: list[str], tag: str) -> bytes | None:
    return _read(ole, prefix + [f"__substg1.0_{tag}{PT_BINARY}"])


def _fixed_props(ole, prefix: list[str], header_len: int) -> dict[int, tuple[int, bytes]]:
    raw = _read(ole, prefix + ["__properties_version1.0"])
    out: dict[int, tuple[int, bytes]] = {}
    if not raw or len(raw) <= header_len:
        return out
    for pos in range(header_len, len(raw) - 15, 16):
        tag, _flags = struct.unpack_from("<II", raw, pos)
        out[tag >> 16] = (tag & 0xFFFF, raw[pos + 8:pos + 16])
    return out


def _filetime(value: bytes) -> str:
    try:
        ticks = struct.unpack("<Q", value)[0]
        if ticks <= 0:
            return ""
        return (_EPOCH_1601 + timedelta(microseconds=ticks // 10)).isoformat()
    except Exception:
        return ""


def _storages(ole, prefix_name: str) -> list[str]:
    names: set[str] = set()
    try:
        for entry in ole.listdir(streams=True, storages=True):
            if entry and entry[0].startswith(prefix_name):
                names.add(entry[0])
    except Exception:
        return []
    return sorted(names)


def parse_msg_ole(data_or_ole: Any, path: str = "") -> dict[str, Any]:
    """Headers, bodies, recipients and attachment list of one .msg message."""
    try:
        ole, owned = _open(data_or_ole)
    except Exception as exc:
        return {"parse_ok": False, "error": f"not an OLE compound file: {exc}"[:200]}
    try:
        top = _fixed_props(ole, [], 32)
        date = ""
        for prop in (PROP_CLIENT_SUBMIT_TIME, PROP_DELIVERY_TIME):
            ptype, value = top.get(prop, (0, b""))
            if ptype == PT_SYSTIME:
                date = _filetime(value)
                if date:
                    break

        to_list: list[str] = []
        cc_list: list[str] = []
        bcc_list: list[str] = []
        for storage in _storages(ole, "__recip_version1.0_"):
            name = _prop_string(ole, [storage], TAG_RECIP_DISPLAY)
            addr = _prop_string(ole, [storage], TAG_RECIP_SMTP) or _prop_string(ole, [storage], TAG_RECIP_EMAIL)
            shown = f"{name} <{addr}>" if name and addr and name != addr else (addr or name)
            rtype = _fixed_props(ole, [storage], 8).get(PROP_RECIPIENT_TYPE, (0, b"\x01\x00\x00\x00"))[1]
            kind = struct.unpack_from("<I", rtype)[0] if len(rtype) >= 4 else 1
            if shown:
                (cc_list if kind == 2 else bcc_list if kind == 3 else to_list).append(shown)

        sender_name = _prop_string(ole, [], TAG_SENDER_NAME)
        sender_addr = (
            _prop_string(ole, [], TAG_SENDER_SMTP)
            or _prop_string(ole, [], TAG_SENDER_EMAIL)
            or _prop_string(ole, [], TAG_SENT_REPR_EMAIL)
        )
        sender = (
            f"{sender_name} <{sender_addr}>" if sender_name and sender_addr and sender_name != sender_addr
            else (sender_addr or sender_name)
        )
        headers = {
            "from": sender,
            "to": "; ".join(to_list) or _prop_string(ole, [], TAG_DISPLAY_TO),
            "cc": "; ".join(cc_list) or _prop_string(ole, [], TAG_DISPLAY_CC),
            "bcc": "; ".join(bcc_list) or _prop_string(ole, [], TAG_DISPLAY_BCC),
            "subject": _prop_string(ole, [], TAG_SUBJECT),
            "date": date,
            "message_id": _prop_string(ole, [], TAG_MESSAGE_ID),
        }
        body_text = _prop_string(ole, [], TAG_BODY)
        html_raw = _prop_binary(ole, [], TAG_HTML)
        body_html = ""
        if html_raw:
            for enc in ("utf-8", "cp1252", "latin-1"):
                try:
                    body_html = html_raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
        else:
            body_html = _prop_string(ole, [], TAG_HTML)

        attachments: list[dict[str, Any]] = []
        for index, storage in enumerate(_storages(ole, "__attach_version1.0_")):
            name = (
                _prop_string(ole, [storage], TAG_ATT_LONG_NAME)
                or _prop_string(ole, [storage], TAG_ATT_NAME)
                or _prop_string(ole, [storage], TAG_ATT_DISPLAY)
                or f"attachment-{index + 1}.dat"
            )
            payload = _prop_binary(ole, [storage], TAG_ATT_DATA)
            method = _fixed_props(ole, [storage], 8).get(PROP_ATTACH_METHOD, (0, b"\x01\x00\x00\x00"))[1]
            embedded = (struct.unpack_from("<I", method)[0] if len(method) >= 4 else 1) == 5
            attachments.append({
                "part_index": index,
                "storage": storage,
                "filename": name[:180],
                "content_type": _prop_string(ole, [storage], TAG_ATT_MIME)
                or ("application/vnd.ms-outlook" if embedded else "application/octet-stream"),
                "size": len(payload or b""),
                "inline": False,
                "embedded_message": embedded,
            })

        return {
            "parse_ok": bool(headers["subject"] or body_text or body_html or sender or attachments),
            "parser": "mapi_msg_ole",
            "message_class": _prop_string(ole, [], TAG_MESSAGE_CLASS),
            "headers": headers,
            "transport_headers": _prop_string(ole, [], TAG_HEADERS)[:20000],
            "body_text": body_text,
            "body_html": body_html,
            "attachments": attachments,
            "attachment_count": len(attachments),
            "source_path": path,
        }
    finally:
        if owned:
            try:
                ole.close()
            except Exception:
                pass


def load_msg_attachment_ole(data_or_ole: Any, index: int) -> tuple[bytes, str | None, str]:
    ole, owned = _open(data_or_ole)
    try:
        storages = _storages(ole, "__attach_version1.0_")
        if index < 0 or index >= len(storages):
            raise LookupError("MSG attachment not found")
        storage = storages[index]
        payload = _prop_binary(ole, [storage], TAG_ATT_DATA)
        if payload is None:
            raise LookupError("MSG attachment has no binary data (embedded message or OLE object)")
        name = (
            _prop_string(ole, [storage], TAG_ATT_LONG_NAME)
            or _prop_string(ole, [storage], TAG_ATT_NAME)
            or f"attachment-{index + 1}.dat"
        )
        return payload, _prop_string(ole, [storage], TAG_ATT_MIME) or None, name[:180]
    finally:
        if owned:
            try:
                ole.close()
            except Exception:
                pass
