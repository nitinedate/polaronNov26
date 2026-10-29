"""2026-10-22: carved EML binary preview, parsers for unopenable artifacts, fast open."""

from __future__ import annotations

import hashlib
import io
import struct
import types
from datetime import datetime, timezone

import pytest

REAL_EMAIL = (
    b"Received: from mx.example.com (mx.example.com [203.0.113.5])\r\n"
    b"\tby mail.example.org with ESMTPS id abc123\r\n"
    b"From: Alice Example <alice@example.com>\r\n"
    b"To: Bob <bob@example.org>\r\n"
    b"Subject: Quarterly invoice\r\n"
    b"Date: Tue, 13 Oct 2026 10:15:00 +0000\r\n"
    b"Message-ID: <msg-1@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hello Bob,\r\nPlease find the invoice details below. Regards, Alice\r\n"
)

# Shape of what Image 3 showed: Outlook/OWA JS state in pagefile memory.
OWA_MEMORY = (
    b"\x00\x10\x83\xff\x01" + b"\x9a\x00\x00" * 40
    + b'{"nativeVersion":"1.2025.5.100","mailTo":"x@y.com","proto:1,"photo:2'
    + b"\nFrom: \x01\x02\xff\xfe" + b"\x00" * 30
    + b'"/mail/inbox/id","ndQuery":"\x8f\x91","module@Mailx folder","focusedViewFilter":0,'
    + b'"globalInboxWindow-1" to: date: subject: '
    + bytes(range(256)) * 4
)


# --------------------------------------------------------------------------- RFC 822

def test_validator_accepts_real_message_and_reports_header_end():
    from app.parsers.rfc822_validate import validate_rfc822

    chk = validate_rfc822(REAL_EMAIL)
    assert chk.valid, chk.reason
    assert REAL_EMAIL[chk.header_end:].startswith(b"Hello Bob")
    assert {"from", "to", "subject", "date", "message-id", "received"} <= set(chk.known_headers)


@pytest.mark.parametrize("blob", [
    OWA_MEMORY,
    b"From: x\nproto: y\nphoto: z\n\nbody",               # 1 known header only
    b"From: a@b.c\nSubject: hi\nX-Foo: \x01\x02\n\n",     # control bytes in value
    b"From: a@b.c\nTo: b@c.d\nSubject: never terminated",  # no blank line
    b'{"From": "a", "to": "b", "date": "c"}',
])
def test_validator_rejects_memory_and_malformed_blocks(blob):
    from app.parsers.rfc822_validate import validate_rfc822

    assert not validate_rfc822(blob).valid


def test_validator_tolerates_mbox_envelope_and_leading_newline():
    from app.parsers.rfc822_validate import validate_rfc822

    chk = validate_rfc822(b"\nFrom alice@example.com Tue Oct 13 10:15:00 2026\n" + REAL_EMAIL.replace(b"\r\n", b"\n"))
    assert chk.valid and chk.start == 1


def test_backtrack_from_mime_version_reaches_block_start():
    from app.parsers.rfc822_validate import find_header_block_start

    buf = b"garbage line\n\n" + REAL_EMAIL
    idx = buf.index(b"MIME-Version:")
    assert find_header_block_start(buf, idx) == buf.index(b"Received:")


# --------------------------------------------------------------------------- carver

def test_carver_finds_only_the_real_message_once():
    from app.services.signature_carve_inventory import scan_buffer_for_signatures

    lead = OWA_MEMORY * 3
    buf = lead + b"\n\n" + REAL_EMAIL + OWA_MEMORY
    hits = [h for h in scan_buffer_for_signatures(buf, source_path="pagefile.sys", base_offset=1000)
            if h["kind"] == "eml"]
    assert len(hits) == 1, hits
    assert hits[0]["offset"] == 1000 + buf.index(b"Received:")
    assert hits[0]["rfc822_validated"] is True


def test_carver_no_hits_in_owa_memory_alone():
    from app.services.signature_carve_inventory import scan_buffer_for_signatures

    hits = scan_buffer_for_signatures(OWA_MEMORY * 20, source_path="pagefile.sys")
    assert not [h for h in hits if h["kind"] == "eml"]


def test_list_time_dedupe_of_old_off_by_one_pairs():
    from app.services.signature_carve_inventory import dedupe_adjacent_eml_hits

    rows = [
        {"kind": "eml", "source_path": "pagefile.sys", "offset": 612902912},
        {"kind": "eml", "source_path": "pagefile.sys", "offset": 612902911},
        {"kind": "eml", "source_path": "pagefile.sys", "offset": 328079673},
        {"kind": "eml", "source_path": "pagefile.sys", "offset": 328079674},
        {"kind": "eml", "source_path": "hiberfil.sys", "offset": 328079674},
        {"kind": "jpeg", "source_path": "pagefile.sys", "offset": 328079675},
        {"kind": "eml", "source_path": "pagefile.sys", "offset": 783181985},
    ]
    out = dedupe_adjacent_eml_hits(rows)
    assert len(out) == 5
    assert sum(1 for r in out if r["source_path"] == "pagefile.sys" and r["kind"] == "eml") == 3
    assert any(r["kind"] == "jpeg" for r in out)


# --------------------------------------------------------------------------- fragment

def test_fragment_view_strings_offsets_indicators_hex():
    from app.parsers.binary_fragment import build_fragment_view

    data = (b"\x00\x01" * 5 + b"hello world forensic" + b"\x00\xff" * 3
            + "C:\\Users\\bob\\Desktop\\plan.docx".encode("utf-16-le") + b"\x00\x00"
            + b"\x03contact: carol@example.net https://evil.example/x?y=1\x00" + bytes(range(256)))
    view = build_fragment_view(data, base_offset=5000, source="pagefile.sys", reason="test")
    first = view["strings"][0]
    assert first["offset"] == 5010 and first["text"] == "hello world forensic"
    assert any(s["encoding"] == "utf-16le" and "plan.docx" in s["text"] for s in view["strings"])
    assert "carol@example.net" in view["indicators"]["emails"]
    assert any(u.startswith("https://evil.example/x") for u in view["indicators"]["urls"])
    assert any(p.endswith("plan.docx") for p in view["indicators"]["windows_paths"])
    assert view["hex"].splitlines()[0].startswith("00001388  00 01 00 01")
    assert "\ufffd" not in view["text"]


def _carved_preview(monkeypatch, data: bytes):
    import app.services.carved_artifact_content as cac

    hit = {"id": "carve-eml-x", "kind": "eml", "source_path": "pagefile.sys", "offset": 612902912}
    monkeypatch.setattr(cac, "load_carved_content",
                        lambda db, j, a: (data, "message/rfc822", "carved-eml-pagefile.sys-612902912.eml", hit))
    return cac.build_carved_preview(None, "job", "carve-eml-x")


def test_carved_memory_hit_is_fragment_not_mojibake_email(monkeypatch):
    pv = _carved_preview(monkeypatch, OWA_MEMORY)
    assert pv["carved_unparsed"] is True and pv["email"] is None
    assert pv["fragment"]["base_offset"] == 612902912
    assert "\ufffd" not in pv["body"] and "\ufffd" not in (pv.get("body_text") or "")
    assert not pv["rfc822_check"]["valid"]
    assert any("mail/inbox" in s["text"] for s in pv["fragment"]["strings"])


def test_carved_real_message_shows_headers_and_body(monkeypatch):
    pv = _carved_preview(monkeypatch, b"\n" + REAL_EMAIL)
    assert pv["email"]["subject"] == "Quarterly invoice"
    assert "invoice details" in pv["body_text"]
    assert not pv.get("carved_unparsed") and "fragment" not in pv


def test_carved_valid_headers_binary_body_is_partial(monkeypatch):
    msg = REAL_EMAIL.split(b"\r\n\r\n")[0] + b"\r\n\r\n" + bytes(range(256)) * 20
    pv = _carved_preview(monkeypatch, msg)
    assert pv["email"]["from"].startswith("Alice")
    assert pv.get("carved_partial") is True and "fragment" in pv
    assert "\ufffd" not in pv["body_text"]


# --------------------------------------------------------------------------- MSG (olefile)

class _FakeOle:
    def __init__(self, streams: dict[str, bytes]):
        self.streams = streams

    def exists(self, name):
        return name in self.streams

    def openstream(self, path):
        key = "/".join(path) if isinstance(path, list) else path
        return io.BytesIO(self.streams[key])

    def listdir(self, streams=True, storages=False):
        return [k.split("/") for k in self.streams]

    def close(self):
        pass


def _u(s: str) -> bytes:
    return s.encode("utf-16-le")


def _filetime(dt: datetime) -> bytes:
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return struct.pack("<Q", int(delta.total_seconds() * 10_000_000))


def test_mapi_msg_reader_headers_recipients_attachments():
    from app.parsers.mapi_msg_ole import load_msg_attachment_ole, parse_msg_ole

    sent = datetime(2026, 10, 13, 10, 15, 0, tzinfo=timezone.utc)
    top_props = b"\x00" * 32 + struct.pack("<II", (0x0039 << 16) | 0x0040, 0) + _filetime(sent)
    recip_props = b"\x00" * 8 + struct.pack("<II", (0x0C15 << 16) | 0x0003, 0) + struct.pack("<I", 2) + b"\x00" * 4
    ole = _FakeOle({
        "__substg1.0_0037001F": _u("Board minutes"),
        "__substg1.0_0C1A001F": _u("Alice Example"),
        "__substg1.0_5D01001F": _u("alice@example.com"),
        "__substg1.0_1000001F": _u("Minutes attached."),
        "__substg1.0_1035001F": _u("<id-9@example.com>"),
        "__properties_version1.0": top_props,
        "__recip_version1.0_#00000000/__substg1.0_3001001F": _u("Carol"),
        "__recip_version1.0_#00000000/__substg1.0_39FE001F": _u("carol@example.org"),
        "__recip_version1.0_#00000000/__properties_version1.0": recip_props,
        "__attach_version1.0_#00000000/__substg1.0_3707001F": _u("minutes.pdf"),
        "__attach_version1.0_#00000000/__substg1.0_37010102": b"%PDF-1.7 test",
        "__attach_version1.0_#00000000/__substg1.0_370E001F": _u("application/pdf"),
    })
    d = parse_msg_ole(ole, "x.msg")
    assert d["parse_ok"]
    h = d["headers"]
    assert h["subject"] == "Board minutes"
    assert h["from"] == "Alice Example <alice@example.com>"
    assert h["cc"] == "Carol <carol@example.org>" and not h["to"]
    assert h["date"].startswith("2026-10-13T10:15:00")
    assert d["attachments"][0]["filename"] == "minutes.pdf" and d["attachments"][0]["size"] == 13
    payload, mime, name = load_msg_attachment_ole(ole, 0)
    assert payload.startswith(b"%PDF") and mime == "application/pdf" and name == "minutes.pdf"


def test_msg_preview_without_extract_msg_does_not_raise():
    from app.parsers.outlook_msg_parser import build_msg_preview_details

    out = build_msg_preview_details(b"not an ole file at all" * 10, "x.msg")
    assert out["parse_ok"] is False and out.get("error")


# --------------------------------------------------------------------------- parsed records

@pytest.mark.parametrize("path,expected", [
    ("Windows/System32/config/SOFTWARE", "registry"),
    ("Users/bob/NTUSER.DAT", "registry"),
    ("Windows/AppCompat/Programs/Amcache.hve", "registry"),
    ("Windows/System32/winevt/Logs/Security.evtx", "evtx"),
    ("Windows/Prefetch/CMD.EXE-0BD30981.pf", "prefetch"),
    ("Users/bob/Desktop/report.lnk", "lnk"),
    ("Users/bob/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms", "jumplist"),
    ("Windows/INF/setupapi.dev.log", "setupapi"),
    ("$Recycle.Bin/S-1-5-21-1/$IAB12CD.docx", "recycle_bin"),
    ("Users/bob/Documents/Outlook Files/bob.pst", "pst"),
    ("Users/bob/notes.txt", None),
])
def test_structured_parser_mapping(path, expected):
    from app.services.artifact_parsed_view import structured_parser_for

    assert structured_parser_for({"file_path": path, "file_name": path.rsplit("/", 1)[-1]}) == expected


def test_records_table_priority_drop_and_truncate():
    from app.services.artifact_parsed_view import records_table

    recs = [
        {"raw": "AAAA", "value": "x" * 1000, "key_path": "HKLM\\SOFTWARE\\Run", "record_type": "autorun",
         "value_name": "Updater", "zz_extra": 1},
        {"record_type": "autorun", "key_path": "HKLM\\SOFTWARE\\Run", "value_name": "Other", "value": "c:\\a.exe"},
    ]
    t = records_table(recs, "registry")
    assert t["columns"][:4] == ["record_type", "key_path", "value_name", "value"]
    assert "raw" not in t["columns"]
    assert t["rows"][0][3].endswith("…") and len(t["rows"][0][3]) <= 400


def test_latest_parse_meta_prefers_real_parser(monkeypatch):
    import app.services.artifact_parsed_view as pv

    rows = [
        {"id": "1", "parser_name": "file_meta", "parser_version": "2.13.0", "jtype": "array", "n": 1},
        {"id": "2", "parser_name": "registry", "parser_version": "2.13.0", "jtype": "array", "n": 812},
    ]
    monkeypatch.setattr(pv, "fetchall", lambda db, sql, params=None: rows)
    meta = pv.latest_parse_meta(None, "a")
    assert meta["id"] == "2" and pv.is_strong_parse(meta)
    monkeypatch.setattr(pv, "fetchall", lambda db, sql, params=None: rows[:1])
    assert not pv.is_strong_parse(pv.latest_parse_meta(None, "a"))


def test_records_page_sql_slices_in_postgres(monkeypatch):
    import app.services.artifact_parsed_view as pv

    seen = {}

    def fake_fetchall(db, sql, params=None):
        seen["sql"], seen["params"] = sql, params
        return [{"rec": {"event_id": 4624}, "ord": 201}]

    monkeypatch.setattr(pv, "fetchall", fake_fetchall)
    out = pv.page_records(None, {"id": "r", "jtype": "array", "n": 5000}, offset=200, limit=9999)
    assert out == [{"event_id": 4624}]
    assert "jsonb_array_elements" in seen["sql"] and "WITH ORDINALITY" in seen["sql"]
    assert seen["params"] == {"rid": "r", "off": 200, "lim": 500}


# --------------------------------------------------------------------------- locator / read order

def test_location_rows_last_wins_and_resolves_part_uri():
    from app.services.artifact_locator import location_rows, manifest_fingerprint

    manifest = {"parts_map": {"0": "s3://b/part-0.tar.zst", "1": "s3://b/part-1.tar.zst"}}
    entries = [
        {"path": "Windows\\System32\\config\\SOFTWARE", "part_id": 0, "offset": 10, "size_bytes": 5, "sha256": "a"},
        {"path": "Windows/System32/config/SOFTWARE", "part_id": 1, "offset": 20, "size_bytes": 6, "sha256": "b"},
        {"path": "Users/x.txt", "part_id": 7},  # unknown part -> skipped
    ]
    rows = location_rows(manifest, entries)
    assert len(rows) == 1 and rows[0]["part_uri"].endswith("part-1.tar.zst") and rows[0]["sha256"] == "b"
    fp1 = manifest_fingerprint(manifest)
    manifest["parts_map"]["2"] = "s3://b/part-2.tar.zst"
    assert manifest_fingerprint(manifest) != fp1


def _fake_vd_module(monkeypatch, payload: bytes):
    mod = types.ModuleType("app.services.virtual_disk")
    mod.read_full_file_from_disk = lambda vd, path, inode=None, max_bytes=None: payload
    monkeypatch.setitem(__import__("sys").modules, "app.services.virtual_disk", mod)


def test_source_read_verifies_size_and_sha(monkeypatch):
    import app.services.artifact_locator as loc

    data = b"evidence bytes"
    _fake_vd_module(monkeypatch, data)
    monkeypatch.setattr(loc, "_source_disk", lambda db, job: object())
    row = {"file_path": "Users/a.txt", "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assert loc.read_from_source(None, "j", row, max_bytes=None) == data
    assert loc.read_from_source(None, "j", dict(row, sha256="00" * 32), max_bytes=None) is None
    assert loc.read_from_source(None, "j", dict(row, size_bytes=999), max_bytes=None) is None


def test_deleted_entry_without_hash_never_read_by_path():
    from app.services.artifact_locator import source_read_allowed

    assert not source_read_allowed({"file_path": "a/b.doc", "metadata": {"is_deleted": True}})
    assert source_read_allowed({"file_path": "a/b.doc", "metadata": {"is_deleted": True}, "sha256": "ab"})
    assert source_read_allowed({"file_path": "a/b.doc"})


@pytest.mark.parametrize("source,located,legacy_expected,expected", [
    (b"SRC", (True, b"SHARD"), False, b"SRC"),
    (None, (True, b"SHARD"), False, b"SHARD"),
    (None, (True, None), False, None),       # shard read, member absent: no 2nd full scan
    (None, (False, None), True, b"LEGACY"),  # no location index: legacy reader
])
def test_preview_read_order(monkeypatch, source, located, legacy_expected, expected):
    import app.services.artifact_live_counts as alc
    import app.services.artifact_locator as loc
    import app.services.artifact_preview as ap

    calls = {"legacy": 0}
    monkeypatch.setattr(loc, "read_from_source", lambda db, j, row, max_bytes=None: source)
    monkeypatch.setattr(loc, "read_from_located_shard", lambda db, j, row, max_bytes=None: located)

    def legacy(db, j, rows, max_bytes=None):
        calls["legacy"] += 1
        return {"Users/a.txt": b"LEGACY"}

    monkeypatch.setattr(alc, "_read_job_files", legacy)
    out = ap._read_bytes_from_extraction(None, "j", {"file_path": "Users/a.txt", "size_bytes": 3})
    assert out == expected
    assert (calls["legacy"] > 0) == legacy_expected
