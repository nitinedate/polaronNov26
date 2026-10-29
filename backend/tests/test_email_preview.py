"""Structured email preview for artifact browse."""

from __future__ import annotations

from email.message import EmailMessage

from app.parsers import email_mime_parser as em
from app.services import artifact_preview


class _FakeDb:
    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


def _sample_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Quarterly report"
    msg["Date"] = "Mon, 1 Jan 2024 12:00:00 +0000"
    msg.set_content("Plain body text")
    msg.add_attachment(b"pdf-bytes", maintype="application", subtype="pdf", filename="report.pdf")
    return msg.as_bytes()


def test_build_email_preview_details_parses_headers_and_attachments() -> None:
    details = em.build_email_preview_details(_sample_eml(), "Mail/Inbox/message.eml")
    assert details["parse_ok"] is True
    assert details["headers"]["from"] == "sender@example.com"
    assert details["headers"]["subject"] == "Quarterly report"
    assert "Plain body text" in details["body_text"]
    assert len(details["attachments"]) == 1
    assert details["attachments"][0]["filename"] == "report.pdf"
    assert details["attachments"][0]["size"] == len(b"pdf-bytes")


def test_load_mime_part_bytes_returns_attachment_payload() -> None:
    raw = _sample_eml()
    details = em.build_email_preview_details(raw, "message.eml")
    part_index = details["attachments"][0]["part_index"]
    payload, content_type, filename = em.load_mime_part_bytes(raw, "message.eml", part_index)
    assert payload == b"pdf-bytes"
    assert filename == "report.pdf"
    assert "pdf" in content_type


def test_build_artifact_preview_includes_email_block(monkeypatch) -> None:
    row = {
        "id": "a1",
        "file_path": "Mail/Inbox/message.eml",
        "file_name": "message.eml",
        "extension": ".eml",
        "minio_uri": "s3://bucket/message.eml",
        "metadata": {},
    }
    raw = _sample_eml()

    monkeypatch.setattr(artifact_preview, "_load_artifact_row", lambda db, jid, aid: row)
    monkeypatch.setattr(artifact_preview, "resolve_artifact_bytes", lambda *args, **kwargs: raw)
    monkeypatch.setattr(artifact_preview, "_link_attachment_artifacts", lambda db, jid, path, atts: atts)

    preview = artifact_preview.build_artifact_preview(_FakeDb(), "job", "a1")
    assert preview["email"]["subject"] == "Quarterly report"
    assert preview["body_text"]
    assert preview["attachments"][0]["filename"] == "report.pdf"
    assert preview["attachment_count"] == 1


# ---------------------------------------------------------------- carved EML fragments
def test_readable_email_gate_accepts_real_and_rejects_binary() -> None:
    from app.services.artifact_preview import _decode_text, _looks_like_readable_email
    import os

    real = ("From: a@x.com\r\nTo: b@y.com\r\nSubject: Project update\r\n\r\n"
            "Hi Bob, please review the attached figures and reply by Friday. Thanks, Alice.\r\n")
    assert _looks_like_readable_email(real) is True
    assert _looks_like_readable_email("Subject: hi\r\n\r\nSee you at 3pm in room 2.\r\n") is True
    # 200 random carved blobs must never be mistaken for readable email.
    fp = sum(1 for _ in range(200) if _looks_like_readable_email(_decode_text(os.urandom(4000))))
    assert fp == 0
    # EML signature followed by binary (the pagefile carve case).
    frag = b"Subject: carved\r\nFrom: x\r\nMIME-Version: 1.0\r\n\r\n" + os.urandom(3500)
    assert _looks_like_readable_email(_decode_text(frag)) is False


def _carved_row(path="pagefile.sys", name="carved-eml-pagefile.sys-387610514.eml"):
    return {
        "id": "c1", "file_path": path, "file_name": name, "extension": ".eml",
        "minio_uri": "s3://bucket/carved.eml", "metadata": {"carved": True},
        "artifact_type": "carved_eml",
    }


def test_carved_binary_eml_is_not_dumped_as_text(monkeypatch) -> None:
    import os

    raw = b"Subject: carved-eml\r\nFrom: x\r\nMIME-Version: 1.0\r\n\r\n" + os.urandom(4000)
    monkeypatch.setattr(artifact_preview, "_load_artifact_row", lambda db, jid, aid: _carved_row())
    monkeypatch.setattr(artifact_preview, "resolve_artifact_bytes", lambda *a, **k: raw)
    monkeypatch.setattr(artifact_preview, "_link_attachment_artifacts", lambda db, jid, path, atts: atts)

    preview = artifact_preview.build_artifact_preview(_FakeDb(), "job", "c1")
    # Email shell still mounts, but the body is an honest notice, not binary.
    assert preview["email"]["subject"]
    assert preview.get("carved_unparsed") is True
    assert "signature carving" in preview["body_text"].lower()
    # No replacement chars / mojibake leaked into the body.
    assert "\ufffd" not in preview["body_text"]
    assert preview["body"] == preview["body_text"]
    assert preview["attachment_count"] == 0


def test_real_eml_that_trips_strict_parser_still_shows_body(monkeypatch) -> None:
    # A valid RFC822 message the strict parser rejects must keep its readable body.
    raw = (b"From: real@example.com\r\nTo: b@example.com\r\n"
           b"Subject: Genuine message\r\n\r\n"
           b"This is a perfectly readable plain-text email body that should be shown.\r\n")
    monkeypatch.setattr(artifact_preview, "_load_artifact_row", lambda db, jid, aid: _carved_row())
    monkeypatch.setattr(artifact_preview, "resolve_artifact_bytes", lambda *a, **k: raw)
    monkeypatch.setattr(artifact_preview, "_link_attachment_artifacts", lambda db, jid, path, atts: atts)
    # Force the strict parser to "fail" so we exercise the fallback path.
    monkeypatch.setattr(artifact_preview, "build_email_preview_details",
                        lambda data, path: {"parse_ok": False}, raising=False)
    import app.parsers.email_mime_parser as em
    monkeypatch.setattr(em, "build_email_preview_details", lambda data, path: {"parse_ok": False})

    preview = artifact_preview.build_artifact_preview(_FakeDb(), "job", "c1")
    assert preview.get("carved_unparsed") is not True
    assert "readable plain-text email body" in preview["body_text"]
