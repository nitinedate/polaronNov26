from pathlib import Path

from app.parsers import run_parser, select_parser
from app.services.mobile_acquire.decryption_key_manifest import write_decryption_key_manifest


def test_unknown_binary_gets_bounded_strings():
    data = b"\x00\x01" + b"COMPANY_SECRET_TOKEN_ABC123" + b"\x00\xff" * 100
    name, records = run_parser("evidence/opaque.bin2", data)
    assert name == "binary_fallback"
    assert records[0]["record_type"] == "binary_metadata"
    assert any("COMPANY_SECRET_TOKEN" in str(r.get("text") or "") for r in records[1:])


def test_document_extensions_have_native_parser():
    for ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp"):
        assert select_parser("sample" + ext) is not None


def test_key_manifest_exports_valid_whatsapp_material(tmp_path):
    original = tmp_path / "02_Original_Extraction"
    key_dir = original / "data" / "data" / "com.whatsapp" / "files"
    key_dir.mkdir(parents=True)
    # Classic 158-byte key file: cipher key is bytes 126:158.
    raw = bytes(range(126)) + bytes(range(32))
    (key_dir / "key").write_bytes(raw)
    exports = tmp_path / "05_Exports" / "run1"
    result = write_decryption_key_manifest(exports, original=original, platform="android")
    text = (exports / "decryption_keys.txt").read_text(encoding="utf-8")
    assert "PLATFORM=android" in text
    assert "KEY_MATERIAL_001_BASE64=" in text
    assert "KEY_MATERIAL_001_SHA256=" in text
    assert result["binary_material_count"] == 1


def test_key_manifest_records_authorized_password_without_returning_value(tmp_path):
    exports = tmp_path / "05_Exports" / "run2"
    result = write_decryption_key_manifest(
        exports,
        platform="ios",
        supplied_keys={"ios_backup_password": "CasePassword!"},
    )
    text = (exports / "decryption_keys.txt").read_text(encoding="utf-8")
    assert "IOS_BACKUP_PASSWORD=CasePassword!" in text
    assert "CasePassword!" not in repr(result)
