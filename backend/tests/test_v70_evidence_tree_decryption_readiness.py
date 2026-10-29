from pathlib import Path

from app.services.artifact_family_browse import family_where_sql
from app.services.mobile_acquire.decryption_key_manifest import write_decryption_key_manifest
from app.services.mobile_forensic.package_inventory import _empty_counts


def test_android_existing_encrypted_backup_without_key_recommends_fuller_acquisition(tmp_path):
    original = tmp_path / "existing"
    crypt = original / "WhatsApp" / "Databases"
    crypt.mkdir(parents=True)
    (crypt / "msgstore.db.crypt14").write_bytes(b"x" * 64)
    out = tmp_path / "exports"
    result = write_decryption_key_manifest(out, original=original, platform="android")
    ready = result["readiness"]
    assert ready["WHATSAPP_ENCRYPTED_BACKUP_FOUND"] is True
    assert ready["WHATSAPP_KEY_FOUND"] is False
    assert ready["WHATSAPP_DECRYPTION_READY"] is False
    assert ready["REACQUISITION_RECOMMENDED"] is True
    text = (out / "decryption_keys.txt").read_text(encoding="utf-8")
    assert "MISSING_REQUIREMENTS=WHATSAPP_KEY_MATERIAL" in text


def test_android_existing_private_key_and_backup_is_ready(tmp_path):
    original = tmp_path / "existing"
    key_dir = original / "data" / "data" / "com.whatsapp" / "files"
    db_dir = original / "sdcard" / "WhatsApp" / "Databases"
    key_dir.mkdir(parents=True)
    db_dir.mkdir(parents=True)
    (key_dir / "key").write_bytes(bytes(range(126)) + bytes(range(32)))
    (db_dir / "msgstore.db.crypt14").write_bytes(b"x" * 64)
    result = write_decryption_key_manifest(tmp_path / "exports", original=original, platform="android")
    ready = result["readiness"]
    assert ready["WHATSAPP_KEY_FOUND"] is True
    assert ready["WHATSAPP_DECRYPTION_READY"] is True
    assert ready["REACQUISITION_RECOMMENDED"] is False


def test_ios_existing_chatstorage_is_parse_ready_without_reacquisition(tmp_path):
    original = tmp_path / "existing" / "AppDomain-com.whatsapp.WhatsApp" / "Documents"
    original.mkdir(parents=True)
    (original / "ChatStorage.sqlite").write_bytes(b"SQLite format 3\0")
    root = tmp_path / "existing"
    result = write_decryption_key_manifest(tmp_path / "exports", original=root, platform="ios")
    ready = result["readiness"]
    assert ready["IOS_CHATSTORAGE_FOUND"] is True
    assert ready["WHATSAPP_DECRYPTION_READY"] is True
    assert ready["REACQUISITION_RECOMMENDED"] is False


def test_whatsapp_evidence_subfamilies_have_specific_sql_filters():
    for key in (
        "whatsapp_images", "whatsapp_videos", "whatsapp_audio",
        "whatsapp_documents", "whatsapp_key_material",
    ):
        sql, params = family_where_sql(key)
        assert sql.strip(), key
        assert isinstance(params, dict)


def test_package_inventory_declares_whatsapp_subtree_counts():
    counts = _empty_counts()
    for key in (
        "whatsapp_images", "whatsapp_videos", "whatsapp_audio",
        "whatsapp_documents", "whatsapp_key_material",
    ):
        assert key in counts


def test_mobile_evidence_ui_has_source_specific_tree():
    text = Path("frontend/src/pages/mobile/MobileArtifactsPage.tsx").read_text(encoding="utf-8")
    for label in (
        "Communications › WhatsApp", "WhatsApp images", "WhatsApp videos",
        "WhatsApp audio / voice notes", "WhatsApp documents", "Media & files",
        "Email / attachment evidence", "Deleted / recovered evidence",
        "Company Information Leakage", "Encryption & recovery",
    ):
        assert label in text
