from pathlib import Path

from app.services.mobile_forensic.key_intake import (
    is_whatsapp_key_path,
    whatsapp_backup_path_priority,
    whatsapp_key_path_priority,
)
from app.services.mobile_acquire.decryption_key_manifest import write_decryption_key_manifest


def test_android_data_whatsapp_key_is_recognized_and_prioritized():
    assert is_whatsapp_key_path("Android/data/com.whatsapp/files/key")
    assert is_whatsapp_key_path("data/user/10/com.whatsapp/files/key")
    assert whatsapp_key_path_priority("data/data/com.whatsapp/files/key") < whatsapp_key_path_priority(
        "Android/data/com.whatsapp/files/key"
    )
    assert whatsapp_key_path_priority("Android/data/com.whatsapp/files/key") < whatsapp_key_path_priority(
        "random/com.whatsapp/cache/key"
    )


def test_backup_locations_are_ranked_but_not_excluded():
    assert whatsapp_backup_path_priority("Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14") < whatsapp_backup_path_priority(
        "Downloads/msgstore.db.crypt14"
    )


def test_manifest_promotes_discovered_android_data_key(tmp_path: Path):
    original = tmp_path / "acquisition"
    key_path = original / "Android" / "data" / "com.whatsapp" / "files" / "key"
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"K" * 32)
    backup = original / "Android" / "media" / "com.whatsapp" / "WhatsApp" / "Databases" / "msgstore.db.crypt14"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"encrypted-placeholder")
    export = tmp_path / "05_Exports" / "run"
    result = write_decryption_key_manifest(export, original=original, platform="android")
    text = (export / "decryption_keys.txt").read_text(encoding="utf-8")
    assert "WHATSAPP_KEY_HEX=" + (b"K" * 32).hex() in text
    assert "WHATSAPP_KEY_SOURCE_PATH=Android/data/com.whatsapp/files/key" in text
    assert "WHATSAPP_KEY_FOUND=true" in text
    assert result["readiness"]["WHATSAPP_ENCRYPTED_BACKUP_FOUND"] is True


def test_duplicate_key_material_is_recorded_once(tmp_path: Path):
    original = tmp_path / "acquisition"
    one = original / "data" / "data" / "com.whatsapp" / "files" / "key"
    two = original / "Android" / "data" / "com.whatsapp" / "files" / "key"
    one.parent.mkdir(parents=True)
    two.parent.mkdir(parents=True)
    one.write_bytes(b"Q" * 32)
    two.write_bytes(b"Q" * 32)
    export = tmp_path / "exports"
    result = write_decryption_key_manifest(export, original=original, platform="android")
    text = (export / "decryption_keys.txt").read_text(encoding="utf-8")
    assert result["binary_material_count"] == 1
    assert "KEY_DUPLICATE_SOURCE_001=" in text
