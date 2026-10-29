"""The Android acquisition UI exposes the WhatsApp decrypt agent controls.

String-level contract checks (no Node). The field is Android-gated and the
device-modifying authorization is opt-in.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "frontend/src/pages/forensic/MobileAcquisitionPage.tsx"
TYPES = ROOT / "frontend/src/lib/types/forensic.ts"


def test_whatsapp_block_is_android_gated():
    s = PAGE.read_text()
    assert 'preview.device_profile.os_family === "android" && (' in s
    block = s[s.index('preview.device_profile.os_family === "android" && ('):]
    block = block[:block.index("Cloud mailboxes (optional)")]
    assert "WhatsApp decryption" in block
    assert "wa_generate_backup" in block
    assert "64-digit WhatsApp key" in block


def test_authorization_is_opt_in_and_defaults_off():
    s = PAGE.read_text()
    assert "wa_generate_backup: false," in s  # default off
    assert "wa_allow_device_modification: false," in s  # independent override off


def test_device_modification_requires_both_tokens():
    s = PAGE.read_text()
    # Both the backup action AND the override must be set before any token is sent.
    assert "form.wa_generate_backup && form.wa_allow_device_modification" in s
    assert '"whatsapp_generate_key_and_backup", "allow_device_modification"' in s


def test_read_only_options_are_presented_before_backup_creation():
    s = PAGE.read_text()
    block = s[s.index("WhatsApp decryption"):s.index("Cloud mailboxes (optional)")]
    # The read-only ladder text appears before the "last resort" device-write block.
    assert block.index("without") < block.index("Last resort")
    assert "files/key" in block and "live" in block


def test_key_is_sent_as_whatsapp_64_digit_key():
    s = PAGE.read_text()
    assert "whatsapp_64_digit_key: form.wa_64_digit_key.trim()," in s


def test_payload_type_declares_new_fields():
    s = TYPES.read_text()
    assert "authorized_actions?: string[];" in s
    assert "whatsapp_64_digit_key?: string;" in s
