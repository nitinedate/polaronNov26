"""WhatsApp decrypt agent — behaviour without a device or real ADB.

A FakeDriver stands in for the device. Decryption uses the project's real
``whatsapp_crypt`` encoder to build a genuine crypt15 backup, so the
read-only-pull → decrypt → msgstore.db path is exercised end to end.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.services.mobile_acquire.whatsapp_decrypt_agent import (
    AUTH_ALLOW_DEVICE_MODIFICATION,
    AUTH_GENERATE_KEY_AND_BACKUP,
    DecryptAgentRequest,
    WhatsAppDecryptAgent,
)
from app.services.mobile_acquire.whatsapp_device_driver import DeviceStep, normalize_64_digit_key

SQLITE_HEADER = b"SQLite format 3\x00"
KEY_HEX = "3e4602d7137cacac8774996f106710245f3ec6a086ae964ae0058507236decc2"


def _synthetic_msgstore() -> bytes:
    # A minimal-but-real SQLite file so looks_like_sqlite() and quick_check pass.
    import sqlite3
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        path = tmp.name
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)")
    conn.executemany("INSERT INTO messages (body) VALUES (?)", [("hi",), ("there",), ("bye",)])
    conn.commit()
    conn.close()
    data = Path(path).read_bytes()
    Path(path).unlink(missing_ok=True)
    assert data[:16] == SQLITE_HEADER
    return data


def _crypt15(plaintext: bytes, key_hex: str) -> bytes:
    from app.services.mobile_forensic.whatsapp_crypt import _encrypt_fixture, parse_key_material

    km = parse_key_material(key_hex)
    return _encrypt_fixture(plaintext, km, container="crypt15", iv=bytes(range(16)))


class FakeDriver:
    """Scripted stand-in for WhatsAppDeviceDriver. Writes files the agent reads."""

    def __init__(self, out_dir: Path, *, backup: bytes | None, key_file: bytes | None = None,
                 device_ok: bool = True, installed: bool = True,
                 new_backup_on_create: bytes | None = None,
                 backup_ext: str = "crypt15", live_db: bytes | None = None):
        self.out_dir = out_dir
        self.backup = backup
        self.key_file = key_file
        self.device_ok = device_ok
        self.installed = installed
        self.new_backup_on_create = new_backup_on_create
        self.backup_ext = backup_ext
        self.live_db = live_db
        self.calls: list[str] = []
        self._state_backups: list[dict] = []

    def confirm_device(self):
        self.calls.append("confirm_device")
        return DeviceStep("adb_devices", self.device_ok,
                          "ok" if self.device_ok else "Device state is 'unauthorized'.")

    def whatsapp_installed(self, package="com.whatsapp"):
        return self.installed and package == "com.whatsapp"

    def pull_public_tree(self, remote, dest: Path, *, timeout=1800):
        self.calls.append(f"pull:{remote}")
        dest.mkdir(parents=True, exist_ok=True)
        db_dir = dest / "WhatsApp" / "Databases"
        db_dir.mkdir(parents=True, exist_ok=True)
        wrote = 0
        if self.backup is not None and remote.endswith("com.whatsapp"):
            (db_dir / f"msgstore.db.{self.backup_ext}").write_bytes(self.backup)
            wrote += 1
        if self.key_file is not None and remote.endswith("com.whatsapp"):
            keydir = dest / "files"
            keydir.mkdir(parents=True, exist_ok=True)
            (keydir / "key").write_bytes(self.key_file)
            wrote += 1
        return DeviceStep("pull_public", True, f"pulled {remote}", {"remote": remote, "files": wrote})

    def list_backups(self):
        return list(self._state_backups)

    def capture_backup_screen_state(self):
        return {"backups": list(self._state_backups), "databases_dir_mtime": "100"}

    def pull_live_private_db(self, dest_dir):
        self.calls.append("live_private_db")
        if self.live_db is None:
            return DeviceStep("live_private_db", False, "no existing root")
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "data_data_com.whatsapp_databases_msgstore.db").write_bytes(self.live_db)
        return DeviceStep("live_private_db", True, "read via su", {"mode": "su"})

    def open_backup_settings(self):
        # Simulate the examiner creating the backup on the device.
        if self.new_backup_on_create is not None:
            self.backup = self.new_backup_on_create
            self.backup_ext = "crypt15"
            self._state_backups = [{"remote": ".../msgstore.db.crypt15", "name": "msgstore.db.crypt15"}]
        return DeviceStep("open_backup_settings", True, "opened")


# ----------------------------------------------------------------- unit bits
def test_normalize_64_digit_key():
    assert normalize_64_digit_key(KEY_HEX) == KEY_HEX
    assert normalize_64_digit_key(KEY_HEX.upper()) == KEY_HEX
    spaced = " ".join(KEY_HEX[i:i + 4] for i in range(0, 64, 4))
    assert normalize_64_digit_key(spaced) == KEY_HEX
    assert normalize_64_digit_key("not-a-key") is None
    assert normalize_64_digit_key(KEY_HEX[:-1]) is None  # 63 chars


# ----------------------------------------------------------------- read-only
def test_readonly_pull_and_decrypt_with_intake_key(tmp_path):
    plain = _synthetic_msgstore()
    backup = _crypt15(plain, KEY_HEX)
    driver = FakeDriver(tmp_path, backup=backup)
    agent = WhatsAppDecryptAgent(driver=driver)
    req = DecryptAgentRequest(out_dir=tmp_path, intake_key_candidates=(KEY_HEX,), include_business=False)
    res = agent.run(req)

    assert res.ok
    assert res.device_modified is False
    assert "pull:/sdcard/Android/media/com.whatsapp" in driver.calls
    assert len(res.decrypted_databases) == 1
    out = Path(res.decrypted_databases[0]["database"])
    assert out.read_bytes()[:16] == SQLITE_HEADER
    assert res.decrypted_databases[0]["sha256"] == hashlib.sha256(plain).hexdigest()


def test_decrypt_uses_device_key_file_when_no_intake_key(tmp_path):
    # crypt15 needs the 64-digit root key, not files/key; use a hex key file.
    plain = _synthetic_msgstore()
    backup = _crypt15(plain, KEY_HEX)
    driver = FakeDriver(tmp_path, backup=backup, key_file=KEY_HEX.encode())
    agent = WhatsAppDecryptAgent(driver=driver)
    res = agent.run(DecryptAgentRequest(out_dir=tmp_path, include_business=False))
    assert res.ok and len(res.decrypted_databases) == 1


def test_backup_without_matching_key_is_blocked_not_invented(tmp_path):
    plain = _synthetic_msgstore()
    backup = _crypt15(plain, KEY_HEX)
    driver = FakeDriver(tmp_path, backup=backup)
    agent = WhatsAppDecryptAgent(driver=driver)
    wrong = "a" * 64
    res = agent.run(DecryptAgentRequest(out_dir=tmp_path, intake_key_candidates=(wrong,), include_business=False))
    assert res.ok  # no hard error
    assert res.decrypted_databases == []
    # The ladder records a blocked rung and a precise no-touch gap.
    assert any(x["result"] == "blocked" for x in res.ladder)
    assert any("No read-only path yielded" in lim for lim in res.limitations)
    assert res.read_only is True


def test_no_device_access_skips_agent(tmp_path):
    driver = FakeDriver(tmp_path, backup=None, device_ok=False)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(out_dir=tmp_path))
    assert res.ok is False
    assert driver.calls == ["confirm_device"]


def test_whatsapp_not_installed_is_a_clean_skip(tmp_path):
    driver = FakeDriver(tmp_path, backup=None, installed=False)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(out_dir=tmp_path, include_business=False))
    assert res.ok is True
    assert any("not installed" in lim for lim in res.limitations)


# ----------------------------------------------------------- device-modifying
def test_device_modifying_backup_requires_both_tokens(tmp_path):
    # Backup action alone must NOT modify the device (fail-closed override).
    driver = FakeDriver(tmp_path, backup=None)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(
        out_dir=tmp_path, authorized_actions=(AUTH_GENERATE_KEY_AND_BACKUP,),
        supplied_64_digit_key=KEY_HEX, include_business=False))
    assert res.device_modified is False
    assert res.read_only is True
    assert any("allow_device_modification" in lim for lim in res.limitations)


def test_no_authorization_stays_read_only(tmp_path):
    driver = FakeDriver(tmp_path, backup=None)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(
        out_dir=tmp_path, include_business=False))
    assert res.device_modified is False and res.read_only is True


def test_authorized_backup_creation_records_custody_and_decrypts(tmp_path):
    plain = _synthetic_msgstore()
    new_backup = _crypt15(plain, KEY_HEX)
    # Device starts with no backup; the "create" step produces one.
    driver = FakeDriver(tmp_path, backup=None, new_backup_on_create=new_backup)
    agent = WhatsAppDecryptAgent(driver=driver)
    req = DecryptAgentRequest(
        out_dir=tmp_path,
        authorized_actions=(AUTH_GENERATE_KEY_AND_BACKUP, AUTH_ALLOW_DEVICE_MODIFICATION),
        supplied_64_digit_key=KEY_HEX,
        include_business=False,
    )
    res = agent.run(req)
    assert res.device_modified is True
    assert res.read_only is False
    # The manual on-device steps are recorded for the examiner/report.
    manual = [s for s in res.steps if s.get("name") == "on_device_manual_steps"]
    assert manual and manual[0]["manual_steps"]
    # Custody shows a before/after device-write record.
    assert any("Authorized on-device action" in c["detail"] for c in res.custody)
    assert len(res.decrypted_databases) == 1


def test_authorized_without_key_records_gap(tmp_path):
    driver = FakeDriver(tmp_path, backup=None)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(
        out_dir=tmp_path,
        authorized_actions=(AUTH_GENERATE_KEY_AND_BACKUP, AUTH_ALLOW_DEVICE_MODIFICATION),
        include_business=False))
    assert res.device_modified is True
    assert any("no valid 64-digit key" in lim for lim in res.limitations)


def test_manifest_has_no_raw_key_bytes(tmp_path):
    plain = _synthetic_msgstore()
    driver = FakeDriver(tmp_path, backup=_crypt15(plain, KEY_HEX))
    agent = WhatsAppDecryptAgent(driver=driver)
    req = DecryptAgentRequest(out_dir=tmp_path, intake_key_candidates=(KEY_HEX,), include_business=False)
    res = agent.run(req)
    manifest = agent.write_manifest(req, res)
    text = manifest.read_text()
    assert KEY_HEX not in text  # the key is never serialized into the manifest


# ------------------------------------------------- read-only ladder (realistic)
# These use DIFFERENT random secrets for files/key vs the crypt15 root key, as on
# a real device, so the version/key matrix is exercised honestly.
FILES_KEY_SECRET = "11" * 32
ROOT_KEY_SECRET = "22" * 32


def _keyfile158(secret_hex: str) -> bytes:
    return bytes(126) + bytes.fromhex(secret_hex)  # AES secret at offset 126


def _crypt(plaintext: bytes, container: str, key_hex: str) -> bytes:
    from app.services.mobile_forensic.whatsapp_crypt import _encrypt_fixture, parse_key_material
    return _encrypt_fixture(plaintext, parse_key_material(key_hex), container=container, iv=bytes(range(16)))


def test_rung2_crypt14_decrypts_with_extracted_device_key_no_generation(tmp_path):
    """crypt12/14 decrypt with the device's own files/key — no key generated, no device write."""
    plain = _synthetic_msgstore()
    backup = _crypt(plain, "crypt14", FILES_KEY_SECRET)
    driver = FakeDriver(tmp_path, backup=backup, key_file=_keyfile158(FILES_KEY_SECRET),
                        backup_ext="crypt14")
    res = WhatsAppDecryptAgent(driver=driver).run(
        DecryptAgentRequest(out_dir=tmp_path, include_business=False))  # no 64-digit key at all
    assert res.read_only is True and res.device_modified is False
    assert len(res.decrypted_databases) == 1
    assert res.decrypted_databases[0]["rung"] == "existing_backup_plus_extracted_device_key"


def test_crypt15_cannot_use_files_key_only_and_stays_read_only(tmp_path):
    """The user's idea confirmed impossible for crypt15: files/key does not open it."""
    plain = _synthetic_msgstore()
    backup = _crypt(plain, "crypt15", ROOT_KEY_SECRET)  # encrypted with the random root key
    driver = FakeDriver(tmp_path, backup=backup, key_file=_keyfile158(FILES_KEY_SECRET),
                        backup_ext="crypt15")
    res = WhatsAppDecryptAgent(driver=driver).run(
        DecryptAgentRequest(out_dir=tmp_path, include_business=False))
    assert res.decrypted_databases == []
    assert res.read_only is True and res.device_modified is False
    assert any(x["result"] == "blocked" for x in res.ladder)


def test_rung1_crypt15_decrypts_with_supplied_64digit_key(tmp_path):
    plain = _synthetic_msgstore()
    backup = _crypt(plain, "crypt15", ROOT_KEY_SECRET)
    driver = FakeDriver(tmp_path, backup=backup, backup_ext="crypt15")
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(
        out_dir=tmp_path, intake_key_candidates=(ROOT_KEY_SECRET,), include_business=False))
    assert len(res.decrypted_databases) == 1 and res.read_only is True
    assert res.decrypted_databases[0]["rung"] == "existing_backup_plus_supplied_64digit_key"


def test_rung3_live_private_db_via_existing_root(tmp_path):
    """Live plaintext msgstore.db read read-only when root is already present."""
    plain = _synthetic_msgstore()
    driver = FakeDriver(tmp_path, backup=None, live_db=plain)
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(out_dir=tmp_path, include_business=False))
    assert "live_private_db" in driver.calls
    assert len(res.decrypted_databases) == 1 and res.read_only is True
    assert res.decrypted_databases[0]["rung"] == "already_plaintext_sqlite"


def test_ladder_prefers_readonly_before_device_modification(tmp_path):
    """With an existing crypt14 + files/key AND the backup action authorized, the
    read-only rung wins and the device is never modified."""
    plain = _synthetic_msgstore()
    backup = _crypt(plain, "crypt14", FILES_KEY_SECRET)
    driver = FakeDriver(tmp_path, backup=backup, key_file=_keyfile158(FILES_KEY_SECRET),
                        backup_ext="crypt14", new_backup_on_create=_crypt(plain, "crypt15", ROOT_KEY_SECRET))
    res = WhatsAppDecryptAgent(driver=driver).run(DecryptAgentRequest(
        out_dir=tmp_path,
        authorized_actions=(AUTH_GENERATE_KEY_AND_BACKUP, AUTH_ALLOW_DEVICE_MODIFICATION),
        include_business=False))
    assert res.device_modified is False and res.read_only is True
    assert len(res.decrypted_databases) == 1
