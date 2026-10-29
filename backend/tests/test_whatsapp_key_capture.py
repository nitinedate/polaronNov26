"""WhatsApp key capture — read-only, root-present-only, fully logged."""
from __future__ import annotations

import json
from pathlib import Path

from app.services.mobile_acquire.whatsapp_device_driver import DeviceStep
from app.services.mobile_acquire.whatsapp_key_capture import (
    KEY_REMOTE_PATHS,
    LIVE_DB_REMOTE_PATHS,
    capture_whatsapp_key,
    write_capture_log,
)

KEY158 = bytes(126) + bytes(range(32))  # 158-byte files/key, AES at offset 126
SQLITE = b"SQLite format 3\x00" + b"\x00" * 200


class FakeDriver:
    """Scripted device: declares root and serves specific remote files via _root_cat."""

    def __init__(self, *, root="su", files=None, device_ok=True, escalation_guard=None):
        self.root = root
        self.files = files or {}
        self.device_ok = device_ok
        self.calls: list[str] = []
        self.escalation_guard = escalation_guard

    def confirm_device(self):
        return DeviceStep("adb_devices", self.device_ok, "ok" if self.device_ok else "unauthorized")

    def root_mode(self):
        return self.root

    def _root_cat(self, mode, remote, dest: Path, *, timeout):
        self.calls.append(remote)
        if self.escalation_guard:
            self.escalation_guard(mode, remote)
        data = self.files.get(remote)
        if data is None:
            return False
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return True


def test_captures_and_stages_key_where_ladder_looks(tmp_path):
    drv = FakeDriver(files={KEY_REMOTE_PATHS[0]: KEY158, LIVE_DB_REMOTE_PATHS[0]: SQLITE})
    res = capture_whatsapp_key(out_dir=tmp_path, driver=drv)
    assert res.ok and res.root_available and res.root_mode == "su"
    # Key is staged under the decrypt ladder's search dir.
    ladder = tmp_path / "whatsapp_decrypt_agent" / "live_private"
    staged = list(ladder.rglob("key"))
    assert staged, "key must be staged where the ladder looks"
    # Mirrored to the private-apps namespace too.
    assert (tmp_path / "private_apps" / "com.whatsapp" / "files" / "key").is_file()
    # Live DB captured.
    assert res.live_db_files and res.live_db_files[0]["size_bytes"] == len(SQLITE)


def test_decrypt_ladder_finds_the_staged_key(tmp_path):
    # End-to-end: stage the key, then build a crypt14 and decrypt it via the agent.
    import sqlite3
    from app.services.mobile_forensic.whatsapp_crypt import _encrypt_fixture, parse_key_material
    from app.services.mobile_acquire.whatsapp_decrypt_agent import WhatsAppDecryptAgent, DecryptAgentRequest
    from app.services.mobile_acquire.whatsapp_device_driver import DeviceStep as DS

    secret = bytes(range(1, 33))
    keyfile = bytes(126) + secret
    dbp = tmp_path / "m.db"; c = sqlite3.connect(dbp)
    c.execute("CREATE TABLE messages(_id INTEGER PRIMARY KEY, data TEXT)")
    c.executemany("INSERT INTO messages(data) VALUES(?)", [("hi",), ("bye",)]); c.commit(); c.close()
    plain = dbp.read_bytes()
    crypt14 = _encrypt_fixture(plain, parse_key_material(keyfile), container="crypt14", iv=bytes(range(16)))

    # 1) capture stages the key
    drv = FakeDriver(files={KEY_REMOTE_PATHS[0]: keyfile})
    capture_whatsapp_key(out_dir=tmp_path, driver=drv, include_live_db=False)

    # 2) a crypt14 backup is present in the same tree
    bdir = tmp_path / "whatsapp_decrypt_agent" / "public" / "com.whatsapp" / "WhatsApp" / "Databases"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "msgstore.db.crypt14").write_bytes(crypt14)

    # 3) the agent's ladder decrypts using the staged key (no device needed now)
    class _NoDev:
        def confirm_device(self): return DS("adb_devices", True, "ok")
        def whatsapp_installed(self, p="com.whatsapp"): return True
        def pull_public_tree(self, remote, dest, *, timeout=1800): return DS("pull_public", True, "noop")
        def pull_live_private_db(self, d): return DS("live_private_db", False, "no root")
    agent = WhatsAppDecryptAgent(driver=_NoDev())
    res = agent.run(DecryptAgentRequest(out_dir=tmp_path / "whatsapp_decrypt_agent", include_business=False,
                                        try_live_private_db=False))
    assert len(res.decrypted_databases) == 1
    assert res.decrypted_databases[0]["rung"] == "existing_backup_plus_extracted_device_key"


def test_no_root_records_gap_and_never_escalates(tmp_path):
    seen = {"escalated": False}

    def guard(mode, remote):
        # If capture ever tried to read a private path with no root, that's a bug.
        seen["escalated"] = True

    drv = FakeDriver(root=None, files={}, escalation_guard=guard)
    res = capture_whatsapp_key(out_dir=tmp_path, driver=drv)
    assert res.root_available is False and res.ok is False
    assert seen["escalated"] is False  # no private reads attempted without root
    assert drv.calls == []             # root gate blocked all reads
    assert any("not root" in l.lower() or "does NOT root" in l for l in res.limitations)
    # Every audit entry records escalation was not attempted.
    rc = [a for a in res.audit if a["action"] == "root_check"]
    assert rc and rc[0]["escalation_attempted"] is False


def test_implausible_key_size_is_rejected(tmp_path):
    drv = FakeDriver(files={KEY_REMOTE_PATHS[0]: b"x" * 8})  # too short to be a key
    res = capture_whatsapp_key(out_dir=tmp_path, driver=drv, include_live_db=False)
    assert res.key_files == []
    assert any(a.get("note", "").startswith("implausible") for a in res.audit)


def test_logs_are_complete_and_omit_raw_key_bytes(tmp_path):
    drv = FakeDriver(files={KEY_REMOTE_PATHS[0]: KEY158})
    res = capture_whatsapp_key(out_dir=tmp_path, driver=drv, include_live_db=False)
    log_path = write_capture_log(res, tmp_path)
    text = log_path.read_text()
    # The log records command, target, size, sha256 and outcome...
    assert "exec-out cat" in text and "sha256" in text and "size_bytes" in text
    # ...but never the raw key bytes.
    assert KEY158.hex() not in text
    assert "\x00\x01\x02\x03" not in text
    # Audit covers the full sequence.
    actions = [a["action"] for a in res.audit]
    for expected in ("start", "adb_devices", "root_check", "read_attempt", "read_result", "done"):
        assert expected in actions


def test_device_unreachable_is_a_clean_skip(tmp_path):
    drv = FakeDriver(device_ok=False)
    res = capture_whatsapp_key(out_dir=tmp_path, driver=drv)
    assert res.ok is False and drv.calls == []
    assert any("not reachable" in l for l in res.limitations)
