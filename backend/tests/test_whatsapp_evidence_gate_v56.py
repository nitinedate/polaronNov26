from __future__ import annotations


def test_platform_specific_derived_path_acceptance():
    from app.services.mobile_forensic.whatsapp_derivation import _is_registered_decrypted_path

    assert _is_registered_decrypted_path("derived/mobile/android/whatsapp_decrypted/a/b/msgstore.db")
    assert _is_registered_decrypted_path("derived/mobile/ios/whatsapp_decrypted/a/b/ChatStorage.sqlite")
    assert _is_registered_decrypted_path("derived/whatsapp_decrypted/a/b/msgstore.db")  # legacy
    assert not _is_registered_decrypted_path("derived/mobile/android/other/msgstore.db")


def test_ios_gate_ready_when_chatstorage_exists(monkeypatch):
    from app.services.mobile_forensic import whatsapp_evidence_gate as gate
    import app.db.sql_helpers as sql
    import app.services.mobile_forensic.integrity as integrity

    monkeypatch.setattr(sql, "fetchall", lambda *a, **k: [
        {"file_path": "ios_backup/AppDomainGroup-net.whatsapp.WhatsApp.shared/ChatStorage.sqlite", "file_name": "ChatStorage.sqlite", "metadata": {}},
        {"file_path": "ios_backup/AppDomainGroup-net.whatsapp.WhatsApp.shared/ChatStorage.sqlite-wal", "file_name": "ChatStorage.sqlite-wal", "metadata": {}},
    ])
    monkeypatch.setattr(sql, "execute", lambda *a, **k: None)
    monkeypatch.setattr(integrity, "load_intake_keys_from_disk_source", lambda ds: {})
    out = gate._ios_gate(object(), "job-1", {})
    assert out["state"] == "ready"
    assert out["chatstorage_files"] == 1
    assert out["wal_or_journal_files"] == 1
    assert out["recovery_enabled"] is True


def test_ios_gate_does_not_guess_without_authorized_credential(monkeypatch):
    from app.services.mobile_forensic import whatsapp_evidence_gate as gate
    import app.db.sql_helpers as sql
    import app.services.mobile_forensic.integrity as integrity

    monkeypatch.setattr(sql, "fetchall", lambda *a, **k: [
        {"file_path": "ios_backup/WhatsApp/protected-chat.enc", "file_name": "protected-chat.enc", "metadata": {}},
        {"file_path": "ios_backup/Manifest.db", "file_name": "Manifest.db", "metadata": {}},
    ])
    monkeypatch.setattr(sql, "execute", lambda *a, **k: None)
    monkeypatch.setattr(integrity, "load_intake_keys_from_disk_source", lambda ds: {})
    out = gate._ios_gate(object(), "job-1", {})
    assert out["state"] == "credential_required"
    assert out["authorized_backup_credential_present"] is False


def test_android_crypt_derivation_is_not_applied_to_ios():
    from app.services.mobile_forensic.whatsapp_derivation import materialize_registered_whatsapp_backups

    out = materialize_registered_whatsapp_backups(object(), "job-1", platform="ios")
    assert out["state"] == "not_applicable_ios"
    assert out["encrypted_files"] == 0


def test_pipeline_runs_gate_before_inventory():
    from pathlib import Path
    import app.services.mobile_forensic.pipeline as pipeline

    text = Path(pipeline.__file__).read_text(encoding="utf-8")
    gate_pos = text.index("prepare_whatsapp_evidence(db, job_id")
    inventory_pos = text.index("items = inventory_from_job_artifacts(db, job_id)")
    assert gate_pos < inventory_pos


def test_serial_materialize_uses_mandatory_gate():
    from pathlib import Path
    import app.services.forensic_serial_stages as stages

    text = Path(stages.__file__).read_text(encoding="utf-8")
    assert "prepare_whatsapp_evidence" in text
    assert "WhatsApp evidence preparation" in text
