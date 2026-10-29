from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_runtime_installs_requested_whatsapp_tools():
    req = read("backend/requirements.txt")
    assert "whatsapp-chat-exporter[android_backup]==0.13.0" in req
    assert "wa-crypt-tools==0.1.0" in req
    assert "wa-crypt-tools>=0.2.0" not in req


def test_derivation_uses_external_tools_only_as_authorized_fallback():
    src = read("backend/app/services/mobile_forensic/whatsapp_derivation.py")
    assert "decrypt_with_external_tools" in src
    assert "plain is None and raw is not None and candidates" in src
    assert "DECRYPTING {path} via" in src
    assert "DECRYPTED {path} via" in src
    assert '"deleted_recovery_pending"' in src


def test_external_decryptor_never_uses_shell_or_bruteforce():
    src = read("backend/app/services/mobile_forensic/whatsapp_external_tools.py")
    assert '[wtsexporter, "-a", "-k", str(key_path), "-b", str(enc_path)]' in src
    assert '[wadecrypt, str(key_path), str(enc_path), str(out_path)]' in src
    assert "shell=True" not in src
    assert "bruteforce" not in src.lower()
    assert "WHATSAPP_EXTERNAL_TOOL_TIMEOUT_SEC" in src


def test_wadecrypt_fallback_returns_validated_sqlite(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / "backend"))
    from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate
    from app.services.mobile_forensic.whatsapp_external_tools import decrypt_with_external_tools

    sqlite = b"SQLite format 3\x00" + b"\x00" * 128

    def which(name):
        return None if name == "wtsexporter" else "/usr/local/bin/wadecrypt"

    class Done:
        returncode = 0
        stdout = b"ok"
        stderr = b""

    def run(cmd, **kwargs):
        Path(cmd[-1]).write_bytes(sqlite)
        return Done()

    with patch("app.services.mobile_forensic.whatsapp_external_tools.shutil.which", side_effect=which), \
         patch("app.services.mobile_forensic.whatsapp_external_tools.subprocess.run", side_effect=run):
        plain, diag = decrypt_with_external_tools(
            b"ciphertext", [WhatsAppKeyCandidate(bytes(range(32)), "qa-key")],
            source_path="WhatsApp/Databases/msgstore.db.crypt15",
        )
    assert plain == sqlite
    assert diag["tool"] == "wadecrypt"
    assert diag["payload_kind"] == "sqlite"
    assert diag["key_source"] == "qa-key"


def test_materialized_decrypted_db_also_runs_freelist_recovery():
    src = read("backend/app/services/mobile_forensic/parsers/messaging.py")
    marker = "WHATSAPP_DELETED_RECOVERY_ENABLED"
    assert marker in src
    tail = src[src.index(marker):]
    assert "iter_freelist_residuals(data, item, context, companions=companions or None)" in tail


def test_historical_backup_diff_is_candidate_not_claimed_deletion():
    src = read("backend/app/services/mobile_forensic/whatsapp_deleted_recovery.py")
    assert "historical_backup_diff" in src
    assert "absence_does_not_prove_user_deletion" in src
    assert "state='backup_historical'" in src
    assert "state='allocated'" in src
    assert "'fragment','FRAGMENT'" in src


def test_pipeline_runs_historical_deleted_candidate_recovery_before_rag():
    src = read("backend/app/services/mobile_forensic/pipeline.py")
    recover = src.index("promote_historical_missing_candidates")
    rag = src.index("index_mobile_artifacts_for_rag")
    assert recover < rag
    assert "whatsapp_historical_deleted_candidates" in src


def test_deleted_whatsapp_ui_includes_fragment_and_residual_states():
    src = read("backend/app/services/whatsapp_evidence_browse.py")
    assert '"fragment"' in src
    assert '"freelist_candidate"' in src
    assert '"wal_recovered"' in src
    assert '"journal_recovered"' in src


def test_whatsapp_parser_reads_wal_and_journal_companions_for_deleted_candidates():
    src = read("backend/app/services/mobile_forensic/parsers/messaging.py")
    modern = read("backend/app/services/mobile_forensic/parsers/whatsapp_modern.py")
    assert "WHATSAPP_DELETED_RECOVERY_ENABLED" in src
    assert '("-wal", "wal")' in src and '("-journal", "journal")' in src
    assert "companions=companions or None" in src
    assert "source_component" in modern
    assert "sqlite_" in modern and "_candidate" in modern
