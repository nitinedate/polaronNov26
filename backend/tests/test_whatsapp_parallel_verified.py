"""Verify independent WhatsApp worker fails closed before attempting decryption."""
import hashlib
from app.services.mobile_forensic.whatsapp_derivation import _decrypt_verified_source

def test_missing_payload_is_blocked():
    plain, diag, _ = _decrypt_verified_source(("msgstore.db.crypt14", 4, None, None), [], None)
    assert plain is None and diag["reason"] == "source_unavailable"

def test_size_mismatch_is_blocked():
    plain, diag, _ = _decrypt_verified_source(("msgstore.db.crypt14", 100, b"test", None), [], None)
    assert plain is None and diag["reason"] == "source_size_mismatch"

def test_hash_mismatch_is_blocked():
    plain, diag, _ = _decrypt_verified_source(("msgstore.db.crypt14", 4, b"test", "0" * 64), [], None)
    assert plain is None and diag["reason"] == "source_hash_mismatch"

def test_oversized_payload_is_blocked_without_reading():
    from app.services.mobile_forensic.whatsapp_crypt import MAX_PAYLOAD_BYTES
    plain, diag, _ = _decrypt_verified_source(("msgstore.db.crypt15", MAX_PAYLOAD_BYTES + 1, None, None), [], None)
    assert plain is None and diag["reason"] == "source_size_limit"
