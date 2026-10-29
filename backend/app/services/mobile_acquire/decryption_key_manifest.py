"""Write a private, deterministic decryption-key sidecar after mobile extraction.

Only already-acquired/authorized material is exported. Nothing is brute-forced or
recovered from ciphertext. Secret values are never logged. The sidecar is written
next to the portable packages so later parsers can reuse exactly the same inputs.
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_MANIFEST_NAME = "decryption_keys.txt"
_MAX_KEY_FILE_BYTES = 1024 * 1024
_KEY_NAMES = {"key", "encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"}
_KEYBAG_NAMES = {"systembag.kb", "escrowbag", "keybag", "backup_keybag"}


def _safe_write_private(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return path


def _iter_candidate_key_files(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return
    seen = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
        for name in files:
            seen += 1
            if seen > 100_000:
                return
            p = Path(current) / name
            low = str(p).replace("\\", "/").lower()
            n = name.lower()
            if p.is_symlink():
                continue
            if n in _KEY_NAMES and (n != "key" or "whatsapp" in low):
                yield p
                continue
            if n in _KEYBAG_NAMES or "/keybags/" in low:
                yield p




def _scan_decryption_readiness(root: Path | None, platform: str, supplied: dict[str, Any], candidate_paths: list[Path]) -> dict[str, Any]:
    """Presence-only readiness assessment for the *existing* acquisition.

    This never derives secrets from ciphertext and never logs secret values.  It is
    intentionally conservative: re-acquisition is recommended only when the
    currently registered acquisition lacks material needed to access WhatsApp data.
    """
    plat = str(platform or "").strip().lower()
    found = {
        "WHATSAPP_DATABASE_FOUND": False,
        "WHATSAPP_WAL_FOUND": False,
        "WHATSAPP_ENCRYPTED_BACKUP_FOUND": False,
        "WHATSAPP_APP_CONTAINER_FOUND": False,
        "WHATSAPP_KEY_FOUND": bool(str(supplied.get("whatsapp_key_hex") or "").strip()),
        "IOS_CHATSTORAGE_FOUND": False,
        "IOS_CHATSTORAGE_WAL_FOUND": False,
        "IOS_APP_CONTAINER_FOUND": False,
        "IOS_KEYBAG_MATERIAL_FOUND": any(p.name.lower() in _KEYBAG_NAMES or "/keybags/" in str(p).replace("\\", "/").lower() for p in candidate_paths),
        "BACKUP_CREDENTIAL_AVAILABLE": bool(str(supplied.get("ios_backup_password") or supplied.get("backup_password") or supplied.get("keychain_password") or "").strip()),
    }
    if candidate_paths:
        found["WHATSAPP_KEY_FOUND"] = found["WHATSAPP_KEY_FOUND"] or any(
            p.name.lower() in _KEY_NAMES for p in candidate_paths
        )
    if root and Path(root).is_dir():
        seen = 0
        for current, dirs, files in os.walk(Path(root), followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            current_norm = str(current).replace("\\", "/").lower()
            for name in files:
                seen += 1
                if seen > 250_000:
                    break
                low_name = name.lower()
                full = f"{current_norm}/{low_name}"
                if low_name in {"msgstore.db", "wa.db", "chatstorage.sqlite", "messages.db"}:
                    found["WHATSAPP_DATABASE_FOUND"] = True
                if low_name in {"msgstore.db-wal", "wa.db-wal", "chatstorage.sqlite-wal", "messages.db-wal"}:
                    found["WHATSAPP_WAL_FOUND"] = True
                if "msgstore" in low_name and (".crypt" in low_name or low_name.endswith(".enc")):
                    found["WHATSAPP_ENCRYPTED_BACKUP_FOUND"] = True
                if low_name == "chatstorage.sqlite":
                    found["IOS_CHATSTORAGE_FOUND"] = True
                if low_name == "chatstorage.sqlite-wal":
                    found["IOS_CHATSTORAGE_WAL_FOUND"] = True
                if any(tok in full for tok in ("/com.whatsapp/", "/com.whatsapp.w4b/", "appdomain-com.whatsapp.whatsapp", "appdomain-net.whatsapp.whatsapp")):
                    found["WHATSAPP_APP_CONTAINER_FOUND"] = True
                if "appdomain-com.whatsapp.whatsapp" in full or "appdomain-net.whatsapp.whatsapp" in full:
                    found["IOS_APP_CONTAINER_FOUND"] = True
            if seen > 250_000:
                break

    missing: list[str] = []
    if plat.startswith("android"):
        # Plain private DB is immediately parseable. Encrypted msgstore requires an
        # authorized key captured from the same acquisition/device context.
        ready = bool(found["WHATSAPP_DATABASE_FOUND"] or (found["WHATSAPP_ENCRYPTED_BACKUP_FOUND"] and found["WHATSAPP_KEY_FOUND"]))
        if found["WHATSAPP_ENCRYPTED_BACKUP_FOUND"] and not found["WHATSAPP_KEY_FOUND"]:
            missing.append("WHATSAPP_KEY_MATERIAL")
        if not found["WHATSAPP_DATABASE_FOUND"] and not found["WHATSAPP_ENCRYPTED_BACKUP_FOUND"]:
            missing.append("WHATSAPP_DATABASE_OR_BACKUP")
        reacquire = bool(missing and not found["WHATSAPP_APP_CONTAINER_FOUND"])
    elif plat.startswith("ios"):
        # A directly acquired ChatStorage DB is parseable without backup-password
        # derivation. Otherwise protected backup/container access needs authorized
        # credential/keybag material.
        ready = bool(found["IOS_CHATSTORAGE_FOUND"] or (found["IOS_APP_CONTAINER_FOUND"] and (found["BACKUP_CREDENTIAL_AVAILABLE"] or found["IOS_KEYBAG_MATERIAL_FOUND"])))
        if not found["IOS_CHATSTORAGE_FOUND"]:
            missing.append("CHATSTORAGE_OR_UNLOCKED_APP_CONTAINER")
        if found["IOS_APP_CONTAINER_FOUND"] and not (found["BACKUP_CREDENTIAL_AVAILABLE"] or found["IOS_KEYBAG_MATERIAL_FOUND"] or found["IOS_CHATSTORAGE_FOUND"]):
            missing.append("IOS_BACKUP_CREDENTIAL_OR_KEYBAG")
        reacquire = bool(not ready and not found["IOS_APP_CONTAINER_FOUND"])
    else:
        ready = bool(found["WHATSAPP_DATABASE_FOUND"] or found["IOS_CHATSTORAGE_FOUND"])
        if not ready:
            missing.append("PLATFORM_SPECIFIC_WHATSAPP_MATERIAL")
        reacquire = False

    found["WHATSAPP_DECRYPTION_READY"] = ready
    found["REACQUISITION_RECOMMENDED"] = reacquire
    found["MISSING_REQUIREMENTS"] = ",".join(dict.fromkeys(missing))
    return found



def read_decryption_key_manifest(path: Path) -> dict[str, str]:
    """Read an authorized key=value sidecar without logging secret values."""
    path = Path(path)
    if not path.is_file() or path.name.lower() != _MANIFEST_NAME:
        return {}
    out: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().upper()
            if key and len(key) <= 128:
                out[key] = value.strip()
    except OSError:
        return {}
    return out

def find_decryption_key_manifest(root: Path | None) -> Path | None:
    """Find only the case-export sidecar; never crawl outside the supplied root."""
    if root is None:
        return None
    root = Path(root)
    if root.is_file():
        direct = root.parent / _MANIFEST_NAME
        return direct if direct.is_file() else None
    direct = root / _MANIFEST_NAME
    if direct.is_file():
        return direct
    try:
        for child in root.iterdir():
            if child.is_dir() and (child / _MANIFEST_NAME).is_file():
                return child / _MANIFEST_NAME
    except OSError:
        return None
    return None

def write_decryption_key_manifest(
    export_dir: Path,
    *,
    original: Path | None = None,
    platform: str = "",
    supplied_keys: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create ``05_Exports/<run>/decryption_keys.txt``.

    Values are key=value lines so the file is machine-readable without a custom
    parser. Binary material is base64 encoded. The function returns presence and
    hashes only; secret values never leave the file via its return value.
    """
    export_dir = Path(export_dir)
    supplied = supplied_keys if isinstance(supplied_keys, dict) else {}
    lines = [
        "# Aetheris/Polaron authorized decryption material",
        "# PRIVATE FORENSIC MATERIAL - restrict access; values are not written to application logs.",
        "FORMAT_VERSION=1",
        f"GENERATED_UTC={datetime.now(timezone.utc).isoformat()}",
        f"PLATFORM={str(platform or '').strip().lower()}",
    ]
    secret_count = 0
    secret_names: list[str] = []
    candidate_paths = list(_iter_candidate_key_files(Path(original))) if original else []
    try:
        from app.services.mobile_forensic.key_intake import whatsapp_key_path_priority
        candidate_paths.sort(key=lambda p: whatsapp_key_path_priority(str(p)))
    except Exception:
        candidate_paths.sort(key=lambda p: str(p).lower())

    # If acquisition discovered a valid WhatsApp key in any supported location
    # (including Android/data/com.whatsapp), promote the highest-priority valid
    # candidate into the machine-readable top-level fields unless the examiner
    # explicitly supplied a key. The full material records below still preserve
    # every unique candidate and its provenance.
    discovered_key_hex = None
    discovered_key_source = None
    if not str(supplied.get("whatsapp_key_hex") or "").strip():
        for candidate_path in candidate_paths:
            if candidate_path.name.lower() not in _KEY_NAMES:
                continue
            try:
                raw = candidate_path.read_bytes()
                from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
                parsed = parse_key_material(raw)
                if parsed:
                    discovered_key_hex = parsed.raw32.hex()
                    try:
                        discovered_key_source = str(candidate_path.relative_to(Path(original))).replace("\\", "/")
                    except Exception:
                        discovered_key_source = str(candidate_path).replace("\\", "/")
                    break
            except Exception:
                continue

    mapping = (
        ("WHATSAPP_KEY_HEX", supplied.get("whatsapp_key_hex") or discovered_key_hex),
        ("WHATSAPP_LEGACY_ACCOUNT", supplied.get("whatsapp_legacy_account")),
        ("SIGNAL_DB_KEY_HEX", supplied.get("signal_db_key_hex")),
        ("SIGNAL_PASSPHRASE", supplied.get("signal_passphrase")),
        ("IOS_BACKUP_PASSWORD", supplied.get("ios_backup_password") or supplied.get("backup_password")),
        ("KEYCHAIN_PASSWORD", supplied.get("keychain_password")),
        ("ADB_BACKUP_PASSWORD", supplied.get("adb_backup_password")),
    )
    for key, value in mapping:
        if value is None or not str(value).strip():
            continue
        # Keep each logical value on one line and preserve exact printable content.
        clean = str(value).replace("\r", "").replace("\n", "\\n")
        lines.append(f"{key}={clean}")
        secret_count += 1
        secret_names.append(key)
    if discovered_key_source:
        lines.append(f"WHATSAPP_KEY_SOURCE_PATH={discovered_key_source}")

    material_index = 0
    seen_material_sha256: dict[str, str] = {}
    duplicate_index = 0
    if original:
        for path in candidate_paths:
            try:
                size = path.stat().st_size
                if size <= 0 or size > _MAX_KEY_FILE_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            digest = hashlib.sha256(raw).hexdigest()
            rel = str(path)
            try:
                rel = str(path.relative_to(Path(original))).replace("\\", "/")
            except Exception:
                rel = str(path).replace("\\", "/")
            if digest in seen_material_sha256:
                # Same key may appear in more than one exported path. Preserve the
                # alternate location without duplicating the secret material.
                duplicate_index += 1
                lines.append(f"KEY_DUPLICATE_SOURCE_{duplicate_index:03d}={rel}")
                continue
            seen_material_sha256[digest] = rel
            material_index += 1
            prefix = f"KEY_MATERIAL_{material_index:03d}"
            kind = "binary_key_material"
            n = path.name.lower()
            if n in _KEY_NAMES:
                kind = "whatsapp_key_file"
                try:
                    from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
                    parsed = parse_key_material(raw)
                    if parsed:
                        lines.append(f"{prefix}_WHATSAPP_KEY_HEX={parsed.raw32.hex()}")
                except Exception:
                    pass
            elif n in _KEYBAG_NAMES or "/keybags/" in str(path).replace("\\", "/").lower():
                kind = "ios_keybag_or_manifest_material"
            lines.extend([
                f"{prefix}_TYPE={kind}",
                f"{prefix}_SOURCE_PATH={rel}",
                f"{prefix}_SHA256={digest}",
                f"{prefix}_SIZE_BYTES={len(raw)}",
                f"{prefix}_BASE64={base64.b64encode(raw).decode('ascii')}",
            ])
            secret_count += 1
            secret_names.append(prefix)

    readiness = _scan_decryption_readiness(Path(original) if original else None, platform, supplied, candidate_paths)
    lines.append("")
    lines.append("# Existing-acquisition decryption readiness (presence/status only)")
    for key in (
        "WHATSAPP_DATABASE_FOUND", "WHATSAPP_WAL_FOUND", "WHATSAPP_ENCRYPTED_BACKUP_FOUND",
        "WHATSAPP_APP_CONTAINER_FOUND", "WHATSAPP_KEY_FOUND", "IOS_CHATSTORAGE_FOUND",
        "IOS_CHATSTORAGE_WAL_FOUND", "IOS_APP_CONTAINER_FOUND", "IOS_KEYBAG_MATERIAL_FOUND",
        "BACKUP_CREDENTIAL_AVAILABLE", "WHATSAPP_DECRYPTION_READY", "REACQUISITION_RECOMMENDED",
    ):
        lines.append(f"{key}={str(bool(readiness.get(key))).lower()}")
    lines.append(f"MISSING_REQUIREMENTS={str(readiness.get('MISSING_REQUIREMENTS') or '')}")
    lines.append(f"MATERIAL_COUNT={material_index}")
    lines.append(f"SECRET_ENTRY_COUNT={secret_count}")
    path = _safe_write_private(export_dir / _MANIFEST_NAME, "\n".join(lines) + "\n")
    return {
        "path": str(path),
        "filename": path.name,
        "secret_entry_count": secret_count,
        "binary_material_count": material_index,
        "secret_names": secret_names,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "readiness": readiness,
    }
