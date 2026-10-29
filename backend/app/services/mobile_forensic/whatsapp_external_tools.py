"""Controlled external WhatsApp backup decryptor fallbacks.

The in-house authenticated decoder remains primary.  This module is used only when
that decoder cannot decode an examiner-authorized CRYPT12/14/15 backup.  It never
brute-forces keys and never logs key material.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from app.services.mobile_forensic.whatsapp_crypt import (
    WhatsAppKeyCandidate,
    crypt_extension,
    looks_like_sqlite,
    parse_key_material,
)

_MAX_STDIO = 4000
_DEFAULT_TIMEOUT = 300


def _enabled() -> bool:
    return os.environ.get("WHATSAPP_EXTERNAL_TOOLS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def _safe_summary(text: str | bytes | None) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    value = str(text or "")[-_MAX_STDIO:]
    # Do not retain long hex-like tokens that could be key material.
    import re
    return re.sub(r"(?i)\b[0-9a-f]{48,}\b", "<redacted-hex>", value)


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _candidate_material(candidate: WhatsAppKeyCandidate) -> bytes | None:
    material = candidate.material
    if isinstance(material, str):
        try:
            return bytes.fromhex("".join(ch for ch in material if ch not in " \r\n\t-:"))
        except ValueError:
            return None
    return bytes(material) if isinstance(material, (bytes, bytearray)) else None


def _find_sqlite(root: Path) -> bytes | None:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 768_000_000:
                continue
            with path.open("rb") as fh:
                head = fh.read(16)
            if head == b"SQLite format 3\x00":
                return path.read_bytes()
        except OSError:
            continue
    return None


def decrypt_with_external_tools(
    encrypted: bytes,
    candidates: Iterable[WhatsAppKeyCandidate],
    *,
    source_path: str,
    timeout: int | None = None,
) -> tuple[bytes | None, dict]:
    """Try ``wtsexporter`` then ``wadecrypt`` with collected key material only.

    ``wtsexporter`` is invoked in Android-backup mode as requested by the examiner.
    If that command succeeds but does not retain a plaintext DB, ``wadecrypt`` is
    used as the deterministic decryption-only fallback.  Secrets are written only
    to private temporary key files, not placed directly on the command line.
    """
    family = crypt_extension(source_path) or "unknown"
    if not _enabled() or family not in {"crypt12", "crypt14", "crypt15"}:
        return None, {"external_tools": False, "reason": "disabled_or_unsupported_family", "container": family}

    wtsexporter = shutil.which("wtsexporter")
    wadecrypt = shutil.which("wadecrypt")
    if not wtsexporter and not wadecrypt:
        return None, {"external_tools": False, "reason": "external_tools_not_installed", "container": family}

    attempts: list[dict] = []
    limit = max(30, min(int(timeout or os.environ.get("WHATSAPP_EXTERNAL_TOOL_TIMEOUT_SEC", _DEFAULT_TIMEOUT)), 1800))
    for candidate in candidates:
        raw_key = _candidate_material(candidate)
        parsed = parse_key_material(raw_key) if raw_key else None
        if not parsed:
            continue
        with tempfile.TemporaryDirectory(prefix="polaron-wa-") as tmp:
            root = Path(tmp)
            enc_path = root / (Path(source_path.replace("\\", "/")).name or f"msgstore.db.{family}")
            key_path = root / ("encrypted_backup.key" if family == "crypt15" else "key")
            out_path = root / "msgstore.decrypted.db"
            _write_private(enc_path, encrypted)
            # Preserve the collected representation when possible.  For a raw
            # 32-byte candidate, both supported tools accept the private key file.
            _write_private(key_path, raw_key)

            if wtsexporter:
                cmd = [wtsexporter, "-a", "-k", str(key_path), "-b", str(enc_path)]
                try:
                    proc = subprocess.run(
                        cmd, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=limit, check=False,
                        env={**os.environ, "PYTHONUNBUFFERED": "1"},
                    )
                    attempt = {"tool": "wtsexporter", "exit_code": proc.returncode,
                               "stdout_tail": _safe_summary(proc.stdout), "stderr_tail": _safe_summary(proc.stderr)}
                    attempts.append(attempt)
                    plain = _find_sqlite(root)
                    if proc.returncode == 0 and plain and looks_like_sqlite(plain):
                        return plain, {"external_tools": True, "tool": "wtsexporter", "container": family,
                                       "authenticated": family in {"crypt12", "crypt14", "crypt15"},
                                       "validation": "sqlite_magic_external_tool", "payload_kind": "sqlite",
                                       "integrity": "external_tool_validated", "key_source": candidate.source,
                                       "key_sha256_prefix": hashlib.sha256(raw_key).hexdigest()[:12], "attempts": attempts}
                except (OSError, subprocess.SubprocessError) as exc:
                    attempts.append({"tool": "wtsexporter", "error": type(exc).__name__})

            if wadecrypt:
                # wadecrypt has an explicit output argument and supports CRYPT12/14/15.
                cmd = [wadecrypt, str(key_path), str(enc_path), str(out_path)]
                try:
                    proc = subprocess.run(
                        cmd, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=limit, check=False,
                    )
                    attempts.append({"tool": "wadecrypt", "exit_code": proc.returncode,
                                     "stdout_tail": _safe_summary(proc.stdout), "stderr_tail": _safe_summary(proc.stderr)})
                    if proc.returncode == 0 and out_path.is_file():
                        plain = out_path.read_bytes()
                        if looks_like_sqlite(plain):
                            return plain, {"external_tools": True, "tool": "wadecrypt", "container": family,
                                           "authenticated": True, "validation": "sqlite_magic_external_tool",
                                           "payload_kind": "sqlite", "integrity": "external_tool_validated",
                                           "key_source": candidate.source,
                                           "key_sha256_prefix": hashlib.sha256(raw_key).hexdigest()[:12], "attempts": attempts}
                except (OSError, subprocess.SubprocessError) as exc:
                    attempts.append({"tool": "wadecrypt", "error": type(exc).__name__})

    return None, {"external_tools": True, "reason": "all_external_decryptors_failed", "container": family, "attempts": attempts}
