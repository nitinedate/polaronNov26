"""Capture WhatsApp's private key (and live DB) from an Android device.

Scope and guarantees
---------------------
* **Uses root that is ALREADY present.** It runs ``su -c id`` / checks adbd and
  proceeds only when uid 0 is already available. It NEVER attempts to gain root:
  no exploit, no bootloader/boot-image change, no escalation. Rooting an unrooted
  phone writes to the device and is not a defensible forensic action, so it is out
  of scope by design. When root is absent this returns a precise, actionable gap.
* **Read-only.** Every device access is ``cat`` of an existing file streamed off
  the phone with ``adb exec-out``. Nothing is written, moved or changed on the
  device.
* **Stages the key where decryption expects it.** The captured 158-byte
  ``files/key`` (and ``encrypted_backup.key`` if present) is written to the
  acquisition tree under ``whatsapp_decrypt_agent/`` so the read-only decryption
  ladder and the case-folder gate find it with no further wiring. A copy also
  lands in the canonical private-apps namespace for the materializer.
* **Complete logs.** Every attempt — command, target path, mode, bytes, SHA-256,
  outcome — is emitted to the ``mobile_acquire.whatsapp_key_capture`` logger AND
  appended to the returned audit list and chain-of-custody entries. Raw key bytes
  are never logged; only their length and SHA-256.

Runtime / microservice
----------------------
ADB has no USB access inside Docker, so Android acquisition — and therefore this
capture — runs in the **host drive helper** (``scripts/host-drive-helper.ps1``,
port 9876) on the examiner's Windows PC, which executes the Android adapter in
process. The ``api`` container only brokers the request and records results; the
``worker-*`` containers never touch the phone. See module ``host_bridge``.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.services.mobile_acquire.whatsapp_device_driver import WhatsAppDeviceDriver

log = logging.getLogger("mobile_acquire.whatsapp_key_capture")

# WhatsApp private key locations (consumer + business, multi-user), read-only.
KEY_REMOTE_PATHS: tuple[str, ...] = (
    "/data/data/com.whatsapp/files/key",
    "/data/user/0/com.whatsapp/files/key",
    "/data/data/com.whatsapp/files/encrypted_backup.key",
    "/data/user/0/com.whatsapp/files/encrypted_backup.key",
    "/data/data/com.whatsapp.w4b/files/key",
    "/data/user/0/com.whatsapp.w4b/files/key",
)
LIVE_DB_REMOTE_PATHS: tuple[str, ...] = (
    "/data/data/com.whatsapp/databases/msgstore.db",
    "/data/user/0/com.whatsapp/databases/msgstore.db",
    "/data/data/com.whatsapp.w4b/databases/msgstore.db",
    "/data/user/0/com.whatsapp.w4b/databases/msgstore.db",
)
# files/key is 158 bytes (AES-256 at offset 126); encrypted_backup.key ~131/59 B.
_PLAUSIBLE_KEY_SIZES = range(32, 1025)


@dataclass
class KeyCaptureResult:
    root_mode: str | None = None
    root_available: bool = False
    key_files: list[dict[str, Any]] = field(default_factory=list)   # provenance only
    live_db_files: list[dict[str, Any]] = field(default_factory=list)
    staged_paths: list[str] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    custody: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.key_files or self.live_db_files)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_mode": self.root_mode,
            "root_available": self.root_available,
            "key_files": self.key_files,
            "live_db_files": self.live_db_files,
            "staged_paths": self.staged_paths,
            "audit": self.audit,
            "custody": self.custody,
            "limitations": self.limitations,
            "errors": self.errors,
            "ok": self.ok,
        }


def _audit(result: KeyCaptureResult, action: str, **fields: Any) -> None:
    import datetime as _dt

    entry = {"action": action, "ts_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(), **fields}
    result.audit.append(entry)
    # Structured log line; never includes raw key bytes.
    log.info("whatsapp_key_capture %s", {k: v for k, v in entry.items() if k != "ts_utc"})


def _custody(result: KeyCaptureResult, actor: str, detail: str, location: str = "") -> None:
    try:
        from app.services.mobile_acquire.audit import custody_entry

        result.custody.append(custody_entry("collection", actor=actor, detail=detail, location=location))
    except Exception:
        import datetime as _dt

        result.custody.append({
            "stage": "collection", "actor": actor, "detail": detail,
            "location": location, "timestamp_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        })


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def capture_whatsapp_key(
    *,
    adb: str = "adb",
    serial: str = "",
    out_dir: Path,
    driver: WhatsAppDeviceDriver | None = None,
    include_live_db: bool = True,
) -> KeyCaptureResult:
    """Read-only capture of WhatsApp's private key (+ live DB) when root exists.

    ``out_dir`` is the acquisition destination; the key is staged under
    ``<out_dir>/whatsapp_decrypt_agent/live_private`` (where the decryption ladder
    looks) and mirrored to ``<out_dir>/private_apps/com.whatsapp/files``.
    """
    result = KeyCaptureResult()
    drv = driver or WhatsAppDeviceDriver(adb=adb, serial=serial)
    out_dir = Path(out_dir)
    _audit(result, "start", serial=serial or "(default)", include_live_db=include_live_db)

    # 1) Confirm the device is reachable and authorized.
    confirm = drv.confirm_device()
    _audit(result, "adb_devices", ok=confirm.ok, detail=confirm.detail)
    if not confirm.ok:
        result.errors.append(confirm.detail)
        result.limitations.append("Key capture skipped: device not reachable over ADB.")
        return result

    # 2) Root must ALREADY be present. We never escalate.
    mode = drv.root_mode()
    result.root_mode = mode
    result.root_available = bool(mode)
    _audit(result, "root_check", root_mode=mode, escalation_attempted=False)
    if not mode:
        msg = (
            "No existing root/su on this device. WhatsApp's private key "
            "(/data/data/com.whatsapp/files/key) is inside the app sandbox and cannot be "
            "read by a logical pull. This tool does NOT root the device (that would modify "
            "evidence). Re-acquire with File System / Full File System on a rooted or "
            "run-as-capable device, use a physical image, or — as an authorized last resort — "
            "create a new crypt15 backup with a 64-digit key."
        )
        result.limitations.append(msg)
        _custody(result, "decrypt_agent", "Key capture not possible: device is not rooted; no escalation attempted.")
        return result

    _custody(result, "decrypt_agent",
             f"Read-only private-data capture authorized by existing device root ({mode}). No escalation.")

    # 3) Capture the key(s) read-only, staged where decryption looks.
    ladder_dir = out_dir / "whatsapp_decrypt_agent" / "live_private"
    mirror_dir = out_dir / "private_apps" / "com.whatsapp" / "files"
    ladder_dir.mkdir(parents=True, exist_ok=True)

    for remote in KEY_REMOTE_PATHS:
        basename = Path(remote).name  # "key" or "encrypted_backup.key"
        # Stage under a per-source subdir keeping the CANONICAL basename, so the
        # decrypt ladder's rglob("key")/rglob("encrypted_backup.key") finds it and
        # two users' keys never collide.
        source_tag = remote.replace("/", "_").strip("_").removesuffix("_" + basename)
        dest = ladder_dir / source_tag / basename
        _audit(result, "read_attempt", target=remote, mode=mode, command=f"exec-out cat {remote}")
        ok = drv._root_cat(mode, remote, dest, timeout=30)
        if not ok:
            _audit(result, "read_result", target=remote, ok=False, note="absent or unreadable")
            continue
        size = dest.stat().st_size
        if size not in _PLAUSIBLE_KEY_SIZES:
            _audit(result, "read_result", target=remote, ok=False, size_bytes=size, note="implausible key size; discarded")
            dest.unlink(missing_ok=True)
            continue
        digest = _sha256_file(dest)
        # Mirror to the canonical private-apps namespace for the materializer.
        mirror_dir.mkdir(parents=True, exist_ok=True)
        mirror = mirror_dir / basename
        try:
            mirror.write_bytes(dest.read_bytes())
            result.staged_paths.append(str(mirror))
        except OSError as exc:
            result.errors.append(f"mirror {remote}: {exc}")
        result.staged_paths.append(str(dest))
        record = {"remote": remote, "staged": str(dest), "size_bytes": size, "sha256": digest}
        result.key_files.append(record)
        _audit(result, "read_result", target=remote, ok=True, size_bytes=size, sha256=digest, staged=str(dest))
        _custody(result, "decrypt_agent",
                 f"Captured WhatsApp key {remote} read-only via {mode} "
                 f"({size} bytes, sha256={digest[:16]}…).", str(dest))

    # 4) Optionally capture the live (already-plaintext) msgstore.db.
    if include_live_db:
        for remote in LIVE_DB_REMOTE_PATHS:
            local_name = remote.replace("/", "_").strip("_")
            dest = ladder_dir / local_name
            _audit(result, "read_attempt", target=remote, mode=mode, command=f"exec-out cat {remote}")
            ok = drv._root_cat(mode, remote, dest, timeout=1800)
            if not ok:
                _audit(result, "read_result", target=remote, ok=False, note="absent or unreadable")
                continue
            size = dest.stat().st_size
            digest = _sha256_file(dest)
            result.live_db_files.append({"remote": remote, "staged": str(dest), "size_bytes": size, "sha256": digest})
            result.staged_paths.append(str(dest))
            _audit(result, "read_result", target=remote, ok=True, size_bytes=size, sha256=digest, staged=str(dest))
            _custody(result, "decrypt_agent",
                     f"Captured live {remote} read-only via {mode} ({size:,} bytes).", str(dest))
            break  # one live DB per device is enough

    if not result.key_files:
        result.limitations.append(
            "Root present but WhatsApp files/key was not found — the account may use only "
            "crypt15 (64-digit key) backups, or WhatsApp is not installed for this user."
        )
    _audit(result, "done", keys=len(result.key_files), live_dbs=len(result.live_db_files),
           staged=len(result.staged_paths))
    return result


def write_capture_log(result: KeyCaptureResult, out_dir: Path) -> Path:
    """Persist the full capture log next to the staged key (no raw key bytes)."""
    import json

    out = Path(out_dir) / "whatsapp_decrypt_agent"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "whatsapp_key_capture_log.json"
    path.write_text(json.dumps(result.as_dict(), indent=2, default=str), encoding="utf-8")
    log.info("whatsapp_key_capture log written path=%s keys=%d live_dbs=%d",
             path, len(result.key_files), len(result.live_db_files))
    return path
