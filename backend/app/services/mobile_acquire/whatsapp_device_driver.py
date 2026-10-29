"""Android WhatsApp acquisition + on-device backup driver (ADB only).

Implements the Monolith Forensics "Android WhatsApp Data Extraction Process"
(2026) behind one callable surface so the decrypt agent can run it without
embedding shell strings.

Two capability tiers, chosen by the agent:

* READ-ONLY (default, always allowed). Confirm the device with ``adb devices``,
  then pull the public WhatsApp tree ``/sdcard/Android/media/com.whatsapp`` and
  the WhatsApp key file. These do not alter the handset. This matches PDF steps
  1-5 and 16-17 (the second pull is only needed after a new backup, so read-only
  runs pull once).

* DEVICE-MODIFYING (PDF steps 6-15: generate a 64-digit end-to-end key and
  create a new encrypted backup on the evidence device). This WRITES to the
  evidence device and is therefore gated behind explicit examiner authorization
  (see ``WhatsAppDecryptAgent``). WhatsApp has no public ADB/intent API to script
  the "End-to-end encrypted backup → 64-digit key → Create" screens; attempting
  to drive them blindly with input taps is not reproducible across WhatsApp
  versions and is unsafe on evidence. This driver therefore does NOT fake those
  taps. When device-modifying mode is authorized it:
    - records the exact manual on-device steps the examiner must perform,
    - captures before/after state (settings DB mtime, backup file listing) for
      the custody record,
    - and, once the examiner confirms the key was generated, accepts the
      64-digit key and re-pulls the freshly created ``.crypt15`` backup.

Everything is deterministic, every ADB call is bounded, and acquisition error
text is never mistaken for evidence.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

PUBLIC_WHATSAPP_MEDIA = "/sdcard/Android/media/com.whatsapp"
PUBLIC_WHATSAPP_BUSINESS_MEDIA = "/sdcard/Android/media/com.whatsapp.w4b"
# Where a crypt15 backup created on-device lands in public storage.
BACKUP_GLOB_DIRS = (
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
    "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
    "/sdcard/WhatsApp/Databases",
)
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DEVICE_LINE = re.compile(r"^(\S+)\s+(device|unauthorized|offline|recovery|sideload)\b")


def normalize_64_digit_key(value: str) -> str | None:
    """The 64-digit key WhatsApp shows is 64 hex chars, optionally spaced."""
    compact = "".join(ch for ch in (value or "") if ch not in " \n\r\t-:")
    return compact.lower() if _HEX64.match(compact) else None


@dataclass
class DeviceStep:
    name: str
    ok: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class DriverResult:
    ok: bool
    steps: list[DeviceStep] = field(default_factory=list)
    pulled_dirs: list[str] = field(default_factory=list)
    backup_files: list[dict[str, Any]] = field(default_factory=list)
    key_files: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def add(self, step: DeviceStep) -> DeviceStep:
        self.steps.append(step)
        if not step.ok and step.detail:
            # A failed read-only step is a gap, not a hard error, unless the
            # caller escalates it.
            self.limitations.append(f"{step.name}: {step.detail}")
        return step


class WhatsAppDeviceDriver:
    """Thin, bounded ADB wrapper. Holds no evidence state of its own."""

    def __init__(self, adb: str = "adb", serial: str = "") -> None:
        self.adb = adb
        self.serial = serial

    # ---- low level -------------------------------------------------------
    def _prefix(self) -> list[str]:
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def _run(self, args: list[str], *, timeout: int, binary: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(
            self._prefix() + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            text=not binary,
        )

    def _shell(self, command: str, *, timeout: int = 30, binary: bool = False) -> subprocess.CompletedProcess:
        return self._run(["shell", command], timeout=timeout, binary=binary)

    # ---- PDF step 3: adb devices ----------------------------------------
    def confirm_device(self) -> DeviceStep:
        """`adb devices` — the serial must be present and authorized."""
        try:
            out = self._run(["devices"], timeout=30)
        except Exception as exc:
            return DeviceStep("adb_devices", False, f"adb devices failed: {exc}")
        states: dict[str, str] = {}
        for line in (out.stdout or "").splitlines()[1:]:
            m = _DEVICE_LINE.match(line.strip())
            if m:
                states[m.group(1)] = m.group(2)
        if self.serial and self.serial not in states:
            return DeviceStep("adb_devices", False, f"Device {self.serial} is not attached.", {"states": states})
        state = states.get(self.serial) or (next(iter(states.values()), "") if states else "")
        if state != "device":
            return DeviceStep("adb_devices", False,
                              f"Device state is '{state or 'none'}' (need 'device'; unlock and authorize USB debugging).",
                              {"states": states})
        return DeviceStep("adb_devices", True, "Device present and authorized.", {"states": states})

    def whatsapp_installed(self, package: str = "com.whatsapp") -> bool:
        try:
            out = self._shell(f"pm path {shlex.quote(package)}", timeout=20)
        except Exception:
            return False
        return bool(out.returncode == 0 and "package:" in (out.stdout or ""))

    # ---- PDF steps 4-5 / 16: adb pull (read-only) -----------------------
    def pull_public_tree(self, remote: str, dest: Path, *, timeout: int = 1800) -> DeviceStep:
        """`adb pull -a <remote> <dest>` of a public (/sdcard) tree."""
        dest.mkdir(parents=True, exist_ok=True)
        try:
            exists = self._shell(f"test -d {shlex.quote(remote)} && echo OK", timeout=15)
        except Exception as exc:
            return DeviceStep("pull_public", False, f"{remote}: {exc}", {"remote": remote})
        if "OK" not in (exists.stdout or ""):
            return DeviceStep("pull_public", False, f"{remote} not present on device.", {"remote": remote})
        try:
            proc = self._run(["pull", "-a", remote, str(dest)], timeout=timeout)
        except Exception as exc:
            return DeviceStep("pull_public", False, f"{remote}: {exc}", {"remote": remote})
        if proc.returncode != 0:
            return DeviceStep("pull_public", False,
                              (proc.stderr or proc.stdout or "")[:240], {"remote": remote})
        files = sum(1 for p in dest.rglob("*") if p.is_file())
        return DeviceStep("pull_public", True, f"Pulled {remote} ({files} files).",
                          {"remote": remote, "files": files, "dest": str(dest)})

    # ---- backup / key discovery (read-only) -----------------------------
    def list_backups(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for directory in BACKUP_GLOB_DIRS:
            try:
                res = self._shell(
                    f"ls -la {shlex.quote(directory)} 2>/dev/null | grep -i 'msgstore.*crypt'",
                    timeout=20,
                )
            except Exception:
                continue
            for line in (res.stdout or "").splitlines():
                name = line.split()[-1] if line.split() else ""
                if name and "crypt" in name.lower():
                    out.append({"dir": directory, "name": name, "remote": f"{directory}/{name}"})
        return out

    def newest_backup_signature(self) -> str:
        """A cheap fingerprint of the backup set to detect a new file later."""
        return "|".join(sorted(f"{b['remote']}" for b in self.list_backups()))

    # ---- device-modifying context (PDF steps 6-15) ----------------------
    def capture_backup_screen_state(self) -> dict[str, Any]:
        """Before/after snapshot for the custody record. Read-only."""
        state: dict[str, Any] = {"backups": self.list_backups()}
        try:
            res = self._shell(
                "stat -c '%Y' /sdcard/Android/media/com.whatsapp/WhatsApp/Databases 2>/dev/null || true",
                timeout=15,
            )
            state["databases_dir_mtime"] = (res.stdout or "").strip()
        except Exception:
            state["databases_dir_mtime"] = ""
        return state

    # ---- rung 3: read the live private DB when root already exists ------
    _PRIVATE_DB_PATHS = (
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/data/user/0/com.whatsapp/databases/msgstore.db",
        "/data/data/com.whatsapp.w4b/databases/msgstore.db",
        "/data/user/0/com.whatsapp.w4b/databases/msgstore.db",
    )
    _PRIVATE_KEY_PATHS = (
        "/data/data/com.whatsapp/files/key",
        "/data/user/0/com.whatsapp/files/key",
        "/data/data/com.whatsapp.w4b/files/key",
        "/data/user/0/com.whatsapp.w4b/files/key",
    )

    def root_mode(self) -> str | None:
        """Return 'adbd_root' / 'su' only when root ALREADY exists. Never escalates."""
        try:
            direct = self._shell("id", timeout=10)
            if direct.returncode == 0 and re.search(r"\buid=0(?:\D|$)", direct.stdout or ""):
                return "adbd_root"
        except Exception:
            pass
        try:
            su = self._run(["shell", "su", "-c", "id"], timeout=12)
            if su.returncode == 0 and re.search(r"\buid=0(?:\D|$)", su.stdout or ""):
                return "su"
        except Exception:
            pass
        return None

    def _root_cat(self, mode: str, remote: str, dest: Path, *, timeout: int) -> bool:
        """`cat` a private file to dest using existing root. Reads only; no device write."""
        quoted = shlex.quote(remote)
        cmd = f"su -c {shlex.quote('cat ' + quoted)}" if mode == "su" else f"cat {quoted}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                self._prefix() + ["exec-out", cmd],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
            )
        except Exception:
            return False
        data = proc.stdout or b""
        # Reject acquisition error text saved as "evidence".
        head = data[:64].lstrip(b"\xef\xbb\xbf \r\n\t").lower()
        if not data or head.startswith((b"su:", b"/system/bin/sh:", b"error:", b"cat:", b"run-as")):
            return False
        dest.write_bytes(data)
        return True

    def pull_live_private_db(self, dest_dir: Path) -> DeviceStep:
        """PDF-free, root-only, READ-ONLY capture of the live msgstore.db (+ files/key).

        Uses root that is ALREADY present; it never roots, unlocks or modifies the
        device. Returns a gap when root is unavailable — never an escalation.
        """
        mode = self.root_mode()
        if not mode:
            return DeviceStep("live_private_db", False,
                              "No existing root/su; live private WhatsApp DB is not readable "
                              "without rooting the device (which would modify it).")
        dest_dir.mkdir(parents=True, exist_ok=True)
        got_db: list[str] = []
        got_key: list[str] = []
        for remote in self._PRIVATE_DB_PATHS:
            name = remote.replace("/", "_").strip("_")
            if self._root_cat(mode, remote, dest_dir / name, timeout=1800):
                got_db.append(remote)
                break  # one live DB per package is enough
        for remote in self._PRIVATE_KEY_PATHS:
            name = remote.replace("/", "_").strip("_")
            if self._root_cat(mode, remote, dest_dir / name, timeout=30):
                got_key.append(remote)
        if not got_db and not got_key:
            return DeviceStep("live_private_db", False,
                              f"Root present ({mode}) but no WhatsApp private DB/key was readable.")
        return DeviceStep("live_private_db", True,
                          f"Read live private data via existing {mode} (db={len(got_db)}, key={len(got_key)}).",
                          {"mode": mode, "db_paths": got_db, "key_paths": got_key})

    def open_backup_settings(self) -> DeviceStep:
        """Bring the Chat Backup screen to the foreground so the examiner can act.

        Uses only the public app-launch intent; it does not tap any control.
        """
        try:
            res = self._shell(
                "am start -n com.whatsapp/com.whatsapp.backup.google.SettingsGoogleDrive",
                timeout=20,
            )
            if res.returncode == 0 and "Error" not in (res.stdout or ""):
                return DeviceStep("open_backup_settings", True, "Opened WhatsApp Chat Backup settings.")
        except Exception:
            pass
        # Fall back to just launching WhatsApp; the examiner navigates manually.
        try:
            self._shell("monkey -p com.whatsapp -c android.intent.category.LAUNCHER 1", timeout=20)
        except Exception:
            pass
        return DeviceStep("open_backup_settings", False,
                          "Could not deep-link the backup screen; launched WhatsApp for manual navigation.")
