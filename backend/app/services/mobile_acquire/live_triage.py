"""Live malware triage of a connected phone: a quick, read-only collection for Malware Detection.

Runs on the examiner workstation (where the USB device is), started by the host helper's
``POST /malware/triage`` route or by hand:

    python -m app.services.mobile_acquire.live_triage --platform android --device SERIAL --out triage.zip \\
        --examiner you@lab --legal-authority "Warrant 123"

Android uses adb (USB debugging authorised on the phone). Only read-only shell commands run: package
lists, granted permissions, secure settings, device admins, accessibility, processes, network stats,
notifications and the log buffer; third-party app packages are copied for analysis (``--no-apks`` to skip).
iOS uses the paired lockdown service: installed apps, configuration profiles and crash reports, copied
without removing them from the phone.

The bundle is a zip whose ``manifest.json`` records every command, its exit code, timings and the SHA-256
of every file, plus the examiner, legal authority and device identity. File names follow the conventions
Malware Detection's engines already read (``packages_all.txt``, ``processes.txt``, ``logcat_main.txt``),
and app packages keep their on-device paths, so the same engines analyse a live capture and an extraction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as _platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

COLLECTOR_VERSION = "1.2.2"  # 1.2.2: a locked progress.json must not abort the phone read; 1.2.1 key log
ROOT_PROBE = ("for p in /system/bin/su /system/xbin/su /sbin/su /system/su /data/local/su /data/local/bin/su "
              "/data/local/xbin/su /su/bin/su /data/adb/magisk /data/adb/ksu /data/adb/ap; "
              "do [ -e \"$p\" ] && echo \"FOUND $p\"; done; true")
# (bundle path, shell command, timeout seconds). Read-only by construction: nothing here writes to the phone.
ANDROID_COMMANDS: tuple[tuple[str, str, int], ...] = (
    ("live/getprop.txt", "getprop", 60),
    ("live/packages_all.txt", "pm list packages -f -i -U", 120),
    ("live/packages_third_party.txt", "pm list packages -3", 60),
    ("live/dumpsys_package.txt", "dumpsys package packages", 600),
    ("live/settings_secure.txt", "settings list secure", 60),
    ("live/settings_global.txt", "settings list global", 60),
    ("live/device_policy.txt", "dumpsys device_policy", 120),
    ("live/accessibility.txt", "dumpsys accessibility", 120),
    ("live/notifications.txt", "dumpsys notification --noredact", 120),
    ("live/processes.txt", "ps -A -o USER,PID,PPID,NAME,ARGS || ps -A", 60),
    ("live/netstats.txt", "dumpsys netstats detail", 180),
    ("live/activities.txt", "dumpsys activity activities", 120),
    ("live/logcat_main.txt", "logcat -d -b all -v threadtime", 300),
    ("live/root_check.txt", ROOT_PROBE, 30),
)
FORBIDDEN = ("rm ", "mv ", "pm install", "pm uninstall", "pm clear", "am force-stop", "settings put", "reboot", " > ", "dd ")


class TriageError(RuntimeError):
    pass


class DeviceGoneError(TriageError):
    """The phone stopped responding (unplugged, locked, or USB dropped) and did not come back."""


# adb prints these to stderr once the phone is no longer reachable over USB.
_DISCONNECT_MARKERS = ("device not found", "device offline", "no devices/emulators found",
                       "device '", "error: closed", "protocol fault", "device unauthorized")


def _looks_disconnected(result) -> bool:
    if result.returncode == 0:
        return False
    err = (getattr(result, "stderr", b"") or b"").decode("utf-8", "replace").lower()
    return any(m in err for m in _DISCONNECT_MARKERS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_progress_file(path: str, payload: str) -> None:
    """Publish progress without letting a locked destination abort the collector.

    Windows returns WinError 5 when another process has ``progress.json`` open without
    delete sharing (the live status poll). A failed replace must not become "Reading the phone failed".
    """
    dest = Path(path)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for attempt in range(5):
        tmp = dest.with_name(f"{dest.name}.{os.getpid()}.{attempt}.tmp")
        try:
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, dest)
            return
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            denied = getattr(exc, "winerror", None) in (5, 32) or exc.errno in (1, 13, 16)
            if not denied:
                break
            time.sleep(0.02 * (attempt + 1))
    try:
        dest.write_text(payload, encoding="utf-8")
    except OSError:
        return


class CommandLog:
    """Every command run against the phone, in order, with its result. Streamed to the progress file (atomically, so
    the host helper never reads half a file) for the live view, and kept whole in the bundle manifest."""

    KEEP_LIVE = 400

    def __init__(self, progress_file: str | None = None):
        self.progress_file = progress_file
        self.entries: list[dict] = []
        self._t: dict[int, float] = {}
        self.state = {"message": "Starting", "step": 0, "total": 0}

    def start(self, command: str) -> dict:
        entry = {"n": len(self.entries) + 1, "command": command, "status": "running", "started_at": _now()}
        self.entries.append(entry)
        self._t[entry["n"]] = time.monotonic()
        self.flush()
        return entry

    def end(self, entry: dict, *, ok: bool = True, exit_code: int | None = None, size: int | None = None,
            note: str | None = None, status: str | None = None) -> None:
        entry.update(status=status or ("ok" if ok else "failed"), exit_code=exit_code, size=size, note=note,
                     duration_ms=int((time.monotonic() - self._t.pop(entry["n"], time.monotonic())) * 1000))
        self.flush()

    def note(self, command: str, *, status: str, note: str | None = None, size: int | None = None) -> None:
        self.entries.append({"n": len(self.entries) + 1, "command": command, "status": status, "note": note, "size": size,
                             "started_at": _now(), "duration_ms": 0})
        self.flush()

    def progress(self, message: str, step: int, total: int) -> None:
        self.state = {"message": message, "step": step, "total": total}
        self.flush()

    def flush(self) -> None:
        if not self.progress_file:
            return
        body = {"status": "running", **self.state, "updated_at": _now(), "log": self.entries[-self.KEEP_LIVE:],
                "log_total": len(self.entries)}
        # The helper polls progress.json while this writes. On Windows that open handle denies
        # os.replace (WinError 5) and used to abort the whole phone read. Retry, then write in place.
        _write_progress_file(self.progress_file, json.dumps(body))


class BundleWriter:
    """Writes files into the triage zip and records each one in the manifest."""

    def __init__(self, out: Path):
        self.out = Path(out)
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self._zip = zipfile.ZipFile(self.out, "w", zipfile.ZIP_DEFLATED, allowZip64=True)
        self.files: list[dict] = []
        self.warnings: list[str] = []

    def add_bytes(self, path: str, data: bytes, **meta) -> None:
        info = zipfile.ZipInfo(path, date_time=time.gmtime()[:6])
        info.compress_type = zipfile.ZIP_STORED if path.endswith((".apk", ".zip")) else zipfile.ZIP_DEFLATED
        self._zip.writestr(info, data)
        self.files.append({"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), **meta})

    def add_file(self, path: str, src: Path, **meta) -> None:
        h, size = hashlib.sha256(), 0
        with open(src, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
                size += len(chunk)
        self._zip.write(src, path, compress_type=zipfile.ZIP_STORED)
        self.files.append({"path": path, "size": size, "sha256": h.hexdigest(), **meta})

    def close(self, manifest: dict) -> dict:
        manifest = {**manifest, "files": self.files, "warnings": self.warnings}
        self._zip.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        self._zip.close()
        return manifest


# ------------------------------------------------------------------------------------------- Android --
class Adb:
    def __init__(self, serial: str, adb: str | None = None):
        self.serial = serial
        self.adb = adb or os.environ.get("ANDROID_ADB") or shutil.which("adb") or "adb"
        self.gone = False  # set once the phone is confirmed unreachable, so later steps stop instead of retrying forever

    def _exec(self, args: list[str], timeout: int) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.adb, "-s", self.serial, *args], capture_output=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise TriageError("adb not found: install Android platform-tools on this workstation or set ANDROID_ADB") from exc

    def run(self, args: list[str], timeout: int, *, allow_reconnect: bool = True) -> subprocess.CompletedProcess:
        if self.gone:
            raise DeviceGoneError("the phone is no longer connected")
        res = self._exec(args, timeout)
        if allow_reconnect and _looks_disconnected(res):
            # A brief USB blip is common; wait for the phone to come back before giving up on the whole read.
            if self._wait_until_back():
                res = self._exec(args, timeout)
            if _looks_disconnected(res):
                self.gone = True
                raise DeviceGoneError("the phone stopped responding during the read "
                                      f"({res.stderr.decode('utf-8', 'replace').strip()[:120]})")
        return res

    def _wait_until_back(self, attempts: int = 6, delay: float = 2.0) -> bool:
        """Poll ``adb get-state`` for up to ~12s; True once the phone is 'device' again."""
        for _ in range(attempts):
            time.sleep(delay)
            state = self._exec(["get-state"], 15)
            if state.returncode == 0 and state.stdout.decode("utf-8", "replace").strip() == "device":
                return True
        return False

    def shell(self, command: str, timeout: int, *, allow_reconnect: bool = True) -> subprocess.CompletedProcess:
        if any(bad in f" {command} " for bad in FORBIDDEN) and command != ROOT_PROBE and "||" not in command:
            raise TriageError(f"refusing a command that could change the phone: {command}")
        return self.run(["exec-out", command], timeout, allow_reconnect=allow_reconnect)


def resolve_adb_serial(device_id: str, instance_id: str | None = None, adb: str | None = None) -> str:
    """The host helper lists phones by their Windows device id (USB\\VID_..&PID_..\\<serial>); adb needs the serial."""
    exe = adb or os.environ.get("ANDROID_ADB") or shutil.which("adb") or "adb"
    try:
        out = subprocess.run([exe, "devices"], capture_output=True, timeout=30).stdout.decode("utf-8", "replace")
    except FileNotFoundError as exc:
        raise TriageError("adb not found: install Android platform-tools on this workstation or set ANDROID_ADB") from exc
    devices = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices[parts[0]] = parts[1]
    if not devices:
        raise TriageError("No phone answers over adb: turn on USB debugging (Settings > Developer options), reconnect the "
                          "cable, and tap Allow on the phone")
    hay = f"{device_id} {instance_id or ''}".lower()
    match = next((s for s in devices if s.lower() == str(device_id).lower() or s.lower() in hay), None)
    if match is None and len(devices) == 1:
        match = next(iter(devices))
    if match is None:
        raise TriageError("Several Android phones are connected over adb and none matches the selected one; "
                          "disconnect the others and try again")
    if devices[match] == "unauthorized":
        raise TriageError("USB debugging is not authorised: unlock the phone and tap Allow on the RSA prompt")
    if devices[match] != "device":
        raise TriageError(f"The phone is {devices[match]} over adb: unplug it, reconnect, and tap Allow")
    return match


def _props(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line.startswith("[") and "]: [" in line:
            k, v = line[1:].split("]: [", 1)
            out[k] = v.rstrip("]")
    return out


def collect_android(serial: str, bundle: BundleWriter, *, pull_apks: bool = True, max_apk_mb: int = 300,
                    max_total_mb: int = 1536, adb: str | None = None, instance_id: str | None = None,
                    pull_whatsapp: bool = True,
                    progress: Callable[[str, int, int], None] | None = None, log: CommandLog | None = None) -> dict:
    log = log or CommandLog()
    progress = progress or log.progress
    entry = log.start("adb devices")
    try:
        serial = resolve_adb_serial(serial, instance_id, adb)
    except TriageError as exc:
        log.end(entry, ok=False, note=str(exc))
        raise
    log.end(entry, note=f"phone {serial}")
    tool = Adb(serial, adb)
    entry = log.start(f"adb -s {serial} get-state")
    state = tool.run(["get-state"], 20)
    log.end(entry, ok=state.returncode == 0, exit_code=state.returncode, note=state.stdout.decode("utf-8", "replace").strip()[:40])
    st = state.stdout.decode("utf-8", "replace").strip()
    if state.returncode != 0 or st != "device":
        err = state.stderr.decode("utf-8", "replace").strip()
        if "unauthorized" in (st + err):
            raise TriageError("USB debugging is not authorised: unlock the phone and tap Allow on the RSA prompt")
        raise TriageError(f"phone not ready over adb ({st or err or 'no state'})")
    steps = len(ANDROID_COMMANDS) + 1
    props: dict[str, str] = {}
    outputs: dict[str, str] = {}
    for i, (path, command, timeout) in enumerate(ANDROID_COMMANDS, 1):
        progress(f"Reading {path.rsplit('/', 1)[-1]}", i, steps)
        started = time.monotonic()
        entry = log.start(f"adb shell {command if command != ROOT_PROBE else 'test -e <su, Magisk and KernelSU paths>'}")
        try:
            res = tool.shell(command, timeout)
            data, code = res.stdout, res.returncode
            if code != 0 and res.stderr:
                bundle.warnings.append(f"{command}: exit {code}: {res.stderr.decode('utf-8', 'replace').strip()[:200]}")
            log.end(entry, ok=code == 0 or bool(data), exit_code=code, size=len(data))
        except DeviceGoneError as exc:
            log.end(entry, ok=False, note=str(exc))
            raise
        except subprocess.TimeoutExpired as exc:
            data, code = exc.stdout or b"", -1
            bundle.warnings.append(f"{command}: timed out after {timeout}s; partial output kept")
            log.end(entry, ok=False, exit_code=-1, size=len(data), note=f"timed out after {timeout}s; partial output kept")
        bundle.add_bytes(path, data, command=f"adb exec-out {command}", exit_code=code,
                         duration_ms=int((time.monotonic() - started) * 1000))
        if path.endswith("getprop.txt"):
            props = _props(data.decode("utf-8", "replace"))
        if path.endswith(("settings_secure.txt", "device_policy.txt")):
            outputs[path.rsplit("/", 1)[-1]] = data.decode("utf-8", "replace")
    # WhatsApp (chat evidence) is copied before the large, low-priority app packages, so a disconnect partway
    # through the read does not cost the backup.
    whatsapp = _pull_whatsapp(tool, bundle, log=log) if pull_whatsapp else {"present": False}
    apks: dict = {"copied": 0}
    if pull_apks:
        progress("Copying app packages", steps, steps)
        apks = _pull_apks(tool, bundle, max_apk_mb=max_apk_mb, max_total_mb=max_total_mb, progress=progress, log=log,
                          privileged=privileged_packages(outputs.get("settings_secure.txt", ""), outputs.get("device_policy.txt", "")))
    return {"platform": "android", "device_id": serial,
            "model": " ".join(filter(None, (props.get("ro.product.manufacturer"), props.get("ro.product.model")))) or None,
            "os_version": props.get("ro.build.version.release"), "security_patch": props.get("ro.build.version.security_patch"),
            "build_fingerprint": props.get("ro.build.fingerprint"), "apks_copied": apks.get("copied", 0), "apk_budget": apks,
            "whatsapp": whatsapp}


# WhatsApp's end-to-end encrypted backup lives in shared storage, readable over USB without root. The key is never
# on the phone in a form we take; it is entered separately on the Mobile key page and used to decrypt offline.
WHATSAPP_BACKUP_DIRS = (
    "/sdcard/WhatsApp/Databases",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
)


def _pull_whatsapp(tool: Adb, bundle: BundleWriter, *, log: CommandLog | None = None) -> dict:
    log = log or CommandLog()
    entry = log.start("adb shell ls <WhatsApp backup dirs> (encrypted backup, no root)")
    found = None
    for base in WHATSAPP_BACKUP_DIRS:
        try:
            listing = tool.shell(f"ls -1 '{base}' 2>/dev/null", 30).stdout.decode("utf-8", "replace")
        except DeviceGoneError as exc:
            log.end(entry, ok=False, note=str(exc))
            raise
        # Prefer the current backup (msgstore.db.crypt15/14) over dated "msgstore-YYYY-MM-DD" ones, and crypt15 over
        # crypt14 (crypt15 needs only the 64-digit key; crypt14 needs the root-only key file).
        names = [n for n in listing.splitlines() if n.startswith("msgstore") and (n.endswith(".crypt15") or n.endswith(".crypt14"))
                 and "increment" not in n]
        for preferred in ("msgstore.db.crypt15", "msgstore.db.crypt14"):
            if preferred in names:
                found = (base, preferred); break
        if not found and names:  # newest dated backup, crypt15 first
            found = (base, sorted(names, key=lambda n: (n.endswith(".crypt14"), n))[-1] if any(n.endswith(".crypt15") for n in names)
                     else sorted(names)[-1])
        if found:
            break
    if not found:
        log.end(entry, status="skipped", note="no WhatsApp backup (.crypt14/.crypt15) in shared storage")
        bundle.warnings.append("No WhatsApp backup (.crypt14 or .crypt15) was found in shared storage. In WhatsApp: "
                               "Settings > Chats > Chat backup > Back up now.")
        return {"present": False}
    base, name = found
    log.end(entry, note=f"{base}/{name}")
    kind = "crypt15" if name.endswith(".crypt15") else "crypt14" if name.endswith(".crypt14") else "unknown"
    entry = log.start(f"adb pull {base}/{name}")
    import tempfile
    with tempfile.TemporaryDirectory(prefix="aetheris-wa-") as tmp:
        local = Path(tmp) / name
        res = tool.run(["pull", f"{base}/{name}", str(local)], 600)
        if res.returncode != 0 or not local.exists():
            log.end(entry, ok=False, exit_code=res.returncode, note=res.stderr.decode("utf-8", "replace").strip()[:160])
            bundle.warnings.append(f"WhatsApp backup could not be copied: {res.stderr.decode('utf-8', 'replace').strip()[:160]}")
            return {"present": False}
        bundle.add_file(f"whatsapp/{name}", local, command=f"adb pull {base}/{name}")
        size = local.stat().st_size
        log.end(entry, exit_code=0, size=size)
    result = {"present": True, "backup": name, "source_dir": base, "bytes": size, "kind": kind}
    # Crypt14 needs the phone's key file. Crypt15 needs the 64-digit key, which is the last 32 bytes of that
    # same file when root is already present. Both are tried with the same read-only methods; nothing is rooted.
    if kind in ("crypt14", "crypt15"):
        result["key_file"] = _pull_whatsapp_key(tool, bundle, log=log)
    return result


WA_KEY_PATHS = (
    "/data/data/com.whatsapp/files/key",
    "/data/user/0/com.whatsapp/files/key",
    "/data/data/com.whatsapp/files/encrypted_backup.key",
    "/data/user/0/com.whatsapp/files/encrypted_backup.key",
    "/data/data/com.whatsapp.w4b/files/key",
    "/data/user/0/com.whatsapp.w4b/files/key",
)
# Root is usually "su", but some custom/engineering builds ship it under another name.
SU_BINARIES = ("su", "/system/xbin/su", "/system/bin/su", "/sbin/su", "/magisk/.core/bin/su")


def _b64_decode(stdout: bytes) -> bytes:
    import base64

    try:
        return base64.b64decode(stdout.decode("utf-8", "replace").strip() or "", validate=False)
    except Exception:
        return b""


_KEY_NOISE = (b"not debuggable", b"permission denied", b"no such file", b"inaccessible", b"not found", b"error:")


def _plausible_key(data: bytes) -> bool:
    if not data or len(data) < 32 or len(data) > 1024:
        return False
    low = data[:160].lower()
    return not any(marker in low for marker in _KEY_NOISE)


def _key_payload(stdout: bytes) -> bytes:
    """Accept a raw key file or the same bytes printed as base64. Reject shell error text."""
    raw = (stdout or b"").strip().strip(b"\x00")
    if not raw:
        return b""
    if re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", raw) and len(raw) >= 44:
        decoded = _b64_decode(raw)
        if _plausible_key(decoded):
            return decoded
    return raw if _plausible_key(raw) else b""


def _pull_whatsapp_key(tool: Adb, bundle: BundleWriter, *, log: CommandLog | None = None) -> dict:
    """Get the Crypt14 ``key`` file from WhatsApp's private storage. It is normally root-only, but every legitimate
    no-root path is tried first: run-as (debuggable builds), then adb backup (older WhatsApp), then su under each of
    its known names. On a locked production phone none of these can work — that is Android's sandbox, not a Polaron
    limit — and the examiner is told so clearly."""
    log = log or CommandLog()
    # The whole effort is one logged step; each method below is a sub-attempt, so the reader sees "trying method 1 of 3"
    # rather than three separate failures, and a single clear verdict at the end.
    outer = log.start("Get the WhatsApp key for the Crypt14 backup (no-root methods first, then root)")

    # 1. run-as: works only if WhatsApp is a debuggable build (almost never on Play Store builds, but free to try).
    for path in ("files/key", "/data/data/com.whatsapp/files/key"):
        res = tool.shell(f"run-as com.whatsapp cat {path} 2>/dev/null | base64 2>/dev/null", 30, allow_reconnect=False)
        data = _key_payload(res.stdout)
        if len(data) >= 32:
            bundle.add_bytes("whatsapp/key", data, command="run-as com.whatsapp cat files/key")
            log.end(outer, exit_code=0, size=len(data), note="Key found via method 1 (run-as, debuggable build). Chats can be decrypted.")
            return {"present": True, "bytes": len(data), "source": "run-as", "method": "run-as"}
    log.note("  method 1 of 3 - run-as (no root): not available (WhatsApp is not a debuggable build)", status="skipped")

    # 2. adb backup of WhatsApp: on older WhatsApp/Android the .ab archive contains files/key. No root needed. Modern
    # WhatsApp sets allowBackup=false so this returns an empty archive, which we detect and skip.
    key_from_backup = _key_from_adb_backup(tool)
    if key_from_backup is not None:
        bundle.add_bytes("whatsapp/key", key_from_backup, command="adb backup com.whatsapp -> files/key")
        log.end(outer, exit_code=0, size=len(key_from_backup), note="Key found via method 2 (adb backup). Chats can be decrypted.")
        return {"present": True, "bytes": len(key_from_backup), "source": "adb-backup", "method": "adb-backup"}
    log.note("  method 2 of 3 - adb backup (no root): not available (WhatsApp blocks backup on this version)", status="skipped")

    # 3. Root that is already on the phone: adbd running as uid 0, or su under a known name.
    #    This does not install or start root. A production phone without either stays unread.
    id_res = tool.shell("id", 15, allow_reconnect=False)
    if b"uid=0" in (id_res.stdout or b""):
        for path in WA_KEY_PATHS:
            res = tool.shell(f"cat {path} 2>/dev/null | base64 2>/dev/null", 30, allow_reconnect=False)
            data = _key_payload(res.stdout)
            if data:
                bundle.add_bytes("whatsapp/key", data, command=f"cat {path}")
                log.end(outer, exit_code=0, size=len(data), note="Key found via method 3 (adbd already root). Chats can be decrypted.")
                return {"present": True, "bytes": len(data), "source": path, "method": "adbd"}
    for su in SU_BINARIES:
        for path in WA_KEY_PATHS:
            res = tool.shell(f"{su} -c 'cat {path}' 2>/dev/null | base64 2>/dev/null", 30, allow_reconnect=False)
            data = _key_payload(res.stdout)
            if len(data) >= 32:
                bundle.add_bytes("whatsapp/key", data, command=f"{su} -c cat {path}")
                log.end(outer, exit_code=0, size=len(data), note=f"Key found via method 3 (root, {su}). Chats can be decrypted.")
                return {"present": True, "bytes": len(data), "source": path, "method": "su"}
    log.note("  method 3 of 3 - su (root): not available (this phone is not rooted)", status="skipped")
    log.end(outer, status="skipped", note="Could not get the key. A read-only collection cannot open WhatsApp's private "
            "key on this phone. The phone was not changed. Chats stay encrypted (see the warning below). This does NOT "
            "affect the rest of the malware scan.")
    bundle.warnings.append("This phone has a Crypt14 WhatsApp backup. Its key file "
                           "(/data/data/com.whatsapp/files/key) is inside WhatsApp's private storage. A read-only "
                           "collection cannot read it: WhatsApp is not a debuggable build, it blocks adb backup, and "
                           "this phone is not rooted. Nothing on the phone was changed to chase the key. The encrypted "
                           "backup is in this capture. Chats stay encrypted until a key file that already exists from "
                           "another acquisition is uploaded on the Mobile key page.")
    return {"present": False, "reason": "root_required"}


def _key_from_adb_backup(tool: Adb, timeout: int = 120) -> bytes | None:
    """``adb backup`` writes an Android backup archive; on older WhatsApp it contains apps/com.whatsapp/f/key.
    The archive is a 24-byte header then (optionally) zlib-compressed tar. Returns the key bytes, or None."""
    import io
    import tarfile
    import tempfile
    import zlib

    with tempfile.TemporaryDirectory(prefix="aetheris-wa-ab-") as tmp:
        ab = Path(tmp) / "wa.ab"
        # -noapk keeps it small; the backup still includes the app's files. No confirmation dialog is auto-accepted,
        # so on a phone that shows the on-screen "Back up my data" prompt this needs the examiner to tap it.
        res = tool.run(["backup", "-f", str(ab), "-noapk", "com.whatsapp"], timeout, allow_reconnect=False)
        if res.returncode != 0 or not ab.exists() or ab.stat().st_size <= 24:
            return None
        raw = ab.read_bytes()
        newline = b"\x0a"
        # Android backup header: "ANDROID BACKUP", version, compression flag, encryption, each on its own line.
        parts = raw.split(newline, 4)
        body = parts[4] if len(parts) == 5 else b""
        if not body:
            return None
        try:
            tar_bytes = zlib.decompress(body)
        except zlib.error:
            tar_bytes = body  # some devices write an uncompressed archive
        try:
            with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
                for member in tar.getmembers():
                    if member.name.endswith("/f/key") or member.name.endswith("/files/key"):
                        f = tar.extractfile(member)
                        data = f.read() if f else b""
                        if len(data) >= 32:
                            return data
        except (tarfile.TarError, EOFError):
            return None
    return None


# App stores whose installs are reviewed; anything else (browser, file manager, package installer, adb) is a sideload.
TRUSTED_INSTALLERS = frozenset({
    "com.android.vending", "com.google.android.feedback", "com.amazon.venezia", "com.sec.android.app.samsungapps",
    "com.huawei.appmarket", "com.xiaomi.mipicks", "com.xiaomi.market", "com.oppo.market", "com.heytap.market",
    "com.bbk.appstore", "com.vivo.appstore",
})
_COMPONENT_PKG = re.compile(r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/")


def privileged_packages(settings_secure: str, device_policy: str) -> set[str]:
    """Apps holding accessibility, notification-listener or device-admin access (the stalkerware toolkit)."""
    out: set[str] = set()
    for line in settings_secure.splitlines():
        key, _, value = line.partition("=")
        if key.strip() in ("enabled_accessibility_services", "enabled_notification_listeners"):
            out |= set(_COMPONENT_PKG.findall(value))
    section = False
    for line in device_policy.splitlines():
        if "Enabled Device Admins" in line:
            section = True
            continue
        if section:
            m = re.match(r"^\s{2,}([A-Za-z][\w.]*)/[\w.$]+:\s*$", line)
            if m:
                out.add(m.group(1))
            elif line.strip() and not line.startswith(" " * 6):
                section = False
    out |= set(re.findall(r"ComponentInfo\{([A-Za-z][\w.]+)/", device_policy))
    return out


def _pull_apks(tool: Adb, bundle: BundleWriter, *, max_apk_mb: int, max_total_mb: int, privileged: set[str],
               progress: Callable[[str, int, int], None] = lambda *_: None, log: CommandLog | None = None) -> dict:
    log = log or CommandLog()
    """Copy third-party app packages within a size budget, riskiest first: sideloaded apps with special access,
    other sideloaded apps, store apps with special access, then the rest; smaller first within each group.
    Configuration splits (split_config.*.apk) hold only resources, never code, so they are not copied."""
    entry = log.start("adb shell pm list packages -3 -i")
    listing = tool.shell("pm list packages -3 -i", 60).stdout.decode("utf-8", "replace")
    log.end(entry, note=f"{listing.count('package:')} third-party apps")
    installers: dict[str, str] = {}
    for line in listing.splitlines():
        tokens = line.strip().split()
        if tokens and tokens[0].startswith("package:"):
            installers[tokens[0][len("package:"):]] = next((x.split("=", 1)[1] for x in tokens[1:] if x.startswith("installer=")), "null")
    plan = []
    progress("Measuring app packages", 0, len(installers))
    entry = log.start(f"adb shell pm path <app> and stat -c %s <apk> for {len(installers)} apps")
    for pkg in sorted(installers):
        paths = [ln.split(":", 1)[1].strip() for ln in tool.shell(f"pm path {pkg}", 60).stdout.decode("utf-8", "replace").splitlines()
                 if ln.startswith("package:")]
        code = [p for p in paths if not p.rsplit("/", 1)[-1].startswith("split_config.")]
        if not code:
            continue
        sizes = {}
        stat = tool.shell("stat -c '%s %n' " + " ".join(f"'{p}'" for p in code), 60).stdout.decode("utf-8", "replace")
        for line in stat.splitlines():
            size, _, name = line.strip().partition(" ")
            if size.isdigit():
                sizes[name] = int(size)
        sideloaded = installers[pkg] not in TRUSTED_INSTALLERS
        tier = (0 if sideloaded and pkg in privileged else 1 if sideloaded else 2 if pkg in privileged else 3)
        plan.append({"package": pkg, "paths": code, "bytes": sum(sizes.get(p, 0) for p in code), "tier": tier,
                     "installer": installers[pkg]})
    log.end(entry, size=sum(p["bytes"] for p in plan), note=f"{len(plan)} apps with code to copy")
    plan.sort(key=lambda x: (x["tier"], x["bytes"], x["package"]))
    budget, per_apk = max_total_mb * 1024 * 1024, max_apk_mb * 1024 * 1024
    used, copied, skipped = 0, [], []
    with tempfile.TemporaryDirectory(prefix="aetheris-triage-") as tmp:
        for n, item in enumerate(plan, 1):
            if item["tier"] == 3 and item["bytes"] > per_apk:  # sideloaded / special-access apps are always tried
                skipped.append({"package": item["package"], "mb": round(item["bytes"] / 1048576, 1), "reason": "larger than the per-app limit"})
                log.note(f"adb pull {item['package']}", status="skipped", size=item["bytes"], note="larger than the per-app limit")
                continue
            if used + item["bytes"] > budget:
                skipped.append({"package": item["package"], "mb": round(item["bytes"] / 1048576, 1), "reason": "size budget reached"})
                log.note(f"adb pull {item['package']}", status="skipped", size=item["bytes"], note="size budget reached")
                continue
            progress(f"Copying app packages ({n} of {len(plan)})", n, len(plan))
            for i, device_path in enumerate(item["paths"]):
                local = Path(tmp) / f"{n}-{i}.apk"
                entry = log.start(f"adb pull {device_path}")
                try:
                    res = tool.run(["pull", device_path, str(local)], 900)
                except DeviceGoneError as exc:
                    log.end(entry, ok=False, note=str(exc))
                    bundle.warnings.append(f"The phone disconnected while copying app packages; {len(copied)} of {len(plan)} "
                                           "apps were copied. Reconnect the phone and read it again for the rest.")
                    raise
                if res.returncode != 0 or not local.exists():
                    bundle.warnings.append(f"could not copy {device_path}: {res.stderr.decode('utf-8', 'replace').strip()[:160]}")
                    log.end(entry, ok=False, exit_code=res.returncode, note=res.stderr.decode("utf-8", "replace").strip()[:160])
                    continue
                log.end(entry, exit_code=0, size=local.stat().st_size, note=item["package"])
                # The on-device path is kept (under device/), so the engines link it to its app as in an extraction.
                bundle.add_file(f"device{device_path}", local, command=f"adb pull {device_path}", package=item["package"])
                used += local.stat().st_size
                local.unlink()
            copied.append(item["package"])
    if skipped:
        bundle.warnings.append(
            f"{len(skipped)} app package(s) not copied ({sum(s['mb'] for s in skipped):.0f} MB) to stay within the "
            f"{max_total_mb} MB budget; sideloaded apps and apps with special access were copied first. "
            f"Not copied: {', '.join(s['package'] for s in skipped[:15])}{' ...' if len(skipped) > 15 else ''}")
    return {"budget_mb": max_total_mb, "copied": len(copied), "copied_mb": round(used / 1048576, 1), "skipped": skipped,
            "order": "sideloaded with special access, sideloaded, store with special access, others; smaller first"}


# ----------------------------------------------------------------------------------------------- iOS --
IOS_APP_FIELDS = ("CFBundleIdentifier", "CFBundleDisplayName", "CFBundleName", "CFBundleShortVersionString", "CFBundleVersion",
                  "ApplicationType", "SignerIdentity", "Path", "ProfileValidated", "IsAppClip", "IsUpgradeable",
                  "ApplicationDSID", "UIRequiredDeviceCapabilities")


def collect_ios(udid: str, bundle: BundleWriter, *, crash_reports: bool = True,
                progress: Callable[[str, int, int], None] | None = None, log: CommandLog | None = None) -> dict:
    log = log or CommandLog()
    progress = progress or log.progress
    from app.services.mobile_acquire.ios_usbmux import call_maybe_async, get_lockdown, resolve_ios_udid

    entry = log.start("lockdown: connect over usbmux (pairing record)")
    try:
        udid = resolve_ios_udid(udid) or udid  # the helper may pass the Windows device path; record the real UDID
        lockdown = get_lockdown(udid)
    except Exception as exc:
        log.end(entry, ok=False, note=str(exc)[:200])
        raise TriageError(f"iPhone not paired or locked: unlock it and tap Trust ({exc})") from exc
    log.end(entry, note=f"UDID {udid}")
    entry = log.start("lockdown: get_value (model, iOS version, build, name)")
    values: dict = {}
    try:  # pymobiledevice3 4.x/5.x: get_value() with no domain/key returns every lockdown value
        values = dict(call_maybe_async(lockdown.get_value) or {})
    except Exception:
        try:
            values = dict(getattr(lockdown, "short_info", None) or {})
        except Exception:
            values = {}
    for key, attr in (("ProductVersion", "product_version"), ("BuildVersion", "product_build_version"),
                      ("DeviceName", "display_name")):
        if not values.get(key):
            try:
                values[key] = getattr(lockdown, attr, None)
            except Exception:
                pass
    log.end(entry, note=" ".join(str(values.get(k) or "") for k in ("ProductType", "ProductVersion")).strip() or None)
    progress("Listing installed apps", 1, 3)
    entry = log.start("installation_proxy: browse (all installed apps)")
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    apps = call_maybe_async(InstallationProxyService(lockdown=lockdown).get_apps, application_type="Any",
                            calculate_sizes=False) or {}
    slim = {bid: {k: v for k, v in (meta or {}).items() if k in IOS_APP_FIELDS} for bid, meta in dict(apps).items()}
    bundle.add_bytes("live/ios_apps.json", json.dumps(slim, indent=1, default=str).encode(), command="installation_proxy browse")
    log.end(entry, note=f"{len(slim)} apps")
    progress("Listing configuration profiles", 2, 3)
    entry = log.start("mobile_config: get_profile_list (configuration profiles)")
    try:
        from pymobiledevice3.services.mobile_config import MobileConfigService

        profiles = call_maybe_async(MobileConfigService(lockdown=lockdown).get_profile_list) or {}
        bundle.add_bytes("live/ios_profiles.json", json.dumps(profiles, indent=1, default=str).encode(),
                         command="mobile_config get_profile_list")
        log.end(entry, note=f"{len((profiles or {}).get('ProfileMetadata') or {})} profiles")
    except Exception as exc:
        bundle.warnings.append(f"configuration profiles unavailable: {exc}"[:240])
        log.end(entry, ok=False, note=str(exc)[:200])
    if crash_reports:
        progress("Copying crash reports (kept on the phone)", 3, 3)
        entry = log.start("crash_reports: pull, erase=False (reports stay on the phone)")
        try:
            from pymobiledevice3.services.crash_reports import CrashReportsManager

            with tempfile.TemporaryDirectory(prefix="aetheris-crash-") as tmp:
                manager = CrashReportsManager(lockdown)
                try:
                    call_maybe_async(manager.pull, tmp, erase=False, progress_bar=False)
                except TypeError:  # older pymobiledevice3 without the progress_bar parameter
                    call_maybe_async(manager.pull, tmp, erase=False)
                count = 0
                for f in sorted(Path(tmp).rglob("*")):
                    if f.is_file():
                        bundle.add_file(f"live/crash_reports/{f.relative_to(tmp).as_posix()}", f, command="crash_reports pull (erase=False)")
                        count += 1
            log.end(entry, note=f"{count} crash reports")
        except Exception as exc:
            bundle.warnings.append(f"crash reports unavailable: {exc}"[:240])
            log.end(entry, ok=False, note=str(exc)[:200])
    return {"platform": "ios", "device_id": udid, "model": values.get("ProductType"), "os_version": values.get("ProductVersion"),
            "build": values.get("BuildVersion"), "device_name": values.get("DeviceName"), "apps": len(slim)}


# -------------------------------------------------------------------------------------------- driver --
def run_triage(*, platform: str, device_id: str, out: Path, examiner: str, legal_authority: str, pull_apks: bool = True,
               crash_reports: bool = True, max_apk_mb: int = 300, max_total_mb: int = 1536, adb: str | None = None,
               progress_file: str | None = None, instance_id: str | None = None, pull_whatsapp: bool = True) -> dict:
    if not legal_authority.strip():
        raise TriageError("legal authority is required before reading a phone")

    log = CommandLog(progress_file)
    started = _now()
    bundle = BundleWriter(out)
    device: dict = {"platform": platform, "device_id": device_id}
    partial_reason = None
    try:
        if platform == "android":
            device = collect_android(device_id, bundle, pull_apks=pull_apks, max_apk_mb=max_apk_mb,
                                     max_total_mb=max_total_mb, adb=adb, instance_id=instance_id,
                                     pull_whatsapp=pull_whatsapp, log=log)
        elif platform == "ios":
            device = collect_ios(device_id, bundle, crash_reports=crash_reports, log=log)
        else:
            raise TriageError(f"unsupported platform {platform}")
    except DeviceGoneError as exc:
        # The phone disconnected mid-read. Keep what was collected (posture, logs, and WhatsApp if it was reached);
        # the scan runs on the partial capture and its Coverage says what is missing.
        partial_reason = str(exc)
        bundle.warnings.append(f"The read did not finish: {exc}. The capture holds what was collected before the phone "
                               "disconnected. Reconnect the phone and read it again for a complete capture.")
    except BaseException:
        bundle.close({"status": "failed"})
        Path(out).unlink(missing_ok=True)
        raise
    manifest = bundle.close({
        "kind": "aetheris-live-triage", "collector_version": COLLECTOR_VERSION, "platform": platform, "device": device,
        "examiner": examiner, "legal_authority": legal_authority, "started_at": started, "finished_at": _now(),
        "host": _platform.node(), "read_only": True, "commands": log.entries, "partial": partial_reason,
        "options": {"pull_apks": pull_apks, "crash_reports": crash_reports, "max_apk_mb": max_apk_mb, "max_total_mb": max_total_mb},
    })
    digest = hashlib.sha256(Path(out).read_bytes()).hexdigest()
    return {"ok": True, "bundle": str(out), "bundle_sha256": digest, "bundle_bytes": Path(out).stat().st_size,
            "files": len(manifest["files"]), "warnings": manifest["warnings"], "device": device,
            "partial": partial_reason}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.services.mobile_acquire.live_triage")
    ap.add_argument("--payload", help="JSON request written by the host helper (overrides the flags below)")
    ap.add_argument("--platform", choices=("android", "ios"))
    ap.add_argument("--device")
    ap.add_argument("--out")
    ap.add_argument("--examiner", default=os.environ.get("USERNAME") or os.environ.get("USER") or "examiner")
    ap.add_argument("--legal-authority", default="")
    ap.add_argument("--no-apks", action="store_true")
    ap.add_argument("--no-crash-reports", action="store_true")
    ap.add_argument("--max-apk-mb", type=int, default=300)
    ap.add_argument("--max-total-mb", type=int, default=1536)
    ap.add_argument("--progress-file")
    ap.add_argument("--result-file")
    a = ap.parse_args(argv)
    req = json.loads(Path(a.payload).read_text(encoding="utf-8-sig")) if a.payload else {}
    result_file = req.get("result_file") or a.result_file
    try:
        result = run_triage(
            platform=req.get("platform") or a.platform, device_id=req.get("device_id") or a.device,
            out=Path(req.get("out") or a.out), examiner=req.get("examiner") or a.examiner,
            legal_authority=req.get("legal_authority") or a.legal_authority,
            pull_apks=bool(req.get("pull_apks", not a.no_apks)), crash_reports=bool(req.get("crash_reports", not a.no_crash_reports)),
            max_apk_mb=int(req.get("max_apk_mb") or a.max_apk_mb), max_total_mb=int(req.get("max_total_mb") or a.max_total_mb),
            progress_file=req.get("progress_file") or a.progress_file, instance_id=req.get("instance_id"),
            pull_whatsapp=req.get("pull_whatsapp", True))
    except Exception as exc:
        result = {"ok": False, "error": str(exc)[:1000]}
    if result_file:
        Path(result_file).write_text(json.dumps(result, indent=1))
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
