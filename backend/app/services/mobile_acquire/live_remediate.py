"""Incident-response remediation: remove malware from a consenting victim's Android phone over USB.

THIS IS NOT A FORENSIC READ. It deliberately changes the phone. It is a separate module from live_triage.py (which is
strictly read-only and refuses any state-changing command) so the forensic path can never be used to write. Removal
is used only with the device owner's consent, for cleaning a compromised phone.

For each target package it: revokes device-admin and accessibility (so an app cannot block its own removal), force-stops
it, then uninstalls it. ``adb uninstall`` handles user-installed apps without root; system or deeply embedded apps need
root (``pm uninstall --user 0`` as a fallback, or ``su`` to disable). Every command and its result is recorded.
"""

from __future__ import annotations

import json
import os
import platform as _platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class RemediationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WriteAdb:
    """adb wrapper for remediation. Unlike live_triage.Adb this is ALLOWED to change the phone, by design."""

    def __init__(self, serial: str, adb: str | None = None):
        self.serial = serial
        self.adb = adb or os.environ.get("ANDROID_ADB") or shutil.which("adb") or "adb"

    def run(self, args: list[str], timeout: int) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.adb, "-s", self.serial, *args], capture_output=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise RemediationError("adb not found: install Android platform-tools or set ANDROID_ADB") from exc

    def shell(self, command: str, timeout: int) -> subprocess.CompletedProcess:
        return self.run(["exec-out", command], timeout)


def _text(res: subprocess.CompletedProcess) -> str:
    return (res.stdout or b"").decode("utf-8", "replace") + (res.stderr or b"").decode("utf-8", "replace")


def _has_root(tool: WriteAdb) -> bool:
    res = tool.shell("su -c id 2>/dev/null", 15)
    return "uid=0" in _text(res)


def _device_admins(tool: WriteAdb) -> set[str]:
    out = _text(tool.shell("dumpsys device_policy", 30))
    import re

    admins = set(re.findall(r"^\s{2,}([A-Za-z][\w.]*)/[\w.$]+:?\s*$", out, re.M))
    admins |= set(re.findall(r"ComponentInfo\{([A-Za-z][\w.]+)/", out))
    return admins


def _accessibility_components(tool: WriteAdb) -> list[str]:
    out = _text(tool.shell("settings get secure enabled_accessibility_services", 15))
    return [c.strip() for c in out.replace("\n", ":").split(":") if "/" in c]


def remove_package(tool: WriteAdb, package: str, *, has_root: bool, admins: set[str],
                   accessibility: list[str], on_action=None) -> dict:
    """Remove one package, recording each step. Returns {package, removed, steps:[...]}.

    ``on_action`` is called with the step name before that command runs, so a progress file can name
    the app that is being removed right now.
    """
    steps: list[dict] = []

    def begin(action: str) -> None:
        if on_action:
            on_action(action)

    def step(action: str, res: subprocess.CompletedProcess | None, ok: bool | None = None, note: str | None = None):
        code = None if res is None else res.returncode
        out = "" if res is None else _text(res).strip()[:200]
        steps.append({"action": action, "exit_code": code, "ok": (res.returncode == 0) if (ok is None and res) else ok,
                      "output": out or note, "at": _now()})

    # 1. Revoke device-admin (a device-admin app refuses uninstall until it is removed as admin).
    if package in admins:
        begin("revoke device-admin")
        res = tool.shell(f"dpm remove-active-admin {package}/.DeviceAdminReceiver", 20)
        if res.returncode != 0 and has_root:
            res = tool.shell(f"su -c 'dpm remove-active-admin {package}/.DeviceAdminReceiver'", 20)
        step("revoke device-admin", res)

    # 2. Turn off accessibility service (stalkerware uses it to watch the screen and resist removal).
    acc = [c for c in accessibility if c.startswith(package + "/")]
    if acc:
        remaining = ":".join(c for c in accessibility if not c.startswith(package + "/"))
        begin("disable accessibility")
        res = tool.shell(f"settings put secure enabled_accessibility_services '{remaining}'", 15)
        step("disable accessibility", res)

    # 3. Force-stop, then uninstall.
    begin("force-stop")
    step("force-stop", tool.shell(f"am force-stop {package}", 20))
    begin("uninstall")
    res = tool.run(["uninstall", package], 60)
    removed = res.returncode == 0 and "Success" in _text(res)
    step("uninstall", res, ok=removed)

    # 4. Fallbacks when a normal uninstall is refused (system app, or protected).
    if not removed:
        begin("uninstall --user 0")
        res = tool.shell(f"pm uninstall --user 0 {package}", 60)
        removed = "Success" in _text(res)
        step("uninstall --user 0", res, ok=removed)
    if not removed and has_root:
        begin("uninstall (root)")
        res = tool.shell(f"su -c 'pm uninstall --user 0 {package}'", 60)
        removed = "Success" in _text(res)
        step("uninstall (root)", res, ok=removed)
        if not removed:  # last resort for embedded apps: disable so it cannot run
            begin("disable (root)")
            res = tool.shell(f"su -c 'pm disable-user --user 0 {package}'", 30)
            disabled = "new state: disabled" in _text(res).lower()
            step("disable (root)", res, ok=disabled)
            removed = disabled

    return {"package": package, "removed": removed, "steps": steps}


def _still_installed(tool: WriteAdb, packages: list[str]) -> set[str]:
    out = _text(tool.shell("pm list packages", 60))
    present = {line.split(":", 1)[1].strip() for line in out.splitlines() if line.startswith("package:")}
    return {p for p in packages if p in present}


def run_remediation(*, device_id: str, packages: list[str], examiner: str, consent: str,
                     instance_id: str | None = None, adb: str | None = None,
                     progress_file: str | None = None) -> dict:
    """Remove each package in ``packages`` from the connected phone. Requires an explicit consent string."""
    from app.services.mobile_acquire.live_triage import resolve_adb_serial

    if not consent or not consent.strip():
        raise RemediationError("a consent record is required before changing the phone")
    if not packages:
        raise RemediationError("no packages to remove")

    serial = resolve_adb_serial(device_id, instance_id, adb)
    tool = WriteAdb(serial, adb)
    state = tool.run(["get-state"], 20)
    if state.returncode != 0 or _text(state).strip() != "device":
        raise RemediationError("the phone is not connected or not authorised over adb")

    started = _now()
    has_root = _has_root(tool)
    admins = _device_admins(tool)
    accessibility = _accessibility_components(tool)
    results = []

    def emit(done: int, current: str | None = None, action: str | None = None):
        if not progress_file:
            return
        body = {"status": "running", "done": done, "total": len(packages), "current": current, "action": action,
                "updated_at": _now(), "results": results}
        from app.services.mobile_acquire.live_triage import _write_progress_file

        _write_progress_file(progress_file, json.dumps(body))

    emit(0)
    for i, pkg in enumerate(packages, 1):
        results.append(remove_package(
            tool, pkg, has_root=has_root, admins=admins, accessibility=accessibility,
            on_action=lambda action, package=pkg, finished=i - 1: emit(finished, package, action)))
        emit(i)

    still = _still_installed(tool, packages)
    report = {
        "ok": True, "serial": serial, "root": has_root, "examiner": examiner, "consent": consent,
        "started_at": started, "finished_at": _now(), "host": _platform.node(),
        "requested": packages, "results": results,
        "removed": [r["package"] for r in results if r["removed"]],
        "still_present": sorted(still),
        "collector_version": "1.0.0",
    }
    if progress_file:
        Path(progress_file).write_text(json.dumps({"status": "done", "report": report, "updated_at": _now()}))
    return report


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(description="Remove malware from a consenting phone (incident response; changes the phone).")
    ap.add_argument("--payload", help="JSON request written by the host helper (overrides the flags below)")
    ap.add_argument("--device")
    ap.add_argument("--packages", help="comma-separated package names")
    ap.add_argument("--examiner", default="")
    ap.add_argument("--consent", help="consent record, e.g. 'owner consent, case 123'")
    ap.add_argument("--instance-id", default=None)
    ap.add_argument("--adb", default=None)
    ap.add_argument("--progress-file", default=None)
    ap.add_argument("--result-file", default=None)
    a = ap.parse_args(argv)
    req = json.loads(Path(a.payload).read_text(encoding="utf-8-sig")) if a.payload else {}
    packages = req.get("packages") or ([p for p in (a.packages or "").split(",") if p])
    result_file = req.get("result_file") or a.result_file
    try:
        out = run_remediation(device_id=req.get("device_id") or a.device, packages=packages,
                              examiner=req.get("examiner") or a.examiner, consent=req.get("consent") or a.consent or "",
                              instance_id=req.get("instance_id") or a.instance_id, adb=req.get("adb") or a.adb,
                              progress_file=req.get("progress_file") or a.progress_file)
    except Exception as exc:  # record the failure where the helper can read it
        out = {"ok": False, "error": str(exc)}
        if result_file:
            Path(result_file).write_text(json.dumps(out))
        print(json.dumps(out, indent=2))
        raise SystemExit(1)
    if result_file:
        Path(result_file).write_text(json.dumps(out))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
