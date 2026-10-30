"""Incident-response remediation: remove malware from a consenting Android phone over USB.

THIS IS NOT A FORENSIC READ. It deliberately changes the phone. It is separate from live_triage.py (strictly
read-only) so the forensic path can never be used to write. Removal is used only with the device owner's consent,
to clean a compromised phone, and only AFTER the evidence has been acquired.

For each flagged package it: revokes the exact active device-admin component, turns off its accessibility and
notification-listener grants (so it cannot block its own removal or keep spying), force-stops it, uninstalls it,
then falls back to per-user uninstall and (with root) disable. It deletes residual payload files the scan flagged in
public storage, verifies with a re-list, and classifies every package into exactly what happened — including the
cases software CANNOT fix (device-owner, system-partition, firmware), which are reported with the real escalation
(revoke owner / factory reset / reflash stock firmware). A device is reported "clean" only when nothing is left and
nothing needed an escalation.

Enhancements over the previous version:
  * exact device-admin component (no more guessed '/.DeviceAdminReceiver');
  * device-owner detection (cannot be removed without factory reset);
  * brick-protection denylist (never uninstall core framework/vendor packages);
  * notification-listener revocation; residual public-storage payload cleanup;
  * per-package outcome classification + honest device verdict + infected-app report.
"""
from __future__ import annotations

import json
import os
import platform as _platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.services.mobile_acquire import remediation_core as core


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


def _ok(res: subprocess.CompletedProcess) -> bool:
    return res.returncode == 0


def _has_root(tool: WriteAdb) -> bool:
    return "uid=0" in _text(tool.shell("su -c id 2>/dev/null", 15))


def _notification_listeners(tool: WriteAdb) -> list[str]:
    out = _text(tool.shell("settings get secure enabled_notification_listeners", 15))
    return core.parse_accessibility(out)  # same colon-separated component list format


def remove_package(tool: WriteAdb, package: str, *, has_root: bool, admins: dict[str, str],
                   device_owner: str | None, accessibility: list[str], notif_listeners: list[str],
                   system_pkgs: set[str], residual_paths: list[str] | None = None, on_action=None) -> dict:
    """Remove one package, recording every step and classifying the outcome.

    Returns the core.classify() dict plus 'steps' (each adb command + result).
    """
    steps: list[dict] = []
    residual_paths = residual_paths or []

    def begin(action: str) -> None:
        if on_action:
            on_action(action)

    def step(action: str, res: subprocess.CompletedProcess | None, ok: bool | None = None, note: str | None = None):
        code = None if res is None else res.returncode
        out = note if res is None else (_text(res).strip()[:200] or note)
        steps.append({"action": action, "exit_code": code,
                      "ok": ok if ok is not None else (_ok(res) if res else None),
                      "output": out, "at": _now()})

    was_present = package in core.parse_installed(_text(tool.shell("pm list packages", 60)))

    # 0. Never touch a core system package — report it, don't risk a brick.
    if core.is_protected(package):
        step("skip (protected)", None, ok=True, note="core system package — not removed (brick risk)")
        return _finish(tool, package, steps, present_after=True, uninstalled=False, disabled=False,
                       admin_active_after=package in admins, device_owner=device_owner,
                       is_system=True, had_root=has_root, was_present=was_present)

    if not was_present:
        step("check", None, ok=True, note="package is not installed")
        return _finish(tool, package, steps, present_after=False, uninstalled=False, disabled=False,
                       admin_active_after=False, device_owner=device_owner,
                       is_system=package in system_pkgs, had_root=has_root, was_present=False)

    # 1. Revoke the EXACT active device-admin component (not a guessed receiver name).
    admin_active_after = package in admins
    if package in admins:
        if device_owner == package:
            # A device owner cannot be revoked with remove-active-admin; it needs a factory reset.
            step("device-owner", None, ok=False, note="app is Device Owner — cannot be revoked without factory reset")
        else:
            begin("revoke device-admin")
            res = tool.shell(f"dpm remove-active-admin {admins[package]}", 20)
            if not _ok(res) and has_root:
                res = tool.shell(f"su -c 'dpm remove-active-admin {admins[package]}'", 20)
            step("revoke device-admin", res)
            # confirm it is really gone before we trust the uninstall
            now_admins = core.parse_device_admins(_text(tool.shell("dumpsys device_policy", 30)))
            admin_active_after = package in now_admins

    # 2. Turn off accessibility + notification-listener grants (spyware persistence).
    for label, grants, key in (("accessibility", accessibility, "enabled_accessibility_services"),
                               ("notification listener", notif_listeners, "enabled_notification_listeners")):
        mine = [c for c in grants if c.startswith(package + "/")]
        if mine:
            remaining = ":".join(c for c in grants if not c.startswith(package + "/")) or ""
            begin(f"disable {label}")
            value = f"'{remaining}'" if remaining else "''"
            step(f"disable {label}", tool.shell(f"settings put secure {key} {value}", 15))

    # 3. Force-stop, then uninstall (user-installed apps, no root needed).
    begin("force-stop")
    step("force-stop", tool.shell(f"am force-stop {package}", 20))
    begin("uninstall")
    res = tool.run(["uninstall", package], 60)
    uninstalled = _ok(res) and "Success" in _text(res)
    step("uninstall", res, ok=uninstalled)
    disabled = False

    # 4. Fallbacks when a plain uninstall is refused (system app / protected).
    if not uninstalled and not admin_active_after:
        begin("uninstall --user 0")
        res = tool.shell(f"pm uninstall --user 0 {package}", 60)
        uninstalled = "Success" in _text(res)
        step("uninstall --user 0", res, ok=uninstalled)
    if not uninstalled and has_root and not admin_active_after:
        begin("uninstall (root)")
        res = tool.shell(f"su -c 'pm uninstall --user 0 {package}'", 60)
        uninstalled = "Success" in _text(res)
        step("uninstall (root)", res, ok=uninstalled)
        if not uninstalled:  # embedded: disable so it cannot run
            begin("disable (root)")
            res = tool.shell(f"su -c 'pm disable-user --user 0 {package}'", 30)
            disabled = "new state: disabled" in _text(res).lower()
            step("disable (root)", res, ok=disabled)

    # 5. Residual payload cleanup in PUBLIC storage only (no root, forensically bounded to flagged paths).
    for p in residual_paths:
        if _safe_public_path(p):
            begin("delete residual")
            step(f"delete {p}", tool.shell(f"rm -f -- '{p}'", 20))

    present_after = package in core.parse_installed(_text(tool.shell("pm list packages", 60)))
    return _finish(tool, package, steps, present_after=present_after, uninstalled=uninstalled, disabled=disabled,
                   admin_active_after=admin_active_after, device_owner=device_owner,
                   is_system=package in system_pkgs, had_root=has_root, was_present=was_present)


def _finish(tool, package, steps, **facts) -> dict:
    device_owner = facts.pop("device_owner")
    verdict = core.classify(package, is_device_owner=(device_owner == package), **facts)
    verdict["steps"] = steps
    return verdict


def _safe_public_path(path: str) -> bool:
    """Only ever delete files under public storage — never app-private or system paths."""
    p = (path or "").strip()
    return p.startswith(("/sdcard/", "/storage/emulated/0/", "/data/media/0/")) and ".." not in p


def _collect_context(tool: WriteAdb) -> dict:
    has_root = _has_root(tool)
    dp = _text(tool.shell("dumpsys device_policy", 30))
    return {
        "has_root": has_root,
        "admins": core.parse_device_admins(dp),
        "device_owner": core.parse_device_owner(dp),
        "accessibility": core.parse_accessibility(_text(tool.shell("settings get secure enabled_accessibility_services", 15))),
        "notif_listeners": _notification_listeners(tool),
        "system_pkgs": core.parse_system_packages(_text(tool.shell("pm list packages -s", 60))),
    }


def run_remediation(*, device_id: str, packages: list[str], examiner: str, consent: str,
                     instance_id: str | None = None, adb: str | None = None, progress_file: str | None = None,
                     residual: dict[str, list[str]] | None = None, infected: list[dict] | None = None) -> dict:
    """Remove each package from the connected phone. Requires explicit consent.

    ``residual``  : {package: [public-storage payload paths to delete]} (optional).
    ``infected``  : detection rollup rows (package/label/verdict/risk/signatures/...) so the result can carry the
                    "which app is infected" report alongside the removal outcome (optional).
    """
    from app.services.mobile_acquire.live_triage import resolve_adb_serial

    if not consent or not consent.strip():
        raise RemediationError("a consent record is required before changing the phone")
    if not packages:
        raise RemediationError("no packages to remove")

    serial = resolve_adb_serial(device_id, instance_id, adb)
    tool = WriteAdb(serial, adb)
    state = tool.run(["get-state"], 20)
    if not _ok(state) or _text(state).strip() != "device":
        raise RemediationError("the phone is not connected or not authorised over adb")

    started = _now()
    ctx = _collect_context(tool)
    residual = residual or {}
    results: list[dict] = []

    def emit(done: int, current: str | None = None, action: str | None = None):
        if not progress_file:
            return
        from app.services.mobile_acquire.live_triage import _write_progress_file
        _write_progress_file(progress_file, json.dumps(
            {"status": "running", "done": done, "total": len(packages), "current": current,
             "action": action, "updated_at": _now(), "results": results}))

    emit(0)
    for i, pkg in enumerate(packages, 1):
        results.append(remove_package(
            tool, pkg, has_root=ctx["has_root"], admins=ctx["admins"], device_owner=ctx["device_owner"],
            accessibility=ctx["accessibility"], notif_listeners=ctx["notif_listeners"],
            system_pkgs=ctx["system_pkgs"], residual_paths=residual.get(pkg),
            on_action=lambda action, package=pkg, finished=i - 1: emit(finished, package, action)))
        emit(i)

    verdict = core.device_verdict(results)
    infected_apps = [core.InfectedApp(**_infected_kwargs(row)) for row in (infected or [])]
    infected_report = core.build_infected_report(infected_apps, results) if infected_apps else None

    report = {
        "ok": True, "serial": serial, "root": ctx["has_root"], "device_owner": ctx["device_owner"],
        "examiner": examiner, "consent": consent, "started_at": started, "finished_at": _now(),
        "host": _platform.node(), "requested": packages, "results": results,
        "device_verdict": verdict,                 # clean | partial | needs_reflash + escalations
        "infected_report": infected_report,        # which app is infected, by what, and what was done
        # kept for backward-compatibility with existing callers / the old UI:
        "removed": verdict["removed"], "still_present": verdict["still_present"],
        "collector_version": "2.0.0",
    }
    if progress_file:
        Path(progress_file).write_text(json.dumps({"status": "done", "report": report, "updated_at": _now()}))
    return report


def _infected_kwargs(row: dict) -> dict:
    return {
        "package": row.get("package") or row.get("package_id") or "",
        "label": row.get("label") or row.get("app") or "",
        "verdict": row.get("verdict") or "", "risk_score": float(row.get("risk_score") or 0),
        "install_source": row.get("install_source") or "",
        "signatures": row.get("signatures") or row.get("why_flagged") or [],
        "engines": row.get("engines") or row.get("detected_by") or [],
        "device_admin": bool(row.get("device_admin")), "accessibility": bool(row.get("accessibility")),
        "apk_preserved": bool(row.get("apk_preserved") or row.get("preserved")),
    }


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(description="Remove malware from a consenting phone (incident response; changes the phone).")
    ap.add_argument("--payload", help="JSON request written by the host helper (overrides the flags below)")
    ap.add_argument("--device"); ap.add_argument("--packages", help="comma-separated package names")
    ap.add_argument("--examiner", default=""); ap.add_argument("--consent")
    ap.add_argument("--instance-id", default=None); ap.add_argument("--adb", default=None)
    ap.add_argument("--progress-file", default=None); ap.add_argument("--result-file", default=None)
    a = ap.parse_args(argv)
    req = json.loads(Path(a.payload).read_text(encoding="utf-8-sig")) if a.payload else {}
    packages = req.get("packages") or ([p for p in (a.packages or "").split(",") if p])
    result_file = req.get("result_file") or a.result_file
    try:
        out = run_remediation(
            device_id=req.get("device_id") or a.device, packages=packages,
            examiner=req.get("examiner") or a.examiner, consent=req.get("consent") or a.consent or "",
            instance_id=req.get("instance_id") or a.instance_id, adb=req.get("adb") or a.adb,
            progress_file=req.get("progress_file") or a.progress_file,
            residual=req.get("residual"), infected=req.get("infected"))
    except Exception as exc:
        out = {"ok": False, "error": str(exc)}
        if result_file:
            Path(result_file).write_text(json.dumps(out))
        print(json.dumps(out, indent=2)); raise SystemExit(1)
    if result_file:
        Path(result_file).write_text(json.dumps(out))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
