"""End-to-end remediation orchestration against a simulated device (no phone needed).

Covers: a user-app malware with device-admin+accessibility is removed (exact admin
component revoked, residual payload deleted); a Device Owner is blocked_owner; a
system app with no root is blocked_system; a core package is blocked_protected; the
device verdict is needs_reflash; and the infected report is produced.
"""
import subprocess

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from app.services.mobile_acquire import live_remediate as R


class _CP:
    def __init__(self, out="", code=0):
        self.stdout = out.encode(); self.stderr = b""; self.returncode = code


class _FakeDevice:
    def __init__(self):
        self.installed = {"com.evil.spy", "com.evil.owner", "com.oem.badservice", "com.android.systemui", "com.good"}
        self.system = {"com.oem.badservice", "com.android.systemui"}
        self.admins = {"com.evil.spy": "com.evil.spy/com.evil.spy.receivers.BootAdmin",
                       "com.evil.owner": "com.evil.owner/com.evil.owner.AdminRx"}
        self.owner = "com.evil.owner"
        self.accessibility = ["com.evil.spy/com.evil.spy.MonitorSvc", "com.good/.A11y"]
        self.notif = ["com.evil.spy/com.evil.spy.NotifSvc"]
        self.root = False
        self.deleted_files = []

    def dumpsys(self):
        out = ["Current Device Policy Manager state:"]
        if self.owner:
            out += ["  Device Owner:", f"    package={self.owner}"]
        out += ["  Enabled Device Admins (User 0, provisioningState: 0):"]
        for comp in self.admins.values():
            out += [f"    {comp}:", "      uid=10234"]
        return "\n".join(out)


class _FakeAdb(R.WriteAdb):
    def __init__(self, dev):
        self.serial = "FAKE"; self.adb = "adb"; self.dev = dev

    def run(self, args, timeout):
        d = self.dev
        if args[:1] == ["get-state"]:
            return _CP("device")
        if args[:1] == ["uninstall"]:
            pkg = args[1]
            if pkg in d.admins and pkg in d.installed:
                return _CP("Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]", 1)
            if pkg in d.system:
                return _CP("Failure [not installed for 0]", 1)
            if pkg in d.installed:
                d.installed.discard(pkg); return _CP("Success")
            return _CP("Failure", 1)
        return _CP("")

    def shell(self, command, timeout):
        d = self.dev
        if command.startswith("su -c id"):
            return _CP("uid=0" if d.root else "")
        if command == "pm list packages":
            return _CP("\n".join(f"package:{p}" for p in d.installed))
        if command == "pm list packages -s":
            return _CP("\n".join(f"package:{p}" for p in d.system))
        if command == "dumpsys device_policy":
            return _CP(d.dumpsys())
        if command.startswith("settings get") and "enabled_accessibility_services" in command:
            return _CP(":".join(d.accessibility))
        if command.startswith("settings get") and "enabled_notification_listeners" in command:
            return _CP(":".join(d.notif))
        if command.startswith("settings put secure enabled_accessibility_services"):
            d.accessibility = [c for c in d.accessibility if "com.evil" not in c]; return _CP("")
        if command.startswith("settings put secure enabled_notification_listeners"):
            d.notif = [c for c in d.notif if "com.evil" not in c]; return _CP("")
        if command.startswith("dpm remove-active-admin"):
            comp = command.split("dpm remove-active-admin", 1)[1].strip().strip("'")
            pkg = comp.split("/")[0]
            if pkg == d.owner:
                return _CP("Error: Attempt to remove device owner", 1)
            d.admins.pop(pkg, None); return _CP("Success")
        if command.startswith("am force-stop"):
            return _CP("")
        if command.startswith("pm uninstall --user 0"):
            pkg = command.split()[-1]
            if pkg in d.admins:
                return _CP("Failure [DEVICE_POLICY]", 1)
            if pkg in d.system and not d.root:
                return _CP("Failure [not allowed]", 1)
            if pkg in d.installed:
                d.installed.discard(pkg); return _CP("Success")
            return _CP("Failure", 1)
        if command.startswith("rm -f"):
            d.deleted_files.append(command); return _CP("")
        return _CP("")


def test_remediation_orchestration(monkeypatch):
    dev = _FakeDevice()
    monkeypatch.setattr(R, "WriteAdb", lambda serial, adb=None: _FakeAdb(dev))
    monkeypatch.setattr("app.services.mobile_acquire.live_triage.resolve_adb_serial",
                        lambda device_id, instance_id=None, adb=None: "FAKE")

    infected = [
        {"package": "com.evil.spy", "label": "System Update", "verdict": "malicious", "risk_score": 92,
         "signatures": ["Android.Spyware.Flubot"], "engines": ["yara", "antivirus"],
         "device_admin": True, "accessibility": True, "apk_preserved": True},
        {"package": "com.evil.owner", "label": "Device Help", "verdict": "malicious", "risk_score": 88,
         "signatures": ["Android.Trojan.Banker"], "engines": ["static"], "apk_preserved": True},
        {"package": "com.oem.badservice", "label": "OEM Service", "verdict": "suspicious", "risk_score": 55,
         "signatures": ["PUA.Adware"], "engines": ["reputation"], "apk_preserved": False},
        {"package": "com.android.systemui", "label": "System UI", "verdict": "suspicious", "risk_score": 40,
         "signatures": ["heuristic"], "engines": ["behaviour"], "apk_preserved": False},
    ]
    targets = [r["package"] for r in infected]
    rep = R.run_remediation(device_id="FAKE", packages=targets, examiner="examiner@lab",
                            consent="owner consent, case 2026-27", infected=infected,
                            residual={"com.evil.spy": ["/sdcard/Download/payload.apk"]})

    outcomes = {r["package"]: r["outcome"] for r in rep["results"]}
    assert outcomes["com.evil.spy"] == "removed"
    assert outcomes["com.evil.owner"] == "blocked_owner"
    assert outcomes["com.oem.badservice"] == "blocked_system"
    assert outcomes["com.android.systemui"] == "blocked_protected"
    assert rep["device_verdict"]["state"] == "needs_reflash"
    assert any("payload.apk" in c for c in dev.deleted_files)
    assert "com.evil.spy" not in dev.admins      # exact admin component revoked
    assert "com.evil.spy" not in dev.installed    # and uninstalled
    assert rep["infected_report"]["infected_count"] == 4


if __name__ == "__main__":
    import importlib

    class _MonkeyPatch:
        """Tiny stand-in for pytest's monkeypatch supporting both call forms."""
        def setattr(self, *args):
            if len(args) == 3:                      # setattr(obj, name, value)
                obj, name, value = args
                setattr(obj, name, value)
            elif len(args) == 2:                    # setattr("dotted.path", value)
                target, value = args
                mod, attr = target.rsplit(".", 1)
                setattr(importlib.import_module(mod), attr, value)
            else:
                raise TypeError("setattr takes 2 or 3 positional arguments")

    test_remediation_orchestration(_MonkeyPatch())
    print("ALL ORCHESTRATION TESTS PASSED")
