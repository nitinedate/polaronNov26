"""iOS malware remediation — advisory only, by design.

iOS gives no third-party app the ability to scan or delete other apps (the sandbox),
so there is NO software equivalent of the Android uninstall path. What IS possible,
and what this module produces, is a precise, consented remediation PLAN plus the two
actions a tool can actually perform over a trusted USB connection:

  * list configuration profiles (the main iOS "malware"/MDM-abuse vector) via libimobiledevice;
  * optionally remove an UNSIGNED/user-installed profile with the owner present to confirm.

Everything else (removing an App Store app, clearing mercenary spyware) is a human action:
delete the app, update iOS, and for targeted spyware do a DFU restore to clean iOS or
replace the device. This module never claims to have "cleaned" an iPhone.
"""
from __future__ import annotations

import plistlib
import shutil
import subprocess
from typing import Any


def _tool(name: str) -> str | None:
    return shutil.which(name)


def list_configuration_profiles(udid: str) -> list[dict[str, Any]]:
    """Read installed configuration profiles with `ideviceprofile list` (libimobiledevice)."""
    exe = _tool("ideviceprofile")
    if not exe:
        return []
    res = subprocess.run([exe, "-u", udid, "list"], capture_output=True, timeout=30)
    try:
        data = plistlib.loads(res.stdout or b"")
    except Exception:
        return []
    profiles = data.get("ProfileMetadata", {}) if isinstance(data, dict) else {}
    return [{"identifier": k, "name": v.get("PayloadDisplayName", k),
             "organization": v.get("PayloadOrganization", "")} for k, v in profiles.items()]


def remediation_plan(*, udid: str, suspect_apps: list[str], suspect_profiles: list[str],
                     consent: str) -> dict[str, Any]:
    """A consented plan. Software can only remove unsigned profiles; the rest is guided manual action."""
    if not consent.strip():
        raise ValueError("a consent record is required before changing the device")
    profiles = list_configuration_profiles(udid)
    return {
        "platform": "ios", "udid": udid, "consent": consent,
        "software_removable": {
            "configuration_profiles": [p for p in profiles if p["identifier"] in suspect_profiles],
            "note": "Unsigned/user profiles can be removed with `ideviceprofile remove <id>` with the owner confirming.",
        },
        "manual_actions": [
            {"target": a, "action": "Delete the app from the Home Screen; iOS has no API to uninstall it for you."}
            for a in suspect_apps
        ],
        "escalation": [
            "Update to the latest iOS (closes the exploited vulnerability).",
            "For targeted/mercenary spyware (e.g. Pegasus-class), do a DFU restore to clean iOS, or replace the "
            "device for a high-risk target; enable Lockdown Mode afterwards.",
        ],
        "honesty": "iOS cannot be certified malware-free by software. This plan removes what is removable and "
                   "states the rest as owner actions.",
    }
