"""Pure, side-effect-free logic for Android malware remediation.

Split out of live_remediate.py so it can be unit-tested without a phone: ADB
output parsing, a brick-protection denylist, per-package outcome classification,
the overall device verdict, and the infected-application report. live_remediate.py
supplies the ADB I/O; everything that decides *what a result means* lives here.

Design honesty: software cannot guarantee a phone is malware-free. This module
classifies each package into exactly what happened and, when it could not be
removed, the real-world escalation (revoke owner / factory reset / reflash stock
firmware / replace device). A device is only ever reported "clean" when every
flagged package is gone AND nothing needed an escalation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# --- Brick protection -------------------------------------------------------
# Never uninstall/disable these even if a scanner flags them: removing core
# framework/vendor packages can soft-brick the phone. A flagged core package is
# reported as "blocked_protected" with a reflash recommendation instead.
PROTECTED_PACKAGES = frozenset({
    "android", "com.android.systemui", "com.android.settings", "com.android.phone",
    "com.android.shell", "com.android.providers.settings", "com.android.providers.telephony",
    "com.android.providers.contacts", "com.android.providers.media", "com.android.providers.downloads",
    "com.android.keychain", "com.android.server.telecom", "com.android.vending",
    "com.google.android.gms", "com.google.android.gsf", "com.google.android.packageinstaller",
    "com.android.packageinstaller", "com.android.permissioncontroller",
    "com.samsung.android.providers.contacts", "com.sec.android.app.launcher",
})
PROTECTED_PREFIXES = (
    "com.android.internal.", "com.qualcomm.", "com.mediatek.", "com.android.systemui.",
    "com.android.cts.", "android.ext.", "com.android.hardware.",
)


def is_protected(package: str) -> bool:
    p = (package or "").strip()
    if p in PROTECTED_PACKAGES:
        return True
    return any(p.startswith(pre) for pre in PROTECTED_PREFIXES)


# --- ADB output parsing (exact, not guessed) --------------------------------
_ADMIN_COMPONENT = re.compile(r"([A-Za-z][\w.]+)/([\w.$]+)")


def parse_device_admins(dumpsys_device_policy: str) -> dict[str, str]:
    """Return {package: full component 'pkg/Receiver'} for every ENABLED device admin.

    The real receiver name is almost never '.DeviceAdminReceiver'; guessing it is
    why admin-holding malware survives removal. We read the exact component from
    `dumpsys device_policy` so `dpm remove-active-admin` targets the right one.
    """
    admins: dict[str, str] = {}
    in_admins = False
    for line in (dumpsys_device_policy or "").splitlines():
        if re.search(r"Enabled Device Admins|Admin:|Active admins", line):
            in_admins = True
        # Component lines look like "  com.evil/com.evil.Admin:" or "admin=ComponentInfo{pkg/recv}"
        for pkg, recv in _ADMIN_COMPONENT.findall(line):
            if "." in pkg and (in_admins or "ComponentInfo" in line or "admin=" in line):
                admins.setdefault(pkg, f"{pkg}/{recv}")
    return admins


def parse_device_owner(dumpsys_device_policy: str) -> str | None:
    """Return the device-owner package if one is set.

    A device-owner cannot be removed with `dpm remove-active-admin`; it requires a
    factory reset. Detecting it lets us say so instead of silently failing.
    """
    text = dumpsys_device_policy or ""
    m = re.search(r"Device Owner:\s*.*?(?:package=|admin=ComponentInfo\{)([A-Za-z][\w.]+)", text, re.S)
    if m:
        return m.group(1)
    return None


def parse_accessibility(settings_value: str) -> list[str]:
    """Split `settings get secure enabled_accessibility_services` into components."""
    raw = (settings_value or "").strip()
    if raw.lower() in ("", "null"):
        return []
    return [c.strip() for c in raw.replace("\n", ":").split(":") if "/" in c]


def parse_installed(pm_list_packages: str) -> set[str]:
    out = set()
    for line in (pm_list_packages or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            out.add(line.split(":", 1)[1].strip())
    return out


def parse_system_packages(pm_list_packages_s: str) -> set[str]:
    """`pm list packages -s` = system packages (can't be plain-uninstalled)."""
    return parse_installed(pm_list_packages_s)


# --- Outcome classification -------------------------------------------------
OUTCOME_LABELS = {
    "removed":            "Removed",
    "disabled":           "Disabled (could not uninstall; blocked from running)",
    "not_present":        "Already not installed",
    "blocked_protected":  "Not removed — core system package (brick risk)",
    "blocked_owner":      "Not removed — app is Device Owner",
    "blocked_admin":      "Not removed — active device-admin could not be revoked",
    "blocked_system":     "Not removed — system app and device is not rooted",
    "failed":             "Not removed — removal failed",
}
# recommendation shown to the operator for each non-clean outcome
RECOMMENDATION = {
    "blocked_protected": "Do not uninstall this package. If it is genuinely compromised, reflash clean stock firmware.",
    "blocked_owner":     "This app controls the device as Device Owner. It cannot be removed without a factory reset "
                         "(Settings ▸ System ▸ Reset), after which re-provision the device cleanly.",
    "blocked_admin":     "Revoke the app's device-admin manually (Settings ▸ Security ▸ Device admin apps), then re-run "
                         "removal. If it reactivates itself, the device likely needs a factory reset.",
    "blocked_system":    "This is a system/pre-installed app. Remove it per-user with root, or reflash clean stock "
                         "firmware. Factory reset alone will NOT remove a system-partition app.",
    "failed":            "Removal failed. Capture logs, retry with the device unlocked and screen on; if it persists, "
                         "factory reset or reflash.",
    "disabled":          "App was disabled, not deleted (embedded). Reflash stock firmware to remove it fully.",
}


def classify(package: str, *, present_after: bool, uninstalled: bool, disabled: bool,
             admin_active_after: bool, is_device_owner: bool, is_system: bool,
             had_root: bool, was_present: bool) -> dict[str, Any]:
    """Decide the single outcome for one package from the facts gathered."""
    if is_protected(package):
        outcome = "blocked_protected"
    elif not was_present:
        outcome = "not_present"
    elif uninstalled and not present_after:
        outcome = "removed"
    elif disabled and present_after:
        outcome = "disabled"
    elif is_device_owner and present_after:
        outcome = "blocked_owner"
    elif admin_active_after and present_after:
        outcome = "blocked_admin"
    elif is_system and not had_root and present_after:
        outcome = "blocked_system"
    else:
        outcome = "failed"
    rec = RECOMMENDATION.get(outcome)
    return {
        "package": package,
        "outcome": outcome,
        "outcome_label": OUTCOME_LABELS[outcome],
        "cleared": outcome in ("removed", "not_present"),
        "neutralised": outcome in ("removed", "not_present", "disabled"),
        "recommendation": rec,
    }


# --- Device-level verdict ---------------------------------------------------
def device_verdict(classified: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll per-package outcomes up to an honest device state.

    clean         — every flagged app removed/absent.
    partial       — some neutralised (disabled) or some still blocked at user level.
    needs_reflash — at least one package needs factory-reset/reflash to remove.
    """
    if not classified:
        return {"state": "clean", "summary": "No flagged applications to remove.",
                "removed": [], "disabled": [], "still_present": [], "needs_escalation": []}
    removed = [c["package"] for c in classified if c["outcome"] in ("removed", "not_present")]
    disabled = [c["package"] for c in classified if c["outcome"] == "disabled"]
    escalate = [c for c in classified if c["outcome"] in
                ("blocked_owner", "blocked_system", "blocked_protected")]
    still = [c["package"] for c in classified if not c["neutralised"]]
    if escalate:
        state = "needs_reflash"
    elif disabled or still:
        state = "partial"
    else:
        state = "clean"
    summaries = {
        "clean": "All flagged applications were removed. "
                 "Note: software removal cannot detect or remove firmware/bootloader-level implants.",
        "partial": "Flagged applications were neutralised but not all deleted; review the per-app actions.",
        "needs_reflash": "One or more threats cannot be removed by software and require a factory reset or a "
                         "clean firmware reflash. The device must NOT be considered clean until then.",
    }
    return {
        "state": state, "summary": summaries[state],
        "removed": sorted(removed), "disabled": sorted(disabled),
        "still_present": sorted(still),
        "needs_escalation": [{"package": c["package"], "outcome": c["outcome"],
                              "recommendation": c["recommendation"]} for c in escalate],
    }


# --- Infected-application report (the "which app is infected" deliverable) ---
@dataclass
class InfectedApp:
    package: str
    label: str = ""
    verdict: str = ""            # malicious | suspicious
    risk_score: float = 0.0
    install_source: str = ""
    signatures: list[str] = field(default_factory=list)   # families/signatures that flagged it
    engines: list[str] = field(default_factory=list)      # which engines flagged it
    device_admin: bool = False
    accessibility: bool = False
    apk_preserved: bool = False


def build_infected_report(apps: list[InfectedApp], classified: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Join detection (which app is infected, by what) with removal outcome."""
    outcome_by_pkg = {c["package"]: c for c in (classified or [])}
    items = []
    for a in sorted(apps, key=lambda x: (x.verdict != "malicious", -x.risk_score)):
        c = outcome_by_pkg.get(a.package, {})
        items.append({
            "package": a.package, "app": a.label or a.package, "verdict": a.verdict,
            "risk_score": round(a.risk_score, 1), "install_source": a.install_source or "unknown",
            "why_flagged": a.signatures, "detected_by": a.engines,
            "holds_device_admin": a.device_admin, "uses_accessibility": a.accessibility,
            "apk_preserved": a.apk_preserved,
            "removal_outcome": c.get("outcome"), "removal_label": c.get("outcome_label"),
            "recommendation": c.get("recommendation"),
        })
    return {
        "infected_count": len(items),
        "malicious": sum(1 for a in apps if a.verdict == "malicious"),
        "suspicious": sum(1 for a in apps if a.verdict == "suspicious"),
        "applications": items,
    }
