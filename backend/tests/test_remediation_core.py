"""Unit tests for the pure remediation logic (no device needed)."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from app.services.mobile_acquire import remediation_core as C

DUMPSYS = """Current Device Policy Manager state:
  Device Owner:
    admin=ComponentInfo{com.evil.owner/com.evil.owner.AdminRx}
    package=com.evil.owner
    User ID: 0
  Enabled Device Admins (User 0, provisioningState: 0):
    com.evil.spy/com.evil.spy.receivers.BootAdmin:
      uid=10234
    com.evil.owner/com.evil.owner.AdminRx:
      uid=10240
"""


def test_parse_device_admins_uses_exact_component():
    admins = C.parse_device_admins(DUMPSYS)
    # the exact receiver must be read, not guessed as "/.DeviceAdminReceiver"
    assert admins["com.evil.spy"] == "com.evil.spy/com.evil.spy.receivers.BootAdmin"
    assert "com.evil.owner" in admins


def test_parse_device_owner_and_accessibility():
    assert C.parse_device_owner(DUMPSYS) == "com.evil.owner"
    acc = C.parse_accessibility("com.evil.spy/com.evil.spy.MonitorSvc:com.good/.A11y")
    assert acc == ["com.evil.spy/com.evil.spy.MonitorSvc", "com.good/.A11y"]
    assert C.parse_accessibility("null") == []


def test_brick_protection():
    assert C.is_protected("com.android.systemui")
    assert C.is_protected("com.qualcomm.anything")
    assert not C.is_protected("com.evil.spy")


def test_classification_outcomes():
    base = dict(admin_active_after=False, is_device_owner=False, is_system=False, had_root=False, was_present=True)
    assert C.classify("com.evil.spy", present_after=False, uninstalled=True, disabled=False, **base)["outcome"] == "removed"
    assert C.classify("com.evil.owner", present_after=True, uninstalled=False, disabled=False,
                      **{**base, "is_device_owner": True, "admin_active_after": True})["outcome"] == "blocked_owner"
    assert C.classify("com.oem.bad", present_after=True, uninstalled=False, disabled=False,
                      **{**base, "is_system": True})["outcome"] == "blocked_system"
    assert C.classify("com.evil.spy", present_after=True, uninstalled=False, disabled=False,
                      **{**base, "admin_active_after": True})["outcome"] == "blocked_admin"
    assert C.classify("com.evil.embed", present_after=True, uninstalled=False, disabled=True,
                      **{**base, "is_system": True, "had_root": True})["outcome"] == "disabled"
    assert C.classify("com.android.systemui", present_after=True, uninstalled=False, disabled=False,
                      **{**base, "is_system": True})["outcome"] == "blocked_protected"
    assert C.classify("com.evil.old", present_after=False, uninstalled=False, disabled=False,
                      **{**base, "was_present": False})["outcome"] == "not_present"


def test_device_verdict():
    def c(outcome):
        return {"package": "p." + outcome, "outcome": outcome,
                "cleared": outcome in ("removed", "not_present"),
                "neutralised": outcome in ("removed", "not_present", "disabled"),
                "recommendation": C.RECOMMENDATION.get(outcome)}
    assert C.device_verdict([c("removed"), c("not_present")])["state"] == "clean"
    assert C.device_verdict([c("removed"), c("disabled")])["state"] == "partial"
    v = C.device_verdict([c("removed"), c("blocked_owner"), c("blocked_system")])
    assert v["state"] == "needs_reflash" and len(v["needs_escalation"]) == 2


def test_infected_report():
    apps = [
        C.InfectedApp(package="com.evil.spy", label="System Update", verdict="malicious", risk_score=92,
                      signatures=["Android.Spyware.Flubot"], engines=["yara", "antivirus"],
                      device_admin=True, accessibility=True, apk_preserved=True),
        C.InfectedApp(package="com.evil.owner", label="Device Help", verdict="malicious", risk_score=88,
                      signatures=["Android.Trojan.Banker"], engines=["static"], apk_preserved=True),
    ]
    rep = C.build_infected_report(apps)
    assert rep["infected_count"] == 2 and rep["malicious"] == 2
    assert rep["applications"][0]["package"] == "com.evil.spy"
    assert rep["applications"][0]["why_flagged"] == ["Android.Spyware.Flubot"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("PASS", name)
    print("ALL CORE TESTS PASSED")
