"""The Android ADB adapter runs the WhatsApp decrypt agent inside acquire().

No device: the adapter's own ADB calls and the decrypt agent are both stubbed,
so this checks wiring (the agent is invoked, its files and gaps reach the
AcquisitionOutcome, and authorization is forwarded) rather than real decryption.
"""
from __future__ import annotations

from pathlib import Path

from app.services.mobile_acquire.adapters.android_adb import AndroidAdbAdapter
from app.services.mobile_acquire.device_profile import DeviceProfile
from app.services.mobile_acquire.methods import CollectionMethod


class _Proc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def _neutralize_collection(adapter, monkeypatch):
    # The adapter's collection helpers would shell out to adb; stub them.
    monkeypatch.setattr(adapter, "_adb", lambda *a, **k: _Proc("device"))
    monkeypatch.setattr(adapter, "_collect_state", lambda *a, **k: None)
    monkeypatch.setattr(adapter, "_pull_targets", lambda *a, **k: None)


def test_agent_runs_and_records_outputs(monkeypatch, tmp_path):
    adapter = AndroidAdbAdapter()
    _neutralize_collection(adapter, monkeypatch)

    captured = {}

    class _FakeAgent:
        def run(self, req):
            captured["authorized_actions"] = req.authorized_actions
            captured["key"] = req.supplied_64_digit_key
            captured["intake"] = req.intake_key_candidates
            req.out_dir.mkdir(parents=True, exist_ok=True)
            (req.out_dir / "decrypted").mkdir(exist_ok=True)
            db = req.out_dir / "decrypted" / "msgstore.db"
            db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
            from app.services.mobile_acquire.whatsapp_decrypt_agent import DecryptAgentResult
            r = DecryptAgentResult(ok=True)
            r.decrypted_databases.append({"database": str(db)})
            r.limitations.append("agent ran")
            return r

        def write_manifest(self, req, res):
            return req.out_dir / "whatsapp_decrypt_agent_manifest.json"

    import app.services.mobile_acquire.whatsapp_decrypt_agent as mod
    monkeypatch.setattr(mod, "WhatsAppDecryptAgent", lambda *a, **k: _FakeAgent())

    profile = DeviceProfile(os_family="android", serial="SERIAL123")
    outcome = adapter.acquire(
        profile=profile,
        method=CollectionMethod.LOGICAL,
        destination=tmp_path,
        authorized_actions=["whatsapp_generate_key_and_backup"],
        whatsapp_64_digit_key="a" * 64,
        intake_key_candidates=["b" * 64],
    )

    # Authorization and keys were forwarded to the agent request.
    assert captured["authorized_actions"] == ("whatsapp_generate_key_and_backup",)
    assert captured["key"] == "a" * 64
    assert captured["intake"] == ("b" * 64,)
    # The decrypted db is registered on the acquisition outcome.
    assert any(str(p).endswith("msgstore.db") for p in outcome.files_written)
    assert "agent ran" in outcome.coverage_gaps


def test_agent_error_never_fails_the_acquisition(monkeypatch, tmp_path):
    adapter = AndroidAdbAdapter()
    _neutralize_collection(adapter, monkeypatch)

    import app.services.mobile_acquire.whatsapp_decrypt_agent as mod

    def _boom(*a, **k):
        raise RuntimeError("adb exploded")

    monkeypatch.setattr(mod, "WhatsAppDecryptAgent", _boom)
    profile = DeviceProfile(os_family="android", serial="S")
    outcome = adapter.acquire(profile=profile, method=CollectionMethod.LOGICAL, destination=tmp_path)
    assert any("decrypt agent error" in w for w in outcome.warnings)


def test_default_acquire_is_read_only(monkeypatch, tmp_path):
    """With no authorized_actions, the agent is not told to modify the device."""
    adapter = AndroidAdbAdapter()
    _neutralize_collection(adapter, monkeypatch)
    captured = {}

    class _A:
        def run(self, req):
            captured["authorized_actions"] = req.authorized_actions
            from app.services.mobile_acquire.whatsapp_decrypt_agent import DecryptAgentResult
            return DecryptAgentResult(ok=True)

        def write_manifest(self, req, res):
            return Path(req.out_dir) / "m.json"

    import app.services.mobile_acquire.whatsapp_decrypt_agent as mod
    monkeypatch.setattr(mod, "WhatsAppDecryptAgent", lambda *a, **k: _A())
    adapter.acquire(profile=DeviceProfile(os_family="android", serial="S"),
                    method=CollectionMethod.FILE_SYSTEM, destination=tmp_path)
    assert captured["authorized_actions"] == ()


def test_orchestrator_does_not_pass_agent_kwargs_to_a_plain_adapter():
    """A simulated android_adb adapter without the new kwargs is never broken."""
    from app.services.mobile_acquire.orchestrator import _acquire_accepts

    class _Plain:
        name = "android_adb"
        def acquire(self, *, profile, method, destination, progress=None, cancel=None):
            return None

    class _Real:
        name = "android_adb"
        def acquire(self, *, profile, method, destination, progress=None, cancel=None,
                    authorized_actions=None, whatsapp_64_digit_key="", intake_key_candidates=None):
            return None

    class _Kwargs:
        name = "android_adb"
        def acquire(self, **kwargs):
            return None

    assert _acquire_accepts(_Plain(), "authorized_actions") is False
    assert _acquire_accepts(_Real(), "authorized_actions") is True
    assert _acquire_accepts(_Kwargs(), "authorized_actions") is True
