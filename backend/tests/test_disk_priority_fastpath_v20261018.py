"""Strict safety scope for deferred Windows resource header reads.

These fast paths do not change disk acquisition or source hashes. The fallback
record truthfully states that its signature was not examined.
"""
from types import SimpleNamespace
from app.services.disk_priority_fastpath import (
    can_defer_fallback_signature, deferred_signature_artifact, shard_stream_budget,
)


def item(path, **meta):
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return SimpleNamespace(path=path, extension=ext, size=1024,
                           sha256="0" * 64, mime_hint="", meta=meta)


def allowed(source, parsers=("forensic_fallback",), mode="safe_deferred", **opts):
    names = [SimpleNamespace(name=name) for name in parsers]
    return can_defer_fallback_signature(source, names, [source], mode=mode,
                                        web_text=opts.get("web_text", False),
                                        storage=opts.get("storage", False))


def test_only_known_os_resources_may_defer_signature():
    assert allowed(item("G:/Windows/WinSxS/amd64_x/aaa.dll"))
    assert allowed(item("Windows/WinSxS/amd64_x/aaa.dll"))
    assert allowed(item("Windows/System32/example.mui"))
    assert allowed(item("C:/Windows/System32/example.mui"))
    assert not allowed(item("C:/Users/Employee/Downloads/a.dll"))
    assert not allowed(item("C:/Windows/System32/forensic.db"))
    assert not allowed(item("C:/Windows/System32/a.dat"))
    assert not allowed(item("C:/Windows/System32/strange.dll"), parsers=("forensic_fallback", "messaging"))
    assert not allowed(item("C:/Windows/System32/a.dll", is_deleted=True))
    assert not allowed(item("C:/Windows/System32/a.dll"), mode="full")
    assert not allowed(item("C:/Windows/System32/a.dll"), web_text=True)
    assert not allowed(item("C:/Windows/System32/a.dll"), storage=True)


def test_full_source_budgets_never_masquerade_prefix_as_full():
    a = item("C:/Users/bob/Documents/browser.db")
    assert shard_stream_budget(a, [SimpleNamespace(name="browser")]) == a.size
    assert shard_stream_budget(a, [SimpleNamespace(name="forensic_fallback")]) is None
    a.size = 120 * 1024 * 1024
    assert shard_stream_budget(a, [SimpleNamespace(name="browser")]) is None
    a.size = 0
    assert shard_stream_budget(a, [SimpleNamespace(name="browser")]) is None
    a = item("C:/Users/bob/inbox.eml")
    assert shard_stream_budget(a, [SimpleNamespace(name="forensic_fallback")]) == 16 * 1024 * 1024


def test_deferred_record_remains_source_linked_and_transparently_unexamined(monkeypatch):
    from app.services import disk_priority_fastpath as fast
    received = []
    class Model:
        @staticmethod
        def create(**kwargs):
            received.append(kwargs)
            return SimpleNamespace(**kwargs)
    import sys
    import types
    mod = types.ModuleType("app.services.mobile_forensic.models")
    mod.NormalizedArtifact = Model
    monkeypatch.setitem(sys.modules, "app.services.mobile_forensic.models", mod)
    it = item("C:/Windows/System32/test.dll")
    out = deferred_signature_artifact(it, SimpleNamespace(job_id="case-1", source_id="source-1"))
    assert out.artifact_type == "unclassified_file"
    assert out.state == "unsupported"
    assert out.data["sha256"] == it.sha256
    assert out.data["signature_examination_pending"] is True
    assert out.data["recognition"] == "signature_not_examined"
    assert out.source_path == it.path
    assert out.source_id == "source-1"
