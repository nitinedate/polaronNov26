"""Contract tests for independent artifact writer and OCR dispatch cadence."""
from pathlib import Path
import importlib.util
import sys
import types

MODULE = Path(__file__).resolve().parents[1] / 'app/services/mobile_forensic/async_writer.py'


def load_module():
    spec = importlib.util.spec_from_file_location('writer_v81', MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_writer_uses_separate_sessions_and_commits(monkeypatch):
    written = []
    session_mod = types.ModuleType('app.db.session')
    storage_mod = types.ModuleType('app.services.mobile_forensic.storage')
    class Session:
        def __enter__(self):
            written.append('session_open')
            return self
        def __exit__(self, *args):
            written.append('commit')
    def scoped(schema):
        assert schema == 'tenant_test'
        return Session()
    def persist(db, job_id, batch):
        written.append((job_id, tuple(batch)))
    monkeypatch.setitem(sys.modules, 'app.db.session', session_mod)
    monkeypatch.setitem(sys.modules, 'app.services.mobile_forensic.storage', storage_mod)
    session_mod.firm_session = scoped
    storage_mod.persist_artifacts = persist
    with load_module().MobileArtifactWriter('tenant_test', 'job-one', max_pending=2) as writer:
        buf = [1, 2]
        assert writer.submit(buf) == 2
        assert buf == []
        writer.checkpoint()
        assert ('job-one', (1, 2)) in written
    assert written.count('commit') == 1


def test_writer_reports_failed_transaction(monkeypatch):
    import pytest
    session_mod = types.ModuleType('app.db.session')
    storage_mod = types.ModuleType('app.services.mobile_forensic.storage')
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): return False
    session_mod.firm_session = lambda schema: Session()
    def explode(*args): raise ValueError('db write failed')
    storage_mod.persist_artifacts = explode
    monkeypatch.setitem(sys.modules, 'app.db.session', session_mod)
    monkeypatch.setitem(sys.modules, 'app.services.mobile_forensic.storage', storage_mod)
    with pytest.raises(RuntimeError, match='writer transaction failed'):
        with load_module().MobileArtifactWriter('tenant_test', 'job-one') as writer:
            writer.submit([1])
            writer.checkpoint()


def test_writer_requires_scope():
    import pytest
    with pytest.raises(ValueError):
        load_module().MobileArtifactWriter('', 'job-one')


def test_ocr_dispatch_has_no_colon_boolean_literal():
    source = (MODULE.parents[2] / 'tasks.py').read_text()
    assert "jsonb_build_object('early_ocr_dispatched', true" in source
    assert "'{\"early_ocr_dispatched\":true}'" not in source
    assert "early_ocr_dispatch_at" in source


def test_checkpoint_acknowledges_only_committed_batches(monkeypatch):
    import threading
    gate = threading.Event()
    session_mod = types.ModuleType('app.db.session')
    storage_mod = types.ModuleType('app.services.mobile_forensic.storage')
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args):
            assert gate.wait(5), 'commit gate never released'
    session_mod.firm_session = lambda schema: Session()
    storage_mod.persist_artifacts = lambda db, job_id, batch: None
    monkeypatch.setitem(sys.modules, 'app.db.session', session_mod)
    monkeypatch.setitem(sys.modules, 'app.services.mobile_forensic.storage', storage_mod)
    with load_module().MobileArtifactWriter('tenant_test', 'job-one') as writer:
        writer.submit([1, 2, 3])
        assert writer.committed_artifacts == 0
        gate.set()
        assert writer.checkpoint() == 3


def test_writer_failure_does_not_count_queued_batches(monkeypatch):
    import pytest
    session_mod = types.ModuleType('app.db.session')
    storage_mod = types.ModuleType('app.services.mobile_forensic.storage')
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): raise OSError('commit failed')
    session_mod.firm_session = lambda schema: Session()
    storage_mod.persist_artifacts = lambda db, job_id, batch: None
    monkeypatch.setitem(sys.modules, 'app.db.session', session_mod)
    monkeypatch.setitem(sys.modules, 'app.services.mobile_forensic.storage', storage_mod)
    with pytest.raises(RuntimeError, match='writer transaction failed'):
        with load_module().MobileArtifactWriter('tenant_test', 'job-one') as writer:
            writer.submit([1])
            writer.checkpoint()
    assert writer.committed_artifacts == 0
