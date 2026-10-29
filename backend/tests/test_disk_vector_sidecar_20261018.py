"""Offline quality/security tests for the source-preserving GPU vector sidecar."""
from __future__ import annotations

import contextlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import disk_vector_sidecar as sidecar


def test_scheduler_keeps_chunk_rows_and_uses_gpu_queue(monkeypatch):
    settings = SimpleNamespace(rag_embedding_enabled=True)
    import app.config as config
    import app.services.safe_parallel as safe
    monkeypatch.setattr(config, 'get_settings', lambda: settings)
    monkeypatch.setattr(sidecar, 'count_missing_serial_vectors', lambda db, jid: 7)
    events = []
    monkeypatch.setattr(sidecar, 'fetchone', lambda *args, **kwargs: {})
    monkeypatch.setattr(safe, 'ensure_sidecar_schema', lambda db: events.append('ensure_schema'))
    monkeypatch.setattr(safe, 'claim_sidecar', lambda db, jid, name, details: 'claim-uuid')
    gpu_task = SimpleNamespace(apply_async=lambda **kwargs: events.append(kwargs))
    monkeypatch.setitem(sys.modules, 'app.tasks', SimpleNamespace(disk_vector_sidecar_task=gpu_task))
    db = SimpleNamespace(commit=lambda: events.append('commit'))
    result = sidecar.schedule_disk_vectors(db, 'test-job', schema_name='firm1')
    assert result['status'] == 'queued'
    assert events[0] == 'ensure_schema'
    assert events[-1]['queue'] == 'rag-index'
    assert events[-1]['args'] == ('firm1', 'test-job', 'claim-uuid')


def test_vector_sidecar_does_not_recreate_chunk_table_or_write_evidence_rows():
    src = Path(sidecar.__file__).read_text(encoding='utf-8')
    assert 'UPDATE rag_chunks AS c SET embedding_v2' in src
    assert 'AND c.embedding_v2 IS NULL' in src
    assert 'SELECT id::text AS id, content FROM rag_chunks' in src
    assert 'DELETE FROM RAG_CHUNKS' not in src.upper()
    assert 'DROP TABLE' not in src.upper()


def test_vector_sidecar_requires_exact_model_dimension(monkeypatch):
    from app.services import embedding_gpu
    from app.services import job_control
    from app.services import job_locks
    import app.config as config

    settings = SimpleNamespace(rag_embedding_enabled=True, rag_embedding_dim=3,
             rag_embedding_device='cuda', rag_batch_size=2, rag_embedding_model='test/bge')
    monkeypatch.setattr(config, 'get_settings', lambda: settings)
    monkeypatch.setattr(sidecar, 'count_missing_serial_vectors', lambda db, jid: 1)
    monkeypatch.setattr(sidecar, 'fetchall', lambda db, sql, params: [{'id':'11111111-1111-1111-1111-111111111111', 'content':'evidence source A'}])
    monkeypatch.setattr(embedding_gpu, 'resolve_device', lambda device: ('cuda:0 (test)', True))
    monkeypatch.setattr(embedding_gpu, 'embed_texts', lambda *args, **kwargs: [[0.1,0.2]])
    events = []
    monkeypatch.setattr(embedding_gpu, 'unload_embedder', lambda: events.append('unload'))
    monkeypatch.setattr(job_control, 'pipeline_should_stop', lambda db, jid: False)
    monkeypatch.setattr(job_locks, 'gpu_heavy_slot', lambda *args, **kwargs: contextlib.nullcontext(True))
    # Called only after a model output succeeds: avoiding any DB writer dependency.
    extras = types.ModuleType('psycopg2.extras')
    extras.execute_values = lambda *args, **kwargs: None
    psyco = types.ModuleType('psycopg2')
    psyco.__path__ = []
    monkeypatch.setitem(sys.modules,'psycopg2',psyco)
    monkeypatch.setitem(sys.modules,'psycopg2.extras',extras)
    with pytest.raises(RuntimeError, match='dimension mismatch'):
        sidecar.embed_missing_disk_vectors(SimpleNamespace(), 'test-job')
    assert events == ['unload']


def test_cuda_sidecar_registration_is_bound_to_rag_index():
    src = (Path(sidecar.__file__).parents[1] / 'tasks.py').read_text(encoding='utf-8')
    assert '@celery.task(\n    name="app.tasks.disk_vector_sidecar_task"' in src
    assert 'with sidecar_execution(\n                db, job_id, "disk_vectors"' in src
    assert 'finish_sidecar(db, job_id, "disk_vectors", task_id,' in src
    assert 'gpu_heavy_slot("disk_serial_pgvector", fail_closed=True)' in Path(sidecar.__file__).read_text()


def test_vector_backfill_commits_and_resumes_without_rewriting_sources(monkeypatch):
    import app.config as config
    from app.services import embedding_gpu, job_control, job_locks

    ids = ['11111111-1111-1111-1111-111111111111',
           '22222222-2222-2222-2222-222222222222']
    rows = [{'id': k, 'content': f'source {i}', 'embedded': False} for i, k in enumerate(ids)]
    status = {'commit':0, 'model_unloaded':0}
    settings = SimpleNamespace(rag_embedding_enabled=True,rag_embedding_dim=3,
           rag_embedding_device='cuda',rag_batch_size=1,rag_embedding_model='test/3d')
    monkeypatch.setattr(config,'get_settings',lambda: settings)
    monkeypatch.setattr(sidecar,'count_missing_serial_vectors',
                        lambda db, jid: sum(not r['embedded'] for r in rows))
    monkeypatch.setattr(sidecar,'fetchall',lambda db, sql, params: [
        dict(id=r['id'],content=r['content']) for r in rows
        if not r['embedded'] and r['id']>params['after']][:params['lim']])
    monkeypatch.setattr(embedding_gpu,'resolve_device',lambda d: ('cuda:0',True))
    monkeypatch.setattr(embedding_gpu,'embed_texts',lambda texts,**kwargs: [[0.3,0.4,0.5] for _ in texts])
    monkeypatch.setattr(embedding_gpu,'unload_embedder',lambda: status.__setitem__('model_unloaded',status['model_unloaded']+1))
    monkeypatch.setattr(job_control,'pipeline_should_stop',lambda db,jid: False)
    monkeypatch.setattr(job_locks,'gpu_heavy_slot',lambda *args,**kwargs:contextlib.nullcontext(True))

    class FakeCursor:
        def __enter__(self): return self
        def __exit__(self,*exc): return False
    class FakeDB:
        def connection(self): return self
        @property
        def connection_obj(self): return self
        def cursor(self): return FakeCursor()
        def commit(self): status['commit']+=1
    db = FakeDB()
    # SQLAlchemy's .connection().connection.cursor(): the middle .connection is
    # a DBAPI connection attribute rather than a callable on this fake.
    class FakeSession:
        def connection(self): return SimpleNamespace(connection=db)
        def commit(self): status['commit']+=1
    def execute_values(cur,sql,values,**kwargs):
        assert 'AND c.embedding_v2 IS NULL' in sql
        for rid, vector, _jid in values:
            assert vector.startswith('[')
            next(r for r in rows if r['id']==rid)['embedded']=True
    extras = types.ModuleType('psycopg2.extras')
    extras.execute_values=execute_values
    psyco=types.ModuleType('psycopg2');psyco.__path__=[]
    monkeypatch.setitem(sys.modules,'psycopg2',psyco)
    monkeypatch.setitem(sys.modules,'psycopg2.extras',extras)
    result=sidecar.embed_missing_disk_vectors(FakeSession(),'test-job')
    assert result['status']=='ok'
    assert result['embedded']==2
    assert result['pending']==0
    assert status['commit']==1
    assert status['model_unloaded']==1
    # Second delivery is idempotent; all source chunk ids/content are intact.
    result2=sidecar.embed_missing_disk_vectors(FakeSession(),'test-job')
    assert result2['embedded']==0
    assert [(r['id'],r['content']) for r in rows]==list(zip(ids,['source 0','source 1']))
