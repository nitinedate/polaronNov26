from types import SimpleNamespace
from app.services import job_delete


class FakeDB:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0
        self.deleted = False
    def commit(self): self.commits += 1
    def rollback(self): self.rollbacks += 1
    def execute(self, statement, params):
        self.deleted = True
        return SimpleNamespace(rowcount=1)


def test_delete_db_commit_not_blocked_by_external_cleanup(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(job_delete, 'fetchone', lambda db, sql, params=None: (
        {'id':'job-1','celery_task_id':None,'disk_source':{}} if 'SELECT * FROM jobs' in sql
        else {'c':0}
    ))
    monkeypatch.setattr(job_delete, '_purge_celery_for_job', lambda *a, **k: 0)
    monkeypatch.setattr(job_delete, '_purge_job_locks', lambda *a, **k: None)
    monkeypatch.setattr(job_delete, '_child_tables_with_job_id', lambda db: [])
    monkeypatch.setattr(job_delete, '_try_execute', lambda *a, **k: 0)
    monkeypatch.setattr(job_delete, '_purge_neo4j_job', lambda jid: (_ for _ in ()).throw(RuntimeError('neo down')))
    monkeypatch.setattr(job_delete, '_purge_job_files', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('minio down')))
    import app.services.job_control as jc
    monkeypatch.setattr(jc, 'request_job_stop', lambda db, jid: None)
    result = job_delete.hard_delete_job(db, 'job-1')
    assert result['ok'] is True and result['deleted'] is True
    assert db.deleted is True and db.commits >= 2
    assert len(result['cleanup_warnings']) == 2
