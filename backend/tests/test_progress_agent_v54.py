from app.services import progress_agent as progress


def _stage(**kw):
    base = {
        'id': 'stage-1', 'stage': 'parse', 'status': 'running',
        'total_items': 100, 'completed_items': 100,
        'failed_items': 0, 'skipped_items': 0,
    }
    base.update(kw)
    return base


def test_count_complete_parse_with_no_remaining_is_reconciled(monkeypatch):
    updates = []
    def fake_fetchone(db, sql, params=None):
        if 'pipeline_work_items' in sql:
            return {'pending': 0, 'running': 0}
        if 'parse_status' in sql:
            return {'pending': 0, 'running': 0}
        raise AssertionError(sql)
    monkeypatch.setattr(progress, 'fetchone', fake_fetchone)
    monkeypatch.setattr(progress, 'execute', lambda db, sql, params=None: updates.append((sql, params)))
    result = progress.reconcile_count_complete_stage(object(), 'job-1', _stage())
    assert result['completed'] is False
    assert result['remaining']['producer_finalization'] == 1
    assert not any("status='done'" in sql for sql, _ in updates)


def test_count_complete_parse_exposes_exact_remaining(monkeypatch):
    updates = []
    def fake_fetchone(db, sql, params=None):
        if 'pipeline_work_items' in sql:
            return {'pending': 2, 'running': 1}
        if 'parse_status' in sql:
            return {'pending': 3, 'running': 4}
        raise AssertionError(sql)
    monkeypatch.setattr(progress, 'fetchone', fake_fetchone)
    monkeypatch.setattr(progress, 'execute', lambda db, sql, params=None: updates.append((sql, params)))
    result = progress.reconcile_count_complete_stage(object(), 'job-1', _stage())
    assert result['completed'] is False
    assert result['remaining']['parse_pending'] == 3
    assert result['remaining']['parse_running'] == 4
    assert 'producer_finalization' not in result['remaining']
    assert 'files waiting to parse' in result['summary']
    assert not any("status='done'" in sql for sql, _ in updates)


def test_not_reconciled_before_denominator_is_accounted(monkeypatch):
    monkeypatch.setattr(progress, 'fetchone', lambda *a, **k: (_ for _ in ()).throw(AssertionError('should not query')))
    assert progress.reconcile_count_complete_stage(object(), 'job-1', _stage(completed_items=99)) is None
