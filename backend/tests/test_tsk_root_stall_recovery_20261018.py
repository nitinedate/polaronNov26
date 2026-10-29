"""New regression tests for parallel-root stall, serial fallback and attempt clocks."""
from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

from app.services import tsk_walk_isolated, virtual_disk, progress_agent


def test_failed_parallel_root_falls_back_to_serial_then_alternate(monkeypatch):
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '2')
    monkeypatch.setenv('EXTRACT_TSK_ROOT_PREFERRED', 'path')
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths': ['/fake/seg.E01']})
    original_popen = subprocess.Popen
    modes = []
    def fake_popen(args, **kwargs):
        plan = json.loads(open(args[-2], encoding='utf8').read())
        modes.append((plan['root_open_strategy'], plan['inventory_workers_override']))
        if len(modes) < 3:
            return original_popen([sys.executable, '-c', 'raise SystemExit(3)'], **kwargs)
        script = ("import json,sys;open(sys.argv[1],'w').write(json.dumps({'path':'File.txt'})+'\\n');"
                  "print(json.dumps({'kind':'done','count':1}))")
        return original_popen([sys.executable, '-c', script, args[-1]], **kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess, 'Popen', fake_popen)
    events = []
    result = tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='job'),
                    retries=3, on_progress=lambda m,d: events.append(d))
    assert result == [{'path': 'File.txt'}]
    assert modes == [('inode', None), ('inode', 1), ('path', 1)]
    starts = [e for e in events if e.get('action') == 'tsk_walk_attempt_started']
    assert [e['attempt'] for e in starts] == [1, 2, 3]
    assert len({e['reader_attempt_started_at'] for e in starts}) == 3
    assert [e['inventory_mode'] for e in starts] == ['parallel', 'serial', 'serial']


def test_attempt_restart_is_distinct_from_periodic_heartbeat_and_io_trace():
    job = {'pipeline_progress': {'extraction_activity': {
        'subphase': 'enumerating', 'reader_attempt_started_at': '2026-10-18T08:37:38+00:00',
        'reader_attempt': 1, 'reader_phase': 'root_open', 'files_found': 0, 'entries_scanned': 0}}}
    old = progress_agent.acquisition_fingerprint(job)
    job['pipeline_progress']['extraction_activity']['last_source_read_offset'] = 1048576
    assert progress_agent.acquisition_fingerprint(job) == old
    job['pipeline_progress']['extraction_activity']['reader_attempt'] = 2
    job['pipeline_progress']['extraction_activity']['reader_attempt_started_at'] = '2026-10-18T08:41:43+00:00'
    # Restarting a reader must NOT reset the job-wide recovery budget.
    assert progress_agent.acquisition_fingerprint(job) == old
    diagnosis = progress_agent.acquisition_diagnosis(job, 90)
    assert 'attempt=2' in diagnosis and 'last E01 byte offset=1048576' in diagnosis


def test_serial_configuration_preserves_original_alternate_root_retry(monkeypatch):
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '1')
    monkeypatch.setenv('EXTRACT_TSK_ROOT_PREFERRED', 'path')
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths': ['/fake/seg.E01']})
    original_popen = subprocess.Popen
    methods = []
    def fake_popen(args, **kwargs):
        plan = json.loads(open(args[-2], encoding='utf8').read())
        methods.append((plan['root_open_strategy'], plan['inventory_workers_override']))
        if len(methods) == 1:
            return original_popen([sys.executable, '-c', 'raise SystemExit(3)'], **kwargs)
        script = ("import json,sys;open(sys.argv[1],'w').write(json.dumps({'path':'Recovered'})+'\\n');"
                  "print(json.dumps({'kind':'done','count':1}))")
        return original_popen([sys.executable, '-c', script, args[-1]], **kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess, 'Popen', fake_popen)
    result = tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='job'), retries=2)
    assert result == [{'path': 'Recovered'}]
    assert methods == [('inode', None), ('path', None)]


def test_progress_agent_does_not_warn_with_previous_attempt_age(monkeypatch):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    job = {'id': 'job1', 'pipeline_progress': {'extraction_activity': {
        'subphase': 'enumerating', 'reader_attempt': 2,
        'reader_attempt_started_at': (now - timedelta(seconds=25)).isoformat(),
        'files_found': 0, 'entries_scanned': 0}}}
    monkeypatch.setattr(progress_agent, 'execute', lambda *a, **k: None)
    monkeypatch.setattr(progress_agent, 'fetchone', lambda *a, **k: {
        'last_change_at': now - timedelta(seconds=360), 'acquisition_recoveries': 2,
        'acquisition_last_dispatch_at': None})
    class DB:
        def commit(self): pass
    out = progress_agent.inspect_acquisition_progress(DB(), job, schema_name='dummy', now=now)
    assert out['status'] == 'valid_wait'
    assert out['reader_attempt_age_sec'] == 25
    assert '360' not in out['reason']
