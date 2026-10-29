"""Regression fixtures for native E01 walker isolation and progressAgent supervision."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services import progress_agent, tsk_walk_isolated, virtual_disk


def test_tsk_walker_is_iterative_deduplicates_directory_inodes_and_reports_progress(monkeypatch):
    class Meta:
        def __init__(self, typ, inode, size=0):
            self.type, self.addr, self.size = typ, inode, size
    class Entry:
        def __init__(self, name, meta, children=None):
            self.info = SimpleNamespace(name=SimpleNamespace(name=name.encode()), meta=meta)
            self.children = children or []
        def as_directory(self):
            return self.children
    # Root and one child reference the same directory inode: only one expansion.
    child = [Entry('other.txt', Meta(1, 100, 10))]
    root = [Entry('base.bin', Meta(1, 101, 42)), Entry('dirA', Meta(2, 4), child),
            Entry('dirAlias', Meta(2, 4), child)]
    class TSKTypes:
        TSK_FS_META_TYPE_REG = 1
        TSK_FS_META_TYPE_DIR = 2
    monkeypatch.setattr(virtual_disk, '_pytsk3', SimpleNamespace(TSK_FS_META_TYPE_ENUM=TSKTypes))
    vd = SimpleNamespace(mode='ewf', _fs_info=SimpleNamespace(open_dir=lambda path: root))
    events = []
    nodes = virtual_disk.enumerate_all_files(vd, on_progress=lambda m,d: events.append((m,d)),
                                             progress_interval_sec=5)
    assert len(nodes) == 2
    assert len({n['path'] for n in nodes}) == 2
    assert {n['size_bytes'] for n in nodes} == {42, 10}
    assert events[-1][1]['action'] == 'tsk_walk_complete'
    assert events[-1][1]['directories_scanned'] == 2


def test_tsk_walker_reports_unreadable_directories_instead_of_silently_swallowing(monkeypatch):
    class Meta:
        addr, size, type = 5, 0, 2
    class Entry:
        info = SimpleNamespace(name=SimpleNamespace(name=b'broken'), meta=Meta())
        def as_directory(self):
            raise OSError('FS metadata corrupt')
    monkeypatch.setattr(virtual_disk, '_pytsk3', SimpleNamespace(
        TSK_FS_META_TYPE_ENUM=SimpleNamespace(TSK_FS_META_TYPE_REG=1, TSK_FS_META_TYPE_DIR=2)))
    vd = SimpleNamespace(mode='ewf', _fs_info=SimpleNamespace(open_dir=lambda path: [Entry()]))
    events = []
    assert virtual_disk.enumerate_all_files(vd, on_progress=lambda msg, meta: events.append(meta)) == []
    assert events[-1]['unreadable_directories'] == 1


def test_isolated_tsk_worker_returns_only_complete_counted_inventory(monkeypatch):
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths': ['/fake/E01'], 'format': 'e01'})
    original_popen = subprocess.Popen
    def fake_popen(args, **kwargs):
        result_path = args[-1]
        script = ("import json,sys;open(sys.argv[1],'w').write(''.join(json.dumps(x)+'\\n' "
                  "for x in [{'path':'A','size_bytes':2},{'path':'B','size_bytes':3}])); "
                  "print(json.dumps({'kind':'progress','message':'1 dir','metadata':{'files_found':0,'directories_scanned':1,'entries_scanned':1}})); "
                  "print(json.dumps({'kind':'done','count':2}))")
        return original_popen([sys.executable, '-c', script, result_path], **kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess, 'Popen', fake_popen)
    events=[]
    nodes=tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='case-1'),
                    on_progress=lambda m,d:events.append(d), retries=1, idle_timeout_sec=60)
    assert len(nodes) == 2 and nodes[1]['path'] == 'B'
    assert events[-1]['directories_scanned'] == 1


def test_progress_agent_fingerprint_ignores_heartbeat_timestamp():
    row = {'id':'job', 'updated_at':datetime.now(timezone.utc),
           'pipeline_progress':{'extraction_activity':{'subphase':'enumerating','files_found':20,'directories_scanned':7}}}
    first = progress_agent.acquisition_fingerprint(row)
    row['updated_at'] = row['updated_at'] + timedelta(hours=1)
    assert progress_agent.acquisition_fingerprint(row) == first
    row['pipeline_progress']['extraction_activity']['directories_scanned'] += 1
    assert progress_agent.acquisition_fingerprint(row) != first


def test_progress_agent_reports_live_slow_reader_without_duplicate(monkeypatch):
    now = datetime.now(timezone.utc)
    job = {'id':'job-1','status':'processing',
           'pipeline_progress':{'extraction_activity':{'subphase':'enumerating',
              'files_found':100,'directories_scanned':45,'entries_scanned':500,'last_path':'Users/Bob'}}}
    monkeypatch.setattr(progress_agent, 'execute', lambda *a,**k:None)
    monkeypatch.setattr(progress_agent, 'fetchone', lambda *a,**k:
        {'last_change_at':now-timedelta(minutes=3),'acquisition_recoveries':0})
    monkeypatch.setattr('app.services.job_locks.extract_celery_work_active', lambda *_:True)
    events=[]
    monkeypatch.setattr(progress_agent, '_event', lambda db,jid,st,decision,reason:events.append((decision,reason)))
    class DB:
        def commit(self): pass
    result=progress_agent.inspect_acquisition_progress(DB(),job,schema_name='test',now=now)
    assert result['status']=='investigate'
    assert len(events)==1 and 'dirs=45' in events[0][1]
    assert 'no duplicate task queued' in result['reason']


def test_progress_agent_dispatches_only_when_owner_absent_and_no_recent_recovery(monkeypatch):
    now=datetime.now(timezone.utc)
    job={'id':'job-1','status':'processing','pipeline_progress':{'extraction_activity':{'subphase':'copying'}}}
    sql_updates=[]
    monkeypatch.setattr(progress_agent,'execute',lambda db,sql,params=None: sql_updates.append(sql))
    monkeypatch.setattr(progress_agent,'fetchone',lambda *a,**k:
        {'last_change_at':now-timedelta(minutes=4), 'acquisition_recoveries':0,
         'acquisition_last_dispatch_at':None})
    monkeypatch.setattr('app.services.job_locks.extract_celery_work_active',lambda *_:False)
    monkeypatch.setattr('app.services.job_locks.extract_task_in_flight',lambda *a,**k:False)
    monkeypatch.setattr(progress_agent,'_event',lambda *a,**k:None)
    monkeypatch.setattr('app.services.pipeline_supervisor.dispatch_stage_agent',
                       lambda db,jid,**kwargs:{'status':'dispatched','action':kwargs['recommendation']})
    class DB:
        def commit(self):pass
    result=progress_agent.inspect_acquisition_progress(DB(),job,schema_name='test',now=now)
    assert result['status']=='dispatched'
    assert result['action']['action']=='resume_extraction'
    assert any('acquisition_last_dispatch_at=NOW()' in sql for sql in sql_updates)


def test_isolated_tsk_retries_reader_crash_without_accepting_partial_result(monkeypatch):
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths': ['/fake/E01'], 'format':'e01'})
    original_popen = subprocess.Popen
    calls=[]
    def fake_popen(args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            script="import sys;print('first native reader crashed', file=sys.stderr);sys.exit(7)"
            return original_popen([sys.executable, '-c', script], **kwargs)
        script=("import json,sys;open(sys.argv[1],'w').write(json.dumps({'path':'Recovered'})+'\\n');"
                "print(json.dumps({'kind':'done','count':1}))")
        return original_popen([sys.executable,'-c',script,args[-1]],**kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess,'Popen',fake_popen)
    nodes=tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='case-1'), retries=2)
    assert len(calls)==2 and nodes==[{'path':'Recovered'}]


def test_isolated_tsk_rejects_manifest_count_mismatch(monkeypatch):
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths':['/fake/E01'],'format':'e01'})
    original_popen=subprocess.Popen
    def fake_popen(args, **kwargs):
        script=("import json,sys;open(sys.argv[1],'w').write(json.dumps({'path':'A'})+'\\n');"
                "print(json.dumps({'kind':'done','count':2}))")
        return original_popen([sys.executable,'-c',script,args[-1]],**kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess,'Popen',fake_popen)
    import pytest
    with pytest.raises(RuntimeError,match='count mismatch'):
        tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='case-2'),retries=1)


def test_tsk_root_inode_preferred_over_expensive_path_lookup(monkeypatch):
    class Meta:
        def __init__(self):
            self.type, self.addr, self.size = 1, 11, 4
    class Entry:
        info = SimpleNamespace(name=SimpleNamespace(name=b'item.txt'), meta=Meta())
    opened=[]
    class FS:
        info = SimpleNamespace(root_inum=5)
        def open_dir(self, **kwargs):
            opened.append(kwargs)
            return [Entry()]
    monkeypatch.setattr(virtual_disk, '_pytsk3', SimpleNamespace(TSK_FS_META_TYPE_ENUM=SimpleNamespace(
        TSK_FS_META_TYPE_REG=1, TSK_FS_META_TYPE_DIR=2)))
    events=[]
    nodes=virtual_disk.enumerate_all_files(SimpleNamespace(mode='ewf',_fs_info=FS()),
                                            on_progress=lambda m,d:events.append((m,d)))
    assert opened == [{'inode':5}]
    assert nodes[0]['path'] == 'item.txt'
    assert next(d for _,d in events if d.get('action')=='tsk_root_opened')['reader_phase']=='root_first_entry'


def test_tsk_path_root_fallback_on_second_attempt(monkeypatch):
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd:{'segment_paths':['/fake/E01'], 'format':'e01'})
    original_popen = subprocess.Popen
    methods=[]
    def fake_popen(args, **kwargs):
        with open(args[-2],encoding='utf-8') as stream:
            methods.append(json.load(stream)['root_open_strategy'])
        if len(methods)==1:
            return original_popen([sys.executable,'-c','import sys;sys.exit(7)'], **kwargs)
        script=("import json,sys;open(sys.argv[1],'w').write(json.dumps({'path':'ok'})+'\\n');"
                "print(json.dumps({'kind':'done','count':1}))")
        return original_popen([sys.executable,'-c',script,args[-1]],**kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess,'Popen',fake_popen)
    nodes=tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='x'),retries=2)
    assert methods==['inode','inode']  # parallel -> serial on same root method
    assert nodes==[{'path':'ok'}]


def test_ntfs_root_uses_inode_five_when_tsk_omits_it():
    assert virtual_disk.filesystem_root_inode(SimpleNamespace(info=SimpleNamespace(root_inum=5))) == 5
    ntfs = SimpleNamespace(info=SimpleNamespace(root_inum=0, ftype=SimpleNamespace(name='TSK_FS_TYPE_NTFS', value=1)))
    assert virtual_disk.filesystem_root_inode(ntfs) == 5
    assert virtual_disk.filesystem_root_inode(SimpleNamespace(info=SimpleNamespace(root_inum=0, ftype=SimpleNamespace(name='EXT', value=8)))) is None


def test_ewf_metadata_reads_reuse_one_decompressed_window():
    from collections import OrderedDict
    seeks = []
    class Handle:
        def seek(self, offset):
            seeks.append(offset)
        def read(self, size):
            return bytes([offset % 251 for offset in range(seeks[-1], seeks[-1] + size)])
    cache = OrderedDict()
    first = virtual_disk.cached_image_read(Handle(), cache, 100, 16)
    second = virtual_disk.cached_image_read(Handle(), cache, 200, 16)
    assert first == bytes([offset % 251 for offset in range(100, 116)])
    assert second == bytes([offset % 251 for offset in range(200, 216)])
    assert seeks == [0]


def test_agent_diagnoses_zero_progress_root_call():
    job={'pipeline_progress':{'extraction_activity':{'subphase':'enumerating',
         'files_found':0,'directories_scanned':0,'entries_scanned':0,
         'reader_phase':'root_first_entry','root_open_strategy':'inode'}}}
    msg=progress_agent.acquisition_diagnosis(job,270)
    assert 'root_first_entry' in msg
    assert 'root method=inode' in msg
    assert 'no useful entry progress' in msg


def test_tsk_root_idle_watchdog_terminates_owned_child_without_accepting_plan(monkeypatch):
    monkeypatch.setattr(virtual_disk, 'vd_plan', lambda vd: {'segment_paths': ['/fake/E01'], 'format': 'e01'})
    original_popen=subprocess.Popen
    child=[]
    def fake_popen(args, **kwargs):
        script=("import json,time;"
                "print(json.dumps({'kind':'progress','message':'opening root',"
                "'metadata':{'reader_phase':'root_open','action':'tsk_root_open'}}),flush=True);"
                "time.sleep(60)")
        proc=original_popen([sys.executable,'-c',script], **kwargs)
        child.append(proc)
        return proc
    monkeypatch.setattr(tsk_walk_isolated.subprocess, 'Popen', fake_popen)
    elapsed=[0.0]
    def fake_monotonic():
        elapsed[0]+=80.0
        return elapsed[0]
    monkeypatch.setattr(tsk_walk_isolated.time, 'monotonic', fake_monotonic)
    import pytest
    with pytest.raises(tsk_walk_isolated.TSKWalkTimeout, match='phase='):
        tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='case'), retries=1,
                                                 root_idle_timeout_sec=60)
    assert len(child)==1
    assert child[0].poll() is not None
