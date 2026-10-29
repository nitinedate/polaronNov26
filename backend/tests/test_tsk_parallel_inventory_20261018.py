"""Synthetic regression tests; no live E01 evidence is bundled with the source."""
import threading
from types import SimpleNamespace

from app.services import tsk_parallel_inventory as inv, virtual_disk as disk


class Meta:
    def __init__(self, kind, inode, size=0):
        self.type, self.addr, self.size = kind, inode, size


class Entry:
    def __init__(self, name, kind=1, inode=0, size=1, missing=False):
        meta = None if missing else Meta(kind, inode, size)
        self.info = SimpleNamespace(name=SimpleNamespace(name=name.encode()), meta=meta)


class FakeFS:
    info = SimpleNamespace(root_inum=5)
    def __init__(self, tree, opened, barrier=None, fail_inode=None):
        self.tree, self.opened, self.barrier, self.fail_inode = tree, opened, barrier, fail_inode

    def open_dir(self, **kwargs):
        self.opened.append(kwargs)
        inode = kwargs.get('inode')
        if inode == self.fail_inode:
            raise OSError('damaged inode index')
        if self.barrier and inode in (10, 11):
            self.barrier.wait(timeout=3.0)
        key = inode if inode is not None else kwargs.get('path')
        return list(self.tree[key])


def setup(monkeypatch, *, barrier=None, missing=False, fail_inode=None):
    tree = {
        5: [Entry('A', 2, 10), Entry('B', 2, 11), Entry('B_alias', 2, 11),
            Entry('root.bin', 1, 81, 9), *([Entry('unknown', missing=True)] if missing else [])],
        10: [Entry('a.txt', 1, 91, 3), Entry('nested', 2, 12)],
        11: [Entry('b.txt', 1, 92, 4)],
        12: [Entry('deep.bin', 1, 93, 8)],
        '/A': [Entry('a.txt', 1, 91, 3), Entry('nested', 2, 12)],
    }
    opened, created = [], []
    monkeypatch.setattr(disk, '_pytsk3', SimpleNamespace(
        TSK_FS_META_TYPE_ENUM=SimpleNamespace(TSK_FS_META_TYPE_REG=1, TSK_FS_META_TYPE_DIR=2)))
    def fresh_reader(*args, **kwargs):
        r = SimpleNamespace(_fs_info=FakeFS(tree, opened, barrier, fail_inode),
                            closed=False)
        def close(): r.closed = True
        r.close = close
        created.append(r)
        return r
    monkeypatch.setattr(disk, 'open_virtual_disk_from_paths', fresh_reader)
    original = SimpleNamespace(job_id='case1', mode='ewf', segment_paths=['/evidence/image.E01'],
        segment_hashes=[], base_name='image', format='E01', root_folder=None,
        _fs_info=FakeFS(tree, opened))
    return original, opened, created


def test_parallel_reads_distinct_inodes_concurrently_and_preserves_files(monkeypatch):
    vd, opened, created = setup(monkeypatch, barrier=threading.Barrier(2))
    events = []
    files = inv.enumerate_tsk_parallel(vd, workers=2,
               on_progress=lambda message, metadata: events.append(metadata))
    assert {r['path'] for r in files} == {'root.bin', 'A/a.txt', 'B/b.txt', 'A/nested/deep.bin'}
    assert len(files) == len({r['path'] for r in files})
    assert any(entry.get('inode') == 10 for entry in opened)
    assert any(entry.get('inode') == 11 for entry in opened)
    assert len(created) == 2
    assert all(reader.closed for reader in created)
    assert events[-1]['directories_scanned'] == 4
    assert events[-1]['alias_directories_skipped'] == 1
    assert events[-1]['inventory_workers'] == 2
    assert events[-1]['entries_scanned'] == 8


def test_missing_metadata_is_counted_not_falsely_a_file(monkeypatch):
    vd, _, _ = setup(monkeypatch, missing=True)
    events = []
    files = inv.enumerate_tsk_parallel(vd, workers=2,
               on_progress=lambda message, metadata: events.append(metadata))
    assert len(files) == 4
    assert events[-1]['metadata_missing'] == 1


def test_inaccessible_inode_falls_back_to_path(monkeypatch):
    vd, opened, _ = setup(monkeypatch, fail_inode=10)
    events = []
    files = inv.enumerate_tsk_parallel(vd, workers=2,
               on_progress=lambda message, metadata: events.append(metadata))
    assert len(files) == 4
    assert {'path': '/A'} in opened
    assert events[-1]['unreadable_directories'] == 0


def test_reader_setup_crash_does_not_complete_partial_inventory(monkeypatch):
    import pytest
    vd, _, _ = setup(monkeypatch)
    monkeypatch.setattr(disk, 'open_virtual_disk_from_paths', lambda *a, **k: (_ for _ in ()).throw(OSError('image unavailable')))
    with pytest.raises(OSError, match='image unavailable'):
        inv.enumerate_tsk_parallel(vd, workers=2)


def test_media_caps_and_serial_fallback(monkeypatch):
    vd, _, _ = setup(monkeypatch)
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '4')
    import sys
    fake_profile = SimpleNamespace(detect_source_io_profile=lambda x:SimpleNamespace(media='hdd'))
    monkeypatch.setitem(sys.modules, 'app.services.disk_io_profile', fake_profile)
    assert inv.inventory_readers(vd)[0] == 2
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '1')
    assert inv.inventory_readers(vd)[0] == 1


def test_existing_serial_walker_remains_available(monkeypatch):
    # No registered segment plan: older direct-call tools continue to use the
    # original iterative walk (not a worker pool).
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '1')
    monkeypatch.setattr(disk, '_pytsk3', SimpleNamespace(TSK_FS_META_TYPE_ENUM=SimpleNamespace(
        TSK_FS_META_TYPE_REG=1, TSK_FS_META_TYPE_DIR=2)))
    vd = SimpleNamespace(mode='ewf', job_id='old', segment_paths=['image.E01'],
            _fs_info=SimpleNamespace(info=SimpleNamespace(root_inum=5),
                                     open_dir=lambda **kw: [Entry('data', 1, 42, 7)]))
    output = disk.enumerate_all_files(vd)
    assert output == [{'path':'data', 'name':'data','size_bytes':7,'inode':42}]


def test_parallelism_enabled_at_normal_entrypoint(monkeypatch):
    vd, _, _ = setup(monkeypatch)
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '2')
    from app.services import disk_io_profile
    monkeypatch.setattr(disk_io_profile, 'detect_source_io_profile',
                        lambda x: SimpleNamespace(media='hdd'))
    events = []
    found = disk.enumerate_all_files(vd, on_progress=lambda m,d:events.append(d))
    assert len(found) == 4
    assert events[-1]['inventory_parallel'] is True


def test_root_path_preference_and_retry(monkeypatch):
    import json, subprocess, sys
    from app.services import tsk_walk_isolated
    monkeypatch.setenv('EXTRACT_TSK_ROOT_PREFERRED', 'path')
    monkeypatch.setenv('EXTRACT_TSK_ENUM_WORKERS', '2')
    monkeypatch.setattr(disk, 'vd_plan', lambda vd: {'segment_paths':['image.E01'], 'mode':'ewf'})
    original = subprocess.Popen
    methods=[]
    def fake_popen(args, **kwargs):
        with open(args[-2],encoding='utf-8') as inp:
            methods.append(json.load(inp)['root_open_strategy'])
        if len(methods) == 1:
            return original([sys.executable, '-c', 'raise RuntimeError("mock broken path")'], **kwargs)
        script=('import json,sys;open(sys.argv[1],"w").write(json.dumps({"path":"recovered"})+"\\n");'
                'print(json.dumps({"kind":"done","count":1}))')
        return original([sys.executable, '-c', script, args[-1]], **kwargs)
    monkeypatch.setattr(tsk_walk_isolated.subprocess, 'Popen', fake_popen)
    out = tsk_walk_isolated.enumerate_tsk_isolated(SimpleNamespace(job_id='test'), retries=2)
    assert methods == ['inode','inode']  # inode first; path is only the last fallback
    assert out == [{'path':'recovered'}]
