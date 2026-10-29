"""Synthetic scheduling benchmark only: NOT an E01 or production disk throughput test.

Run from backend/: PYTHONPATH=. python tests/benchmark_tsk_parallel_inventory_20261018.py
"""
from __future__ import annotations
import time
from types import SimpleNamespace
from unittest.mock import patch
from app.services import virtual_disk as disk
from app.services.tsk_parallel_inventory import enumerate_tsk_parallel

class Meta:
    def __init__(self, kind, number, size=0):
        self.type, self.addr, self.size = kind, number, size
class Entry:
    def __init__(self, name, kind, number, size=0):
        self.info = SimpleNamespace(name=SimpleNamespace(name=name.encode()), meta=Meta(kind, number, size))
class MockFS:
    info = SimpleNamespace(root_inum=5)
    def __init__(self, tree, delay): self.tree, self.delay = tree, delay
    def open_dir(self, **kwargs):
        if kwargs.get('inode') != 5: time.sleep(self.delay)
        return self.tree[kwargs['inode']]
class Handle:
    def __init__(self, tree, delay): self._fs_info = MockFS(tree, delay)
    def close(self): pass


def main():
    tree = {5: [Entry(f'd{i}', 2, 100+i) for i in range(240)]}
    for i in range(240):
        tree[100+i] = [Entry(f'data{i}.bin', 1, 1000+i, i+1)]
    tsk = SimpleNamespace(TSK_FS_META_TYPE_ENUM=SimpleNamespace(
        TSK_FS_META_TYPE_REG=1, TSK_FS_META_TYPE_DIR=2))
    delay = 0.003
    results = {}
    with patch.object(disk, '_pytsk3', tsk):
        for readers in (2, 4):
            vd = SimpleNamespace(job_id='synthetic', mode='ewf',
                   segment_paths=['/mock.E01'], segment_hashes=[], base_name='mock',
                   format='E01', root_folder=None, _fs_info=MockFS(tree, delay))
            with patch.object(disk, 'open_virtual_disk_from_paths',
                   lambda *a, **k: Handle(tree, delay)):
                start = time.monotonic()
                nodes = enumerate_tsk_parallel(vd, workers=readers)
                elapsed = time.monotonic() - start
            assert len(nodes) == 240
            assert len({x['path'] for x in nodes}) == 240
            results[readers] = elapsed
    print('Synthetic 240-directory read scheduling (3 ms simulated I/O per directory)')
    print(f'2 readers: {results[2]:.3f}s; 4 readers: {results[4]:.3f}s')
    print(f'Concurrency speed ratio 4 vs 2: {results[2] / results[4]:.2f}x')
    print('NOT a measured production or E01 speedup.')

if __name__ == '__main__': main()
