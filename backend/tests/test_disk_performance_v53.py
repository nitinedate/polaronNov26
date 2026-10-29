import ast
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys


def _functions(path, names, extra=None):
    src = Path(path).read_text()
    tree = ast.parse(src)
    body = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    ns = {'os': os}
    if extra:
        ns.update(extra)
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), ns)
    return ns


def _weight(shard):
    return sum(max(int(n.get('size_bytes') or 0), 64 * 1024) for n in shard)


def test_v53_byte_range_preserves_every_node_once_and_balances_large_files():
    ns = _functions('app/services/extracted_disk.py', {'_shard_nodes'})
    nodes = []
    for i in range(120):
        size = 64 * 1024 if i % 7 else 256 * 1024 * 1024
        nodes.append({'path': f'f{i:04d}', 'inode': i, 'size_bytes': size})
    shards = ns['_shard_nodes'](nodes, 8, strategy='byte_range_v53')
    flat = [n['path'] for sid in sorted(shards) for n in shards[sid]]
    assert flat == [n['path'] for n in nodes]
    weights = [_weight(shards[i]) for i in sorted(shards) if shards[i]]
    assert len(weights) == 8
    assert max(weights) - min(weights) <= 300 * 1024 * 1024


def test_v53_fast_media_plan_can_use_ten_readers():
    ns = _functions('app/services/extracted_disk.py', {'plan_ewf_extract_io'})
    nodes = [{'path': f'f{i}', 'inode': i} for i in range(5000)]
    readers, shards, reason = ns['plan_ewf_extract_io'](
        nodes, configured_workers=10, configured_shards=12, live_workers=10,
        thermal_pace=1.0, busy_extracts=1, cpu_count=24, stream_phase3=False,
    )
    assert readers == 10
    assert shards >= readers
    assert reason.startswith('ewf_parallel')


def _load_plan_readers():
    fake = ModuleType('app.services.disk_io_profile')
    fake.detect_source_io_profile = lambda paths: SimpleNamespace(media=os.environ.get('TEST_MEDIA','unknown'), detection='test')
    old = sys.modules.get('app.services.disk_io_profile')
    sys.modules['app.services.disk_io_profile'] = fake
    try:
        ns = _functions('app/services/extract_shard_v45.py', {'plan_readers'}, {
            'READ_SEMAPHORE_SIZE': 8,
            'HDD_READERS': 2,
            'VirtualDisk': object,
        })
        return ns['plan_readers']
    finally:
        pass


def test_v53_hdd_caps_to_two_readers(monkeypatch):
    monkeypatch.setenv('TEST_MEDIA', 'hdd')
    plan = _load_plan_readers()
    readers, gate, reason = plan(SimpleNamespace(segment_paths=['/evidence/case.E01']), 12)
    assert readers == 2
    assert gate == 2
    assert reason.startswith('hdd:')


def test_v53_ssd_uses_eight_reader_gate(monkeypatch):
    monkeypatch.setenv('TEST_MEDIA', 'ssd')
    plan = _load_plan_readers()
    readers, gate, reason = plan(SimpleNamespace(segment_paths=['/evidence/case.E01']), 8)
    assert readers == 8
    assert gate == 8
    assert reason.startswith('ssd:')
