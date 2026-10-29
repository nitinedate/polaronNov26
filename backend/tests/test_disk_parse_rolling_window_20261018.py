"""Focused disk parser regression: slow file does not block submission of next chunk."""
from __future__ import annotations

import ast
import concurrent.futures as futures
import time
from pathlib import Path
from types import SimpleNamespace


def _load_runner():
    source = Path(__file__).resolve().parents[1] / 'app' / 'services' / 'artifact_parse.py'
    parsed = ast.parse(source.read_text())
    node, = [n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == '_process_parse_work_parallel']
    recorded = []
    namespace = {
        'concurrent': SimpleNamespace(futures=futures),
        'Any': object,
        'get_settings': lambda: SimpleNamespace(parse_parallel_enabled=True),
        '_LARGE_FILE_BYTES': 32 * 1024 * 1024,
        '_defer_or_skip_forensic': lambda *a, **k: (False, 'skip'),
        '_exec_locked': lambda *a, **k: None,
        'is_forensic_full_read_path': lambda p: False,
        'is_critical_evtx_path': lambda p: False,
        'rollback_aborted_transaction': lambda db: None,
        'log': SimpleNamespace(warning=lambda *args: None),
    }
    started = time.monotonic()
    def parser(item, _timeout):
        art, path, _data = item
        time.sleep(0.55 if path == 'very-slow' else 0.004)
        return {'artifact': art, 'path': path, 'kind': 'parsed', 'parser_name': 'text', 'records': [{'e':1}]}
    def persist(db, artifact, path, parser, records, defer_commit=False):
        recorded.append((artifact['id'], time.monotonic() - started))
        return True, 'parsed'
    namespace['_parse_work_item'] = parser
    namespace['_apply_parse_outcome'] = persist
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['_process_parse_work_parallel'], recorded


def test_rolling_window_submits_beyond_blocked_old_chunk():
    parse, completed = _load_runner()
    work = [({'id': i}, 'very-slow' if i == 0 else 'fast', b'x') for i in range(120)]
    class DB:
        def __init__(self): self.commits = 0
        def commit(self): self.commits += 1
    db = DB()
    stats = {'parsed':0, 'skipped':0}
    parse(db, 'case', work, parse_workers=3, timeout_sec=0, commit_batch=12,
          stats=stats, heartbeat_fn=lambda: None, backoff_fn=lambda: None)
    assert stats == {'parsed':120,'skipped':0}
    assert len(completed) == 120
    assert len({i for i, _ in completed}) == 120
    assert any(i >= 48 and when < 0.50 for i, when in completed), 'slow file blocked the next submission window'
    assert db.commits >= 10
