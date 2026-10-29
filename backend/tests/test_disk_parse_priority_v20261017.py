"""Dependency-free regression harness for the October disk-performance patch.

The full project integration test still requires PostgreSQL, MinIO and a real E01.
This harness exercises the *real* edited function bodies against deterministic
in-memory service adapters; it does not claim to benchmark E01 throughput.
"""
import ast
import concurrent.futures
import json
import logging
import sys
import time
import types
import threading
import pytest
from pathlib import Path
from types import SimpleNamespace

MODULE_ROOT = Path(__file__).resolve().parents[1] / "app" / "services"


def extract(name, filename, namespace):
    tree = ast.parse((MODULE_ROOT / filename).read_text())
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert len(nodes) == 1
    exec(compile(ast.Module(body=nodes, type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]


def test_parallel_parse_persists_fast_files_while_slow_file_works():
    completed = []
    commits = []
    begin = time.monotonic()
    def parser(item, _timeout):
        art, path, data = item
        time.sleep(0.23 if path == 'slow' else 0.008)
        return dict(artifact=art, path=path, kind='parsed', records=[{'t': path}], parser_name='text')
    def outcome(_db, artifact, _path, _name, _records, defer_commit=False):
        completed.append((artifact['id'], time.monotonic()-begin))
        return True, 'parsed'
    namespace = {
        'concurrent': concurrent,
        'Any': __import__('typing').Any,
        'get_settings': lambda: SimpleNamespace(parse_parallel_enabled=True),
        '_parse_work_item': parser,
        '_apply_parse_outcome': outcome,
        '_defer_or_skip_forensic': lambda *a, **k: (False, 'skipped'),
        '_exec_locked': lambda *a, **k: None,
        'is_forensic_full_read_path': lambda _p: False,
        'is_critical_evtx_path': lambda _p: False,
        'rollback_aborted_transaction': lambda db: None,
        '_LARGE_FILE_BYTES': 32 * 1024 * 1024,
    }
    fn = extract('_process_parse_work_parallel', 'artifact_parse.py', namespace)
    class DB:
        def commit(self): commits.append(time.monotonic()-begin)
    items = [({'id': f'{i:03d}'}, 'slow' if i == 0 else f'fast{i}', b'data') for i in range(27)]
    stats = {'parsed':0,'skipped':0}
    fn(DB(), 'job', items, parse_workers=6, timeout_sec=0, commit_batch=3,
       stats=stats, heartbeat_fn=lambda: None, backoff_fn=lambda: None)
    assert stats == {'parsed':27,'skipped':0}
    assert len(completed) == 27 and len(set(x for x,t in completed)) == 27
    assert min(t for k,t in completed if k != '000') < 0.23  # not blocked by slowest file
    assert min(commits) < 0.23  # durable partial results before slow file completes


@pytest.mark.parametrize("part_count", [1, 8])
def test_priority_evidence_batches_commits_and_shard_reads(monkeypatch, part_count):
    count = 520
    sources = {}
    inventory = []
    payloads = {}
    for i in range(count):
        path = f'Files/unknown_{i:05d}.bin'
        uid = f'00000000-0000-0000-0000-{i+1:012d}'
        data = (b'BINARY SOURCE '+bytes(str(i), 'ascii')) * (400 if i == 0 else 1)
        payloads[path] = data
        sources[path] = {'id':uid, 'file_path':path, 'metadata':{'extracted_part_uri':f's3://part-{i % part_count}'},
                         'minio_uri':None}
        inventory.append(SimpleNamespace(path=path, extension='.bin', size=len(data),
                                         sha256=f'{i:064x}', meta={}))
    files = {}
    db_commits = []
    stream_opens = []
    unexpected_individual_reads = []
    updates = []
    active_parsers = 0
    peak_parsers = 0
    worker_guard = threading.Lock()

    class DB:
        def __init__(self): self.info = {}
        def commit(self): db_commits.append(1)
        def connection(self): return self
        def cursor(self): return self
        def __enter__(self): return self
        def __exit__(self, *args): return None
        @property
        def connection_obj(self): return self
    db = DB()
    # Production runs carry the tenant schema and must give the database writer
    # its own Session created inside the writer thread.
    writer_sessions = []
    if part_count == 8:
        db.info['firm_schema'] = 'tenant_test'

    def install_module(path, **attrs):
        obj = types.ModuleType(path)
        obj.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, path, obj)
        return obj

    def fake_values(cursor, sql, values, **kwargs):
        if 'INSERT INTO forensic_priority_records' in sql:
            for aid, jid, sid, kind, dom, state, ts, data, forensic in values:
                files[aid] = dict(source_id=sid, kind=kind, data=json.loads(data))
        elif 'UPDATE job_artifacts AS ja' in sql:
            for uid, reason in values:
                entry = next(r for r in sources.values() if r['id']==uid)
                entry['metadata'].update(priority_parsed_v4=True, priority_parse_exception=reason)
                updates.append(uid)
        else:
            raise AssertionError(sql)
    install_module('psycopg2', extras=install_module('psycopg2.extras', execute_values=fake_values))
    from contextlib import contextmanager
    @contextmanager
    def fake_tenant_session(schema):
        assert schema == 'tenant_test'
        assert threading.current_thread().name == 'disk-priority-db-writer'
        writer_db = DB()
        writer_db.connection = lambda: SimpleNamespace(connection=writer_db)
        writer_sessions.append(writer_db)
        yield writer_db
    install_module('app.db.session', firm_session=fake_tenant_session)

    class Artifact:
        @staticmethod
        def create(**kwargs):
            path = kwargs['source_path']
            return SimpleNamespace(artifact_id=f"{path}::{kwargs.get('source_row_id','0')}",
                                   artifact_type=kwargs['artifact_type'],
                                   source_domain=kwargs['source_domain'],
                                   forensic={'state':kwargs['state']},
                                   timestamp_utc=None,
                                   data=kwargs['data'])

    class Fallback:
        name = 'forensic_fallback'
        def parse(self, item, context):
            nonlocal active_parsers, peak_parsers
            with worker_guard:
                active_parsers += 1
                peak_parsers = max(active_parsers, peak_parsers)
            try:
                if part_count == 8:
                    time.sleep(0.008)
                data = context.read_artifact_bytes(item.path, max_bytes=4096)
            finally:
                with worker_guard:
                    active_parsers -= 1
            yield Artifact.create(artifact_type='unclassified_file', source_domain='files',
                                  source_path=item.path, state='unsupported',
                                  data={'head':data.decode(errors='replace') if data else None})

    class NeedsFull:
        name = 'needs_full_source'
        def parse(self, item, context):
            data = context.read_artifact_bytes(item.path, max_bytes=120_000_000)
            assert len(data) == item.size, 'bounded fallback header must never leak to a full parser'
            yield Artifact.create(artifact_type='full_source_checked', source_domain='files',
                                  source_path=item.path, source_row_id='full', state='allocated',
                                  data={'size':len(data)})

    class Registry:
        def route(self, item, ctx):
            return [Fallback(), NeedsFull()] if item.path.endswith('00000.bin') else [Fallback()]

    class Context:
        def __init__(self):
            self.extra={'read_errors':set()}
            self._read_bytes=self.reader
        def reader(self, path, max_bytes=120_000_000):
            unexpected_individual_reads.append(path)
            return payloads[path][:max_bytes]
        def read_artifact_bytes(self, path, *, max_bytes=120_000_000):
            return self._read_bytes(path, max_bytes)
        def clear_byte_cache(self): pass

    def streaming_reader(part, paths, **kwargs):
        stream_opens.append(part)
        for path in paths:
            assert kwargs['verify_size_by_path'][path] == len(payloads[path])
            assert kwargs['verify_sha256_by_path'][path]
            yield path, payloads[path][:kwargs['max_bytes_by_path'][path]]

    install_module('app.services.forensic_serial_mobile', _context=lambda *a, **k: Context(),
                   evidence_bundles=lambda items: [[it] for it in items])
    install_module('app.services.forensic_serial_pipeline', StageWaiting=RuntimeError)
    install_module('app.services.job_control', pipeline_should_stop=lambda *a: False)
    install_module('app.services.mobile_forensic.discovery', inventory_from_job_artifacts=lambda *a: inventory)
    install_module('app.services.mobile_forensic.parsers.browser', BrowserHistoryParser=type('B',(),{'name':'browser'}))
    install_module('app.services.mobile_forensic.parsers.messaging', WhatsAppParser=type('W',(),{'name':'whatsapp'}))
    install_module('app.services.mobile_forensic.plugins', get_plugin_registry=lambda: Registry())
    install_module('app.services.mobile_forensic.recovery.analyzers', SqliteHistoryAnalyzer=object)
    install_module('app.services.tar_cache', iter_files_from_part=streaming_reader)
    install_module('app.services.progress_agent', note_operation=lambda *a, **k: None)

    namespace = {'json':json, 'NormalizedArtifact':Artifact, 're':__import__('re'),
                 'is_crypt_file':lambda path: False, 'add_record_links':lambda art: art,
                 '_dumps':json.dumps, 'ensure_priority_schema':lambda *a: None,
                 'fetchone': lambda db, sql, params:{'disk_source':{}},
                 'execute': lambda db, sql, params: None,
                 'fetchall': lambda db, sql, params:list(sources.values())}
    fn = extract('run_disk_priority_evidence','forensic_priority_evidence.py',namespace)
    # Both the new and original use db.connection().connection.cursor().
    db.connection = lambda: SimpleNamespace(connection=db)
    result = fn(db, 'jobid')
    assert result['sources_processed'] == count
    assert result['records_written'] == count+1
    assert result['errors'] == 0
    assert result['streamed_part_groups'] == part_count
    assert result['individual_source_reads'] == 0
    assert len(stream_opens) == part_count
    assert result['priority_async_writer'] is True
    assert peak_parsers <= 8
    if part_count == 8:
        assert peak_parsers >= 4, 'CPU parsing is still serialized under the PostgreSQL mutex'
    assert unexpected_individual_reads == []  # Full source reused from verified shard, no redundant decompress
    assert len(files) == count+1
    assert len(updates) == count
    assert len(db_commits) <= 14  # ~3 batches + DDL/liveness; not 520 commits
    if part_count == 8:
        assert len(writer_sessions) == 1
        assert writer_sessions[0] is not db
    assert all(rec['source_id'] in {source['id'] for source in sources.values()} for rec in files.values())
    # Retry is idempotent: completed sources are skipped.
    assert fn(db, 'jobid')['sources_processed'] == 0
    assert len(stream_opens) == part_count
    if part_count == 8:
        assert len(writer_sessions) == 2  # retry still uses isolated writer session


def test_streaming_headers_validate_full_sha256_and_size_before_use():
    import hashlib
    import io
    import tarfile
    from contextlib import nullcontext
    from typing import Iterator
    data = b'MZ' + b'full forensic evidence '*120
    bad = b'corrupted' + b'-'*250
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for path, blob in [('ok.bin', data), ('bad.bin', bad)]:
            hdr = tarfile.TarInfo(path)
            hdr.size = len(blob)
            tar.addfile(hdr, io.BytesIO(blob))
    payload = archive.getvalue()
    opens = []
    namespace = dict(
        Iterator=Iterator, time=time, log=logging.getLogger('test_tar'),
        _cached_file=lambda part, path: None,
        _cache_file=lambda part, path, content: None,
        open_object_stream=lambda part: (opens.append(part) or io.BytesIO(payload)),
        zstd=SimpleNamespace(ZstdDecompressor=lambda: SimpleNamespace(stream_reader=lambda obj: nullcontext(obj))),
        tarfile=tarfile,
    )
    fn=extract('iter_files_from_part','tar_cache.py',namespace)
    result = dict(fn('part.tar.zst', {'ok.bin','bad.bin','missing.bin'},
                     max_bytes_by_path={'ok.bin':4,'bad.bin':4,'missing.bin':4},
                     verify_sha256_by_path={'ok.bin':hashlib.sha256(data).hexdigest(),
                                            'bad.bin':hashlib.sha256(b'THE ORIGINAL').hexdigest()},
                     verify_size_by_path={'ok.bin':len(data),'bad.bin':len(bad),
                                          'missing.bin':8}))
    assert result == {'ok.bin':b'MZfu','bad.bin':None,'missing.bin':None}
    assert opens == ['part.tar.zst']


def test_shard_scan_reports_bytes_while_skipping_other_members():
    import io
    import tarfile
    from contextlib import nullcontext
    from typing import Iterator
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for path, blob in [('skip.bin', b'x' * 3000), ('keep.bin', b'KEEP')]:
            hdr = tarfile.TarInfo(path)
            hdr.size = len(blob)
            tar.addfile(hdr, io.BytesIO(blob))
    payload = archive.getvalue()
    details = []
    namespace = dict(
        Iterator=Iterator, time=time, log=logging.getLogger('test_tar_progress'),
        _cached_file=lambda part, path: None,
        _cache_file=lambda part, path, content: None,
        open_object_stream=lambda part: io.BytesIO(payload),
        zstd=SimpleNamespace(ZstdDecompressor=lambda: SimpleNamespace(stream_reader=lambda obj, **_kw: nullcontext(obj))),
        tarfile=tarfile,
    )
    fn = extract('iter_files_from_part', 'tar_cache.py', namespace)
    found = dict(fn('part.tar.zst', {'keep.bin'}, max_bytes_by_path={'keep.bin': 4096}, on_detail=details.append))
    assert found == {'keep.bin': b'KEEP'}
    assert details
    assert details[-1]['files_yielded'] == 1
    assert details[-1]['files_wanted'] == 1
    assert details[-1]['bytes_seen'] >= 3000


def test_shard_scan_label_shows_fraction_rate_and_gpu():
    namespace = {}
    extract('_fmt_bytes', 'artifact_parse.py', namespace)
    extract('format_shard_scan_label', 'artifact_parse.py', namespace)
    label = namespace['format_shard_scan_label'](
        {'files_wanted': 36, 'files_yielded': 12, 'bytes_seen': 1500 * 1024 * 1024,
         'members_scanned': 4000, 'current_path': 'Users/a/AppData/History'},
        bytes_total=4 * 1024 * 1024 * 1024, rate_mib_s=80, gpu_done=10, gpu_pending=2,
    )
    assert label.startswith('Shard scan 12/36 files')
    assert '37% of shard' in label or '36% of shard' in label
    assert '80 MB/s' in label
    assert 'GPU OCR 10 done, 2 queued' in label
    assert 'History' in label
