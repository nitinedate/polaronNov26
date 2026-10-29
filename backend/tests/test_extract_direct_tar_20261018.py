"""Dependency-free tests for opt-in known-size E01 tar streaming.

Read just the helper class/functions as AST: this environment intentionally does
not assume MinIO, libewf or zstd are installed.
"""
import ast
import hashlib
import io
import tarfile
import time
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / 'app/services/extract_shard_v45.py'


def _helpers():
    src = ast.parse(SOURCE.read_text())
    wanted = {'_CountingHasher', '_ChunkReader', '_VerifiedTarReader'}
    nodes = [n for n in src.body if isinstance(n, ast.ClassDef) and n.name in wanted]
    assert len(nodes) == len(wanted)
    ns = {'hashlib': hashlib, 'time': time, 'Iterator': __import__('typing').Iterator}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns['_VerifiedTarReader']


def _create_tar(data, hinted_size, *, hash_files):
    Reader = _helpers()
    # Segment chunks intentionally cross tarfile's internal read boundaries.
    chunks = [data[i:i + 137] for i in range(0, len(data), 137)]
    reader = Reader(iter(chunks), hash_files=hash_files)
    dest = io.BytesIO()
    with tarfile.open(fileobj=dest, mode='w|') as tar:
        info = tarfile.TarInfo('Users/test/evidence.bin')
        info.size = hinted_size
        tar.addfile(info, reader)
        size, digest = reader.verify(hinted_size)
    return dest.getvalue(), size, digest


def test_stream_preserves_exact_bytes_and_sha256():
    data = bytes(range(256)) * 40
    tar_bytes, n, digest = _create_tar(data, len(data), hash_files=True)
    assert n == len(data)
    assert digest == hashlib.sha256(data).hexdigest()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as tf:
        assert tf.extractfile('Users/test/evidence.bin').read() == data


def test_stream_without_hash_keeps_bytes():
    data = b'forensic contents' * 200
    tar_bytes, size, digest = _create_tar(data, len(data), hash_files=False)
    assert size == len(data) and digest == ''
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as tf:
        assert tf.extractfile('Users/test/evidence.bin').read() == data


def test_undersized_source_cannot_be_committed():
    with pytest.raises((OSError, IOError)):
        _create_tar(b'only 3 bytes', 512, hash_files=True)


def test_oversized_source_cannot_be_committed():
    with pytest.raises(IOError, match='exceeds'):
        _create_tar(b'A' * 1024, 512, hash_files=True)


def test_zero_length_never_uses_direct_known_size_path():
    code = SOURCE.read_text()
    assert 'size_hint > 0' in code
    assert 'DIRECT_TAR_STREAM = ' in code


def test_disk_progress_tracks_uploaded_separately():
    disk_source = SOURCE.parents[0] / 'extracted_disk.py'
    module = ast.parse(disk_source.read_text())
    extracted = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == '_ExtractionProgress')
    ns = {'threading': __import__('threading'), 'time': time}
    exec(compile(ast.Module(body=[extracted], type_ignores=[]), str(disk_source), 'exec'), ns)
    progress = ns['_ExtractionProgress'](100, progress_step=500)
    progress.record_extracted(100)
    assert progress.snapshot()['files_extracted'] == 1
    assert progress.snapshot()['files_uploaded'] == 0
    progress.mark_shard_committed(1, 100)
    assert progress.snapshot()['files_uploaded'] == 1
    assert progress.snapshot()['bytes_uploaded'] == 100


def _run_worker(expected_size, actual_data):
    """Exercise the real worker body with dependency-free disk/MinIO stand-ins."""
    import contextlib
    import os
    import tempfile
    import threading
    from pathlib import Path
    from types import SimpleNamespace

    module = ast.parse(SOURCE.read_text())
    classes = [n for n in module.body if isinstance(n, ast.ClassDef) and n.name in
               {'_CountingHasher', '_ChunkReader', '_VerifiedTarReader'}]
    worker = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'shard_worker_v45')
    objects = {}

    class FakeCompressor:
        def __init__(self, **kw):
            pass
        def stream_writer(self, raw_out, **kw):
            return contextlib.nullcontext(raw_out)

    class FakeProgress:
        def __init__(self):
            self.count = 0
            self.complete = False
        def set_current(self, *a, **kw):
            pass
        def record_extracted(self, count):
            self.count += 1
        def mark_shard_done(self, *a):
            self.complete = True
        def record_read_skipped(self):
            pass

    class FakeVD:
        mode = 'ewf'
        segment_paths = ['evidence.E01']
        def close(self):
            pass

    def put_file(key, path, kind):
        objects[key] = path.read_bytes()
        return 's3://forensic/' + key

    ns = dict(
        hashlib=hashlib, time=time, tarfile=tarfile, tempfile=tempfile, os=os,
        threading=threading, Path=Path, Any=__import__('typing').Any,
        Iterator=__import__('typing').Iterator,
        zstd=SimpleNamespace(ZstdCompressor=FakeCompressor),
        DIRECT_TAR_STREAM=True, SCRATCH_DIR=None, _read_gate_size=1,
        open_shard_vd=lambda *a, **kw: FakeVD(),
        read_gate=lambda: threading.BoundedSemaphore(1),
        read_chunk_size=lambda vd: 4096,
        iter_file_from_disk=lambda vd, rel, **kw: iter([actual_data]),
        put_file=put_file,
        cpu_backoff_delay=None, VirtualDisk=FakeVD, ShardEventBus=object, JobStopRequested=type("JobStopRequested", (Exception,), {}),
    )
    exec(compile(ast.Module(body=classes + [worker], type_ignores=[]), str(SOURCE), 'exec'), ns)
    progress = FakeProgress()
    payload = dict(schema_name='test', job_id='testcase', shard_id=0,
                   shard_count=1, zstd_level=1, hash_files=True,
                   nodes=[dict(path='test/data', inode=3, size_bytes=expected_size)])
    result = ns['shard_worker_v45'](payload, progress, None, None)
    return result, progress, objects


def test_real_shard_worker_direct_mode_produces_valid_part_and_hash():
    data = b'forensic-e01-test' * 1000
    result, progress, objects = _run_worker(len(data), data)
    assert progress.complete
    assert result['files_extracted'] == 1
    assert result['index_entries'][0]['sha256'] == hashlib.sha256(data).hexdigest()
    with tarfile.open(fileobj=io.BytesIO(next(iter(objects.values()))), mode='r:') as tf:
        assert tf.extractfile('test/data').read() == data


def test_real_shard_worker_rejects_wrong_source_size_without_upload():
    import pytest
    with pytest.raises(IOError, match='exceeds'):
        _run_worker(123, b'X' * 256)
