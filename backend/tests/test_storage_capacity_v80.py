import errno
from types import SimpleNamespace
import pytest
from app.services import storage, storage_capacity as capacity


class FullError(Exception):
    code = 'XMinioStorageFull'


class Client:
    def __init__(self, error=None):
        self.error, self.puts, self.removed = error, [], []
    def put_object(self, bucket, key, data, size, **kwargs):
        self.puts.append((bucket, key, data.read(), size))
        if self.error:
            raise self.error
    def remove_object(self, bucket, key):
        self.removed.append((bucket, key))


@pytest.fixture
def setup(monkeypatch, tmp_path):
    from app import config
    monkeypatch.setattr(config, 'get_settings', lambda: SimpleNamespace(data_root=str(tmp_path), minio_bucket='mobile-android'))
    monkeypatch.setattr(capacity, 'require_local_headroom', lambda p: {'free_bytes': 10**12})


def test_full_minio_blocks_before_extraction_and_preserves_cause(setup, monkeypatch):
    client = Client(FullError('threshold reached'))
    monkeypatch.setattr(storage, '_minio_client', lambda: client)
    with pytest.raises(capacity.StorageCapacityError) as caught:
        capacity.preflight_extraction_storage('job-1')
    assert isinstance(caught.value.__cause__, FullError)
    assert 'checkpoint is retained' in str(caught.value)
    assert not client.removed


def test_probe_cleanup_is_unique_and_cannot_delete_case_evidence(setup, monkeypatch):
    client = Client()
    monkeypatch.setattr(storage, '_minio_client', lambda: client)
    for _ in range(2):
        result = capacity.preflight_extraction_storage('job-1')
        assert not result['capacity_reserved']
    assert len({p[1] for p in client.puts}) == 2
    assert client.removed == [(p[0], p[1]) for p in client.puts]
    assert all('/storage-probes/' in p[1] for p in client.puts)


def test_no_silent_local_fallback_for_extraction(setup, monkeypatch):
    monkeypatch.setattr(storage, '_minio_client', lambda: None)
    with pytest.raises(capacity.StorageUnavailableError):
        capacity.preflight_extraction_storage('job-1')


@pytest.mark.parametrize('error', [FullError(), OSError(errno.ENOSPC, 'full'), OSError(errno.EDQUOT, 'quota')])
def test_mid_upload_errors_remain_typed_and_chained(error):
    def fail():
        raise error
    with pytest.raises(capacity.StorageCapacityError) as caught:
        storage._storage_write(fail)
    assert caught.value.__cause__ is error


def test_other_errors_are_not_mislabeled_as_full():
    def fail():
        raise ValueError('corrupt source')
    with pytest.raises(ValueError):
        storage._storage_write(fail)
    assert not capacity.is_capacity_error(ValueError('bad format'))


def test_scratch_space_headroom(monkeypatch, tmp_path):
    monkeypatch.setattr(capacity.shutil, 'disk_usage', lambda p: SimpleNamespace(total=100_000, free=4_000))
    with pytest.raises(capacity.StorageCapacityError):
        capacity.require_local_headroom(tmp_path, minimum_bytes=100)


def test_caught_capacity_blocker_is_job_scoped(monkeypatch):
    from app.db import sql_helpers
    calls = []
    monkeypatch.setattr(sql_helpers, 'execute', lambda db, sql, args: calls.append((sql, args)))
    capacity.persist_storage_issue(None, 'job-1', FullError())
    assert calls[0][1]['jid'] == 'job-1'
    assert 'WHERE id=:jid' in calls[0][0]
    assert 'storage_capacity' in calls[0][1]['issue']


def test_minio_connection_failure_cache_expires(monkeypatch):
    monkeypatch.setattr(storage, '_client', None)
    monkeypatch.setattr(storage, '_client_failed', True)
    monkeypatch.setattr(storage, '_client_failed_at', 10)
    monkeypatch.setattr(storage.time, 'monotonic', lambda: 41)
    monkeypatch.setattr(storage, 'get_settings', lambda: SimpleNamespace(minio_endpoint='minio:9000', minio_access_key='x', minio_secret_key='x', minio_secure=False, minio_bucket='test'))
    import minio
    client = SimpleNamespace(bucket_exists=lambda b: True)
    monkeypatch.setattr(minio, 'Minio', lambda *a, **kw: client)
    assert storage._minio_client() is client
