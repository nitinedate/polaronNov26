"""Fail early on unwritable evidence storage without deleting case objects."""
from __future__ import annotations
import errno
import io
import os
import shutil
import uuid
from pathlib import Path


class StorageCapacityError(RuntimeError):
    code = 'storage_capacity'


class StorageUnavailableError(RuntimeError):
    code = 'storage_unavailable'


def is_capacity_error(exc):
    current, seen = exc, set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, StorageCapacityError):
            return True
        if getattr(current, 'code', '') in {'XMinioStorageFull', 'StorageFull', 'InsufficientStorage'}:
            return True
        if isinstance(current, OSError) and current.errno in {errno.ENOSPC, getattr(errno, 'EDQUOT', 122)}:
            return True
        current = current.__cause__ or current.__context__
    return False


def capacity_error(exc):
    return StorageCapacityError(
        'Evidence storage capacity exhausted (XMinioStorageFull / no free space). '
        'The extraction checkpoint is retained. Increase capacity or move the complete MinIO data '
        'directory to a larger drive, verify a successful storage write, then resume this job. '
        'Processing is failed; evidence coverage is incomplete.')


def require_local_headroom(path, *, minimum_bytes=None):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(path)
    minimum = minimum_bytes if minimum_bytes is not None else 1024 * 1024 * 1024
    reserve = max(minimum, usage.total // 20)
    if usage.free < reserve:
        raise StorageCapacityError(
            f'Extraction scratch storage has {usage.free:,} bytes free; requires at least '
            f'{reserve:,} bytes of headroom. Free capacity or move job-data before resuming.')
    return {'free_bytes': usage.free, 'reserve_bytes': reserve}


def preflight_extraction_storage(job_id):
    """A write probe detects the actual S3 refusal; it does not reserve future capacity.

    Each invocation owns a unique probe. Removal targets only that probe, never
    case artifacts. Scratch headroom is measured on the worker's real data mount.
    """
    from app.config import get_settings
    from app.services.storage import _minio_client
    settings = get_settings()
    scratch = require_local_headroom(Path(settings.data_root) / 'tmp')
    client = _minio_client()
    if client is None:
        raise StorageUnavailableError('MinIO is unavailable. Extraction is held before enumeration; restore object storage and retry.')
    key = f'jobs/{job_id}/storage-probes/{uuid.uuid4().hex}'
    written = False
    try:
        client.put_object(settings.minio_bucket, key, io.BytesIO(b'1'), 1,
                          content_type='application/octet-stream')
        written = True
    except Exception as exc:
        if is_capacity_error(exc):
            raise capacity_error(exc) from exc
        raise StorageUnavailableError('Evidence storage write preflight failed. Check MinIO connectivity, bucket permissions and service health.') from exc
    finally:
        if written:
            try:
                client.remove_object(settings.minio_bucket, key)
            except Exception:
                import logging
                logging.getLogger(__name__).warning('Storage probe cleanup failed; case evidence was not removed.', exc_info=True)
    return {'status': 'writable', 'scratch': scratch, 'capacity_reserved': False}


def persist_storage_issue(db, job_id, exc):
    """Store a job-scoped operational blocker independently of evidence limitations."""
    from app.db.sql_helpers import execute
    import json
    if not isinstance(exc, (StorageCapacityError, StorageUnavailableError)) and not is_capacity_error(exc):
        return
    execute(db, """UPDATE jobs SET disk_source=COALESCE(disk_source,'{}'::jsonb)
        || CAST(:issue AS jsonb) WHERE id=:jid""",
        {'jid': job_id, 'issue': json.dumps({'storage_issue': {
            'code': 'storage_capacity' if is_capacity_error(exc) else 'storage_unavailable',
            'resolved': False, 'message': str(exc), 'requires_operator_action': True}})})
