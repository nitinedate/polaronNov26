"""Bounded one-pass inventory-to-extraction handoff.

Integration point: call submit(node) from a *committed* inventory batch after the
source's extraction policy (including OS detection) has been resolved. Each node
must have a stable source_id and inode/path; the extractor is responsible for
producing a durable MinIO object and returning its verified manifest entry.

This module does not alter existing job checkpoints or bypass the isolated TSK
watchdog. The caller must persist results transactionally and mark the batch
complete only after its manifest has been committed.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from threading import BoundedSemaphore, Lock
from typing import Any, Callable, Iterable


class BoundedInventoryUpload:
    """Bound in-flight tasks and keep source reads separate from upload policy.

    `extract_and_upload` must be idempotent for `(source_id, path, inode)` and
    must return a durable index record; a raised error is retained for retry.
    Backpressure blocks the inventory producer rather than allocating unlimited
    futures. `finish()` returns one result or error per accepted node.
    """

    def __init__(self, extract_and_upload: Callable[[dict], dict], *, workers: int = 2,
                 max_pending: int = 32):
        if not 1 <= workers <= max_pending:
            raise ValueError('Require 1 <= workers <= max_pending')
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='evidence-writer')
        self._slots = BoundedSemaphore(max_pending)
        self._lock = Lock()
        self._futures: list[tuple[dict, Future]] = []
        self._keys: set[tuple[str, str, str]] = set()
        self._closed = False
        self._fn = extract_and_upload

    @staticmethod
    def identity(node: dict) -> tuple[str, str, str]:
        source = str(node['source_id'])
        path = str(node['path'])
        if not source or not path:
            raise ValueError('source_id and path required')
        return (source, path, str(node.get('inode') or ''))

    def submit(self, node: dict) -> bool:
        key = self.identity(node)
        self._slots.acquire()
        with self._lock:
            if self._closed:
                self._slots.release()
                raise RuntimeError('Pipeline already closed')
            if key in self._keys:
                self._slots.release()
                return False
            self._keys.add(key)
            try:
                future = self._pool.submit(self._fn, dict(node))
            except BaseException:
                self._keys.remove(key)
                self._slots.release()
                raise
            future.add_done_callback(lambda _: self._slots.release())
            self._futures.append((dict(node), future))
        return True

    def finish(self) -> tuple[list[dict], list[dict]]:
        with self._lock:
            self._closed = True
        successes: list[dict] = []
        failures: list[dict] = []
        try:
            for node, future in self._futures:
                try:
                    manifest_entry = future.result()
                    if not isinstance(manifest_entry, dict) or not manifest_entry.get('object_uri'):
                        raise ValueError('Uploader did not return durable object_uri')
                    successes.append(manifest_entry)
                except Exception as exc:
                    failures.append({'source_id': node['source_id'], 'path': node['path'],
                                     'inode': node.get('inode'), 'error': str(exc)})
        finally:
            self._pool.shutdown(wait=True)
        return successes, failures
