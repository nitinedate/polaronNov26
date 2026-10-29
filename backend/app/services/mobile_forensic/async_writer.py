"""Bounded per-job asynchronous artifact writer.

The writer exclusively owns its SQLAlchemy session. All checkpoint acknowledgements
mean the database context manager has completed its commit successfully.
"""
from __future__ import annotations

from queue import Queue
from threading import Thread, Lock


class MobileArtifactWriter:
    def __init__(self, schema: str, job_id: str, max_pending: int = 6):
        if not schema or not job_id:
            raise ValueError("Writer requires a firm schema and job identifier")
        self.schema = schema
        self.job_id = job_id
        self.queue = Queue(maxsize=max(1, min(int(max_pending), 32)))
        self.error = None
        self.thread = None
        self.closed = False
        self._error_lock = Lock()
        self.committed_batches = 0
        self.committed_artifacts = 0

    def __enter__(self):
        self.thread = Thread(target=self._run, name=f"mobile-db-writer-{self.job_id[:8]}", daemon=True)
        self.thread.start()
        return self

    def _run(self):
        from app.db.session import firm_session
        from app.services.mobile_forensic.storage import persist_artifacts
        while True:
            batch = self.queue.get()
            try:
                if batch is None:
                    return
                if self.error is not None:
                    continue  # A failed transaction cannot acknowledge subsequent batches.
                try:
                    with firm_session(self.schema) as db:
                        persist_artifacts(db, self.job_id, batch)
                    # Do not acknowledge success until context manager COMMIT returns.
                    self.committed_batches += 1
                    self.committed_artifacts += len(batch)
                except BaseException as exc:
                    with self._error_lock:
                        if self.error is None:
                            self.error = exc
            finally:
                self.queue.task_done()

    def _ensure_healthy(self):
        if self.closed or self.error is not None or (self.thread and not self.thread.is_alive()):
            raise RuntimeError("Artifact writer stopped or failed") from self.error

    def submit(self, buffer):
        self._ensure_healthy()
        if not buffer:
            return 0
        batch = tuple(buffer)
        self.queue.put(batch)  # Bounded producer backpressure.
        buffer.clear()
        self._ensure_healthy()
        return len(batch)

    def checkpoint(self):
        self.queue.join()
        if self.error is not None:
            raise RuntimeError("Artifact writer transaction failed") from self.error
        self._ensure_healthy()
        return self.committed_artifacts

    def __exit__(self, exc_type, exc, tb):
        checkpoint_error = None
        try:
            self.checkpoint()
        except BaseException as error:
            checkpoint_error = error
        finally:
            self.closed = True
            self.queue.put(None)
            self.thread.join(timeout=30)
        if self.thread.is_alive():
            raise RuntimeError("Artifact writer failed to shut down; job must remain unfinalized")
        if checkpoint_error is not None and exc_type is None:
            raise checkpoint_error
        return False
