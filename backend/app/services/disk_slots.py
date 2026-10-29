"""Disk parallelism is eight slots.

A semaphore admits the work. Threads are started only up to that limit.
Disk stages do not use a ThreadPoolExecutor.
"""

from __future__ import annotations

import os
import queue
import threading

DISK_SLOTS = max(1, min(8, int(os.environ.get("DISK_SLOTS", "8") or 8)))


def run_bounded(fn, items, *, slots: int | None = None):
    """Run ``fn`` on each item with at most ``DISK_SLOTS`` threads.

    Results are yielded as they finish. The first exception is raised after
    the workers drain, so a caller can still commit what already completed.
    """
    pending = list(items)
    limit = DISK_SLOTS if slots is None else max(1, min(DISK_SLOTS, int(slots or 1)))
    if len(pending) <= 1 or limit == 1:
        for item in pending:
            yield fn(item)
        return

    gate = threading.BoundedSemaphore(limit)
    work: queue.Queue = queue.Queue()
    for item in pending:
        work.put(item)
    done: queue.Queue = queue.Queue()

    def worker() -> None:
        while True:
            try:
                item = work.get_nowait()
            except queue.Empty:
                return
            with gate:
                try:
                    done.put((True, fn(item)))
                except BaseException as exc:
                    done.put((False, exc))

    threads = [
        threading.Thread(target=worker, name=f"disk-slot-{index}", daemon=False)
        for index in range(min(limit, len(pending)))
    ]
    for thread in threads:
        thread.start()
    finished = 0
    failure: BaseException | None = None
    while finished < len(pending):
        ok, value = done.get()
        finished += 1
        if ok:
            yield value
        elif failure is None:
            failure = value
    for thread in threads:
        thread.join()
    if failure is not None:
        raise failure
