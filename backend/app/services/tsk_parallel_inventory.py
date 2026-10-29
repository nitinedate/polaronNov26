"""Bounded, read-only parallel TSK directory inventory.

Each executor thread opens its *own* pyewf/pytsk3 handle; handles are never
shared across threads. Discovery and scheduling are coordinated by the child
process already supervised by tsk_walk_isolated, so a stalled native call can
still be killed without committing an incomplete inventory.
"""
from __future__ import annotations

import os
import queue
import threading
import time
from collections import deque
from typing import Any


def inventory_readers(vd, *, requested: str | None = None) -> tuple[int, str]:
    """Cap metadata read concurrency for seek-heavy compressed/rotational media."""
    raw = str(requested if requested is not None else os.getenv('EXTRACT_TSK_ENUM_WORKERS', '2')).strip().lower()
    if raw in ('off', 'false', 'no', '0', 'serial'):
        return 1, 'disabled'
    try:
        target = max(1, min(int(raw), 8)) if raw not in ('auto', '') else 2
    except ValueError:
        target = 2
    media = 'unknown'
    try:
        from app.services.disk_io_profile import detect_source_io_profile
        media = detect_source_io_profile(list(vd.segment_paths or [])).media
    except Exception:
        pass
    if media in ('hdd', 'network'):
        target = min(target, 2)
    return target, media


def enumerate_tsk_parallel(vd, *, on_progress=None, root_open_strategy: str = 'inode',
                           workers: int = 2, progress_interval_sec: float = 10.0) -> list[dict]:
    """Discover every regular-file path by scheduling independent inode directory reads.

    A failure opening a directory is recorded as a source limitation, not an
    invented successful directory. A failed reader setup aborts the entire walk.
    The calling isolated parent only accepts a complete result and will retry
    serially when configured to do so.
    """
    from app.services import virtual_disk as disk

    if workers < 2 or vd._fs_info is None or disk._pytsk3 is None:
        raise ValueError('Parallel inventory requires 2+ workers and a mounted TSK filesystem')
    if root_open_strategy not in ('inode', 'path'):
        raise ValueError(f'Invalid TSK root strategy: {root_open_strategy}')
    workers = max(2, min(int(workers), 8))
    root_inode = disk.filesystem_root_inode(vd._fs_info)
    root_method = 'inode' if root_open_strategy == 'inode' and root_inode is not None else 'path'
    metadata = {'action': 'tsk_walk_start', 'mode': vd.mode, 'reader_phase': 'root_open',
                'root_open_strategy': root_method, 'root_inode': root_inode,
                'inventory_workers': workers, 'inventory_parallel': True}
    def emit(msg, fields):
        if on_progress:
            on_progress(msg, fields)
    emit('Starting TSK filesystem walk (parallel directory inventory)...', metadata)
    emit(f'TSK: opening root directory ({root_method})...', {
        **metadata, 'action': 'tsk_root_open'})
    start = time.monotonic()
    root = (vd._fs_info.open_dir(inode=root_inode) if root_method == 'inode'
            else vd._fs_info.open_dir(path='/'))
    emit(f'TSK root directory opened in {time.monotonic()-start:.1f}s; reading first entry...', {
        **metadata, 'action': 'tsk_root_opened', 'reader_phase': 'root_first_entry'})

    reg = disk._tsk_meta_type(disk._pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG)
    dr = disk._tsk_meta_type(disk._pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR)
    lock = threading.Lock()
    thread_local = threading.local()
    handles: list[Any] = []
    live: list[threading.Thread] = []
    jobs: queue.Queue | None = None
    stop = None
    counts = {'entries_scanned': 0, 'unreadable_directories': 0,
              'metadata_missing': 0, 'files_found': 0, 'directories_scanned': 0,
              'alias_directories_skipped': 0}
    # A worker only changes counters, never the node or scheduling collections.
    scan_progress_at = [time.monotonic()]
    def count(name, n=1):
        with lock:
            counts[name] += n

    def snapshot():
        with lock:
            return dict(counts)

    def scan(directory, path):
        found, children = [], []
        pending_entries = 0
        seen_first = False
        errors = []
        try:
            for entry in directory:
                pending_entries += 1
                if pending_entries >= 256:
                    count('entries_scanned', pending_entries)
                    pending_entries = 0
                # The initial TSK root can contain tens of thousands of entries.
                # Report actual scanned entries while still iterating it, rather
                # than allowing the watchdog to mistake it for a native hang.
                if path == '<root>' and time.monotonic() - scan_progress_at[0] >= max(5.0, float(progress_interval_sec)):
                    scan_progress_at[0] = time.monotonic()
                    partial = snapshot()
                    emit(f"TSK filesystem walk — {len(nodes) + len(found):,} files, "
                         f"{partial['directories_scanned'] + 1:,} directories, "
                         f"{partial['entries_scanned'] + pending_entries:,} entries",
                         {'action': 'tsk_walk_progress', 'reader_phase': 'walking',
                          **partial, 'files_found': len(nodes) + len(found),
                          'directories_scanned': partial['directories_scanned'] + 1,
                          'entries_scanned': partial['entries_scanned'] + pending_entries,
                          'inventory_workers': workers, 'inventory_parallel': True,
                          'last_path': '<root>'})
                if not seen_first:
                    seen_first = True
                    # Root first-entry milestone must reach the watchdog early.
                    if path == '<root>':
                        emit('TSK root first entry readable; traversing filesystem...', {
                            'action': 'tsk_root_first_entry', 'reader_phase': 'walking',
                            'entries_scanned': snapshot()['entries_scanned'] + 1,
                            'inventory_workers': workers, 'inventory_parallel': True})
                try:
                    info = entry.info
                    raw = info.name.name if info and info.name else None
                    if not raw or raw in (b'.', b'..'):
                        continue
                    name = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else str(raw)
                    rel = name if path == '<root>' else f'{path}/{name}'
                    meta = info.meta
                    if meta is None:
                        count('metadata_missing')
                        continue
                    typ = disk._tsk_meta_type(meta.type)
                    addr = getattr(meta, 'addr', None)
                    inode = int(addr) if addr is not None else None
                    if typ == reg:
                        found.append({'path': rel, 'name': name, 'size_bytes': meta.size or 0, 'inode': inode})
                    elif typ == dr:
                        children.append((rel, inode))
                except Exception as exc:
                    count('unreadable_directories')
                    if len(errors) < 5:
                        errors.append(f'Entry metadata error at {path}: {exc}')
        except Exception as exc:
            count('unreadable_directories')
            errors.append(f'Directory iteration failed at {path}: {exc}')
        finally:
            if pending_entries:
                count('entries_scanned', pending_entries)
        count('directories_scanned')
        return found, children, errors

    def worker_scan(item):
        path, inode = item
        local_vd = getattr(thread_local, 'vd', None)
        if local_vd is None:
            # Independent libewf + pytsk3 handle for this worker thread.
            local_vd = disk.open_virtual_disk_from_paths(
                vd.job_id, list(vd.segment_paths), hashes=list(vd.segment_hashes),
                base_name=vd.base_name, fmt=vd.format, root_folder=vd.root_folder)
            if local_vd._fs_info is None:
                raise RuntimeError('Parallel TSK reader could not open the evidence filesystem')
            thread_local.vd = local_vd
            with lock:
                handles.append(local_vd)
        try:
            directory = (local_vd._fs_info.open_dir(inode=inode) if inode is not None
                         else local_vd._fs_info.open_dir(path='/' + path))
        except Exception as first_exc:
            if inode is None:
                count('unreadable_directories')
                return [], [], [f'Unable to open TSK directory {path}: {first_exc}']
            try:
                directory = local_vd._fs_info.open_dir(path='/' + path)
            except Exception as second_exc:
                count('unreadable_directories')
                return [], [], [f'Unable to open TSK directory {path}: inode={first_exc}; path={second_exc}']
        return scan(directory, path)

    nodes = []
    pending = deque()
    seen_inodes = {root_inode} if root_inode is not None else set()
    seen_paths = {'<root>'}
    last_path = '<root>'
    errors_emitted = 0

    def absorb(result):
        nonlocal last_path, errors_emitted
        files, children, errors = result
        nodes.extend(files)
        count('files_found', len(files))
        for err in errors:
            if errors_emitted < 8:
                emit(err, {'action': 'tsk_directory_error', 'reader_phase': 'walking'})
                errors_emitted += 1
        for rel, inode in children:
            if inode is not None and inode in seen_inodes:
                count('alias_directories_skipped')
                continue
            if rel in seen_paths:
                count('alias_directories_skipped')
                continue
            if inode is not None:
                seen_inodes.add(inode)
            seen_paths.add(rel)
            pending.append((rel, inode))
            # Fail closed rather than consume unbounded memory on corrupt metadata.
            if len(pending) > 1_000_000:
                raise RuntimeError('TSK directory backlog exceeded one million; check filesystem metadata')
        if files:
            last_path = files[-1]['path']
        elif children:
            last_path = children[-1][0]

    try:
        absorb(scan(root, '<root>'))
        # The root is accessed on the original isolated-reader handle; every
        # directory below it is opened by independent handles in worker threads.
        last_emit = time.monotonic()
        last_speed = snapshot()
        slots = max(1, min(int(workers), 8))
        gate = threading.BoundedSemaphore(slots)
        jobs = queue.Queue()
        results: queue.Queue = queue.Queue()
        stop = object()
        submitted = 0
        completed = 0

        def _run():
            while True:
                item = jobs.get()
                if item is stop:
                    return
                try:
                    with gate:
                        value = worker_scan(item)
                    results.put((item, value, None))
                except Exception as exc:
                    results.put((item, None, exc))

        for index in range(slots):
            thread = threading.Thread(target=_run, name=f'tsk-enumerate-{index}')
            thread.start()
            live.append(thread)

        def _feed() -> None:
            nonlocal submitted
            while pending:
                jobs.put(pending.popleft())
                submitted += 1

        _feed()
        while completed < submitted:
            try:
                item, value, err = results.get(timeout=1.0)
            except queue.Empty:
                pass
            else:
                completed += 1
                if err is not None:
                    raise err
                last_path = item[0]
                absorb(value)  # Reader-setup errors fail closed.
                _feed()
            if time.monotonic() - last_emit >= max(5.0, float(progress_interval_sec)):
                now = time.monotonic()
                elapsed = max(now - last_emit, 0.001)
                last_emit = now
                snap = snapshot()
                speed = {
                    "entries_per_sec": round((snap['entries_scanned'] - last_speed['entries_scanned']) / elapsed, 1),
                    "directories_per_sec": round((snap['directories_scanned'] - last_speed['directories_scanned']) / elapsed, 1),
                }
                last_speed = snap
                emit(f"TSK filesystem walk — {snap['files_found']:,} files, "
                     f"{snap['directories_scanned']:,} directories, {snap['entries_scanned']:,} entries",
                     {'action': 'tsk_walk_progress', 'reader_phase': 'walking',
                      **snap, **speed, 'inventory_workers': workers, 'inventory_parallel': True,
                      'pending_directories': len(pending), 'active_directories': submitted - completed,
                      'last_path': last_path})
    finally:
        if jobs is not None and stop is not None:
            for _thread in live:
                jobs.put(stop)
        for thread in live:
            thread.join()
        for handle in handles:
            handle.close()

    # Deterministic inventory manifests even when different workers complete
    # their directories in different orders. Keep distinct hard-link paths.
    nodes.sort(key=lambda item: (str(item['path']), int(item.get('inode') or -1)))
    snap = snapshot()
    emit(f"TSK walk complete — {len(nodes):,} files, {snap['directories_scanned']:,} directories",
         {'action': 'tsk_walk_complete', 'reader_phase': 'complete', **snap,
          'inventory_workers': workers, 'inventory_parallel': True, 'last_path': last_path})
    return nodes
