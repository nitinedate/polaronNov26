"""Disk extraction shard worker — V45 (streaming, DB-free, semaphore-gated).

Replaces ``extracted_disk._shard_worker``. Behavioural contract (checkpoint
format, part naming ``parts/part-NNNNN.tar.zst``, index entries, return dict,
``JobStopRequested`` semantics) is unchanged so resume/Phase-3 keep working.

Fixes shipped here
------------------
1. **No DB connection inside shard threads.**  The pre-V45 worker opened a
   ``firm_session`` for the start log, every ``_check_stop`` (each 1 000 files)
   and every unreadable-file log.  With a Celery worker pool of 2+2 and the
   main session + flusher + stop-poller + heartbeat already holding 4, the
   first shard that needed a connection waited 30 s and died with
   ``QueuePool limit of size 2 overflow 2 reached``.  Shard threads now push
   events onto ``ShardEventBus``; the single flusher thread drains it.

2. **Streaming reads.**  Files are streamed from the image in 1–8 MiB chunks
   through a ``SpooledTemporaryFile`` (RAM up to ``EXTRACT_SPOOL_MAX_BYTES``,
   then scratch disk) straight into the tar, with SHA-256 computed in the same
   pass.  No more ``read_full_file_from_disk`` → ``io.BytesIO`` copies.

3. **Bounded read semaphore.**  ``EXTRACT_READ_SEMAPHORE`` (default 8, max 8) caps
   *concurrent image reads* independently of the shard count, so 14 resumable
   shards no longer mean 14 random-seeking pyewf handles.  Rotational/USB
   sources get an automatic cap of ``EXTRACT_HDD_READERS`` (default 2) via
   ``disk_io_profile`` (which existed but was never imported).

4. **Uploads within the shard worker.** A finished part uploads before that
   evidence worker completes. The four-worker extraction pool therefore also
   bounds upload work and retains checkpoint correctness.

5. **Scratch on fast storage.**  Temporary parts go to ``EXTRACT_SCRATCH_DIR``
   when set (point it at NVMe/SSD when the evidence is on a USB HDD).
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import zstandard as zstd

from app.services.job_control import JobStopRequested
from app.services.storage import put_file
from app.services.virtual_disk import VirtualDisk, iter_file_from_disk, open_virtual_disk

log = logging.getLogger("extracted_disk.v45")


# ---------------------------------------------------------------------------
# Tunables (env, with safe defaults)
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name) or default)))
    except (TypeError, ValueError):
        return default


READ_SEMAPHORE_SIZE = _env_int("EXTRACT_READ_SEMAPHORE", 8, 1, 8)
HDD_READERS = _env_int("EXTRACT_HDD_READERS", 2, 1, 2)
SPOOL_MAX_BYTES = _env_int("EXTRACT_SPOOL_MAX_BYTES", 128 * 1024 * 1024, 1 << 20, 1 << 30)
READ_CHUNK_BYTES = _env_int("EXTRACT_READ_CHUNK_BYTES", 8 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024)
HDD_READ_CHUNK_BYTES = _env_int("EXTRACT_HDD_CHUNK_BYTES", 16 * 1024 * 1024, 1 << 20, 64 * 1024 * 1024)
UPLOAD_POOL_SIZE = _env_int("EXTRACT_UPLOAD_CONCURRENCY", 8, 1, 12)
SCRATCH_DIR = (os.environ.get("EXTRACT_SCRATCH_DIR") or "").strip() or None
# Opt in on a representative case first.  For a known-size TSK regular file
# direct streaming eliminates the per-file RAM/disk spool and second copy.
# A size mismatch must fail the *whole uncommitted part*: after tar.addfile has
# started, attempting to skip a damaged member would corrupt the tar stream.
DIRECT_TAR_STREAM = (os.environ.get("EXTRACT_DIRECT_TAR_STREAM", "false").strip().lower()
                     in {"1", "true", "yes", "on"})


# ---------------------------------------------------------------------------
# Shared gates (one per worker process)
# ---------------------------------------------------------------------------

_read_gate_lock = threading.Lock()
_read_gate: threading.BoundedSemaphore | None = None
_read_gate_size = 0


def configure_read_gate(size: int) -> threading.BoundedSemaphore:
    """(Re)size the process-wide image-read semaphore. Safe to call per job."""
    global _read_gate, _read_gate_size
    size = max(1, min(8, int(size)))
    with _read_gate_lock:
        if _read_gate is None or _read_gate_size != size:
            _read_gate = threading.BoundedSemaphore(size)
            _read_gate_size = size
        return _read_gate


def read_gate() -> threading.BoundedSemaphore:
    return configure_read_gate(_read_gate_size or READ_SEMAPHORE_SIZE)


# Uploads share the disk semaphore. There is no process-wide thread pool.


# ---------------------------------------------------------------------------
# Source-aware reader planning
# ---------------------------------------------------------------------------

def plan_readers(vd: VirtualDisk, requested_readers: int) -> tuple[int, int, str]:
    """Return (parallel_readers, read_semaphore, reason) honoring the physical source.

    Rotational / USB / network sources collapse to a sequential-ish profile:
    one or two readers, bigger chunks. SSD/NVMe keep the planner's number but
    never exceed the configured semaphore.
    """
    requested = max(1, int(requested_readers))
    # One payload zip on a Docker Desktop drive mount (/host/<letter>/…). Extra
    # .pas/.ufd/.ufdx sidecars do not make the archive safe to seek in parallel:
    # several threads on that file drop throughput and can return [Errno 5].
    host_paths = [str(p).replace("\\", "/") for p in (getattr(vd, "segment_paths", None) or [])]
    host_zips = [p for p in host_paths if p.lower().endswith(".zip") and p.startswith("/host/")]
    if len(host_zips) == 1:
        return 1, 1, "single_zip_host_mount:readers<=1"
    media, detection = "unknown", "unavailable"
    try:
        from app.services.disk_io_profile import detect_source_io_profile

        prof = detect_source_io_profile(list(getattr(vd, "segment_paths", []) or []))
        media, detection = prof.media, prof.detection
    except Exception:
        pass
    sem = READ_SEMAPHORE_SIZE
    if media in ("hdd", "network"):
        readers = min(requested, HDD_READERS)
        return readers, min(sem, readers), f"{media}:{detection}:readers<={HDD_READERS}"
    if media == "unknown":
        # Docker Desktop on Windows hides the block device. Be conservative but
        # not sequential: half the semaphore until the examiner sets
        # DISK_SOURCE_MEDIA=ssd|nvme|hdd explicitly.
        readers = min(requested, max(2, sem // 2))
        return readers, min(sem, readers), f"unknown_media:{detection}:readers<={readers}"
    readers = min(requested, sem)
    return readers, min(sem, readers), f"{media}:{detection}:readers<={sem}"


def read_chunk_size(vd: VirtualDisk) -> int:
    try:
        from app.services.disk_io_profile import detect_source_io_profile

        if detect_source_io_profile(list(getattr(vd, "segment_paths", []) or [])).media in ("hdd", "network"):
            return HDD_READ_CHUNK_BYTES
    except Exception:
        pass
    return READ_CHUNK_BYTES


# ---------------------------------------------------------------------------
# Event bus: shard threads never touch the DB
# ---------------------------------------------------------------------------

class ShardEventBus:
    """Thread-safe queue of log/progress events, drained by the flusher thread.

    ``drain()`` returns (level, message, metadata) tuples ready for
    ``write_disk_log``. Capped so a pathological shard cannot grow RAM.
    """

    def __init__(self, maxsize: int = 5000) -> None:
        self._q: queue.Queue[tuple[str, str, dict[str, Any]]] = queue.Queue(maxsize=maxsize)
        self.dropped = 0

    def emit(self, message: str, *, level: str = "info", metadata: dict[str, Any] | None = None) -> None:
        try:
            self._q.put_nowait((level, message, dict(metadata or {})))
        except queue.Full:
            self.dropped += 1

    def drain(self, limit: int = 500) -> list[tuple[str, str, dict[str, Any]]]:
        out: list[tuple[str, str, dict[str, Any]]] = []
        while len(out) < limit:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out


# ---------------------------------------------------------------------------
# Streaming file → tar
# ---------------------------------------------------------------------------

class _CountingHasher:
    __slots__ = ("h", "n")

    def __init__(self, enabled: bool) -> None:
        self.h = hashlib.sha256() if enabled else None
        self.n = 0

    def update(self, b: bytes) -> None:
        self.n += len(b)
        if self.h is not None:
            self.h.update(b)

    def hexdigest(self) -> str:
        return self.h.hexdigest() if self.h is not None else ""


class _ChunkReader:
    """File-like over an iterator so tar can stream a zip member without a spool."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._it = iter(chunks)
        self._buf = b""
        self._eof = False

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            parts = [self._buf]
            self._buf = b""
            parts.extend(self._it)
            self._eof = True
            return b"".join(parts)
        while len(self._buf) < n:
            try:
                nxt = next(self._it)
            except StopIteration:
                self._eof = True
                break
            if nxt:
                self._buf += nxt
        out = self._buf[:n]
        self._buf = self._buf[n:]
        return out

    def exhausted(self) -> bool:
        if self._buf:
            return False
        if self._eof:
            return True
        try:
            nxt = next(self._it)
        except StopIteration:
            self._eof = True
            return True
        if nxt:
            self._buf = nxt
            return False
        return self.exhausted()


class _VerifiedTarReader:
    """A counting/hash reader used by tarfile for known-size TSK files.

    Unlike spooling, the tar member is written as the evidence is read.  The
    caller MUST discard the entire shard on short reads, unexpectedly long
    files, or native-reader exceptions, since tarfile may have emitted a
    partial member by that point.  This reader never changes evidence bytes.
    """

    def __init__(self, chunks: Iterator[bytes], *, hash_files: bool) -> None:
        self._source = _ChunkReader(chunks)
        self._hash = _CountingHasher(hash_files)
        self.read_seconds = 0.0

    def read(self, size: int = -1) -> bytes:
        started = time.monotonic()
        block = self._source.read(size)
        self.read_seconds += time.monotonic() - started
        if block:
            self._hash.update(block)
        return block

    def verify(self, expected_size: int) -> tuple[int, str]:
        if self._hash.n != expected_size:
            raise IOError(f"TSK streamed {self._hash.n} bytes; expected {expected_size}")
        if not self._source.exhausted():
            raise IOError("TSK file exceeds its recorded size; discard incomplete tar shard")
        return self._hash.n, self._hash.hexdigest()


def _stream_into_spool(
    chunks: Iterator[bytes],
    *,
    hash_files: bool,
    spool_dir: str | None,
) -> tuple[tempfile.SpooledTemporaryFile, int, str]:
    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX_BYTES, dir=spool_dir)
    ch = _CountingHasher(hash_files)
    for chunk in chunks:
        if not chunk:
            continue
        spool.write(chunk)
        ch.update(chunk)
    spool.seek(0)
    return spool, ch.n, ch.hexdigest()


def open_shard_vd(schema_name: str, job_id: str, payload: dict) -> VirtualDisk:
    """Open a VirtualDisk for a shard WITHOUT a DB session when the payload carries the plan.

    ``extracted_disk`` is patched to put ``vd_plan`` (segment_paths, mode,
    format, root_folder, base_name) into each payload; if an old payload lacks
    it we fall back to the DB-backed opener using a short-lived session.
    """
    plan = payload.get("vd_plan") or {}
    paths = list(plan.get("segment_paths") or [])
    if paths:
        try:
            from app.services.virtual_disk import open_virtual_disk_from_paths  # V45 helper (patched in)

            return open_virtual_disk_from_paths(
                job_id,
                paths,
                hashes=list(plan.get("segment_hashes") or []),
                base_name=str(plan.get("base_name") or ""),
                fmt=str(plan.get("format") or ""),
                root_folder=plan.get("root_folder"),
            )
        except ImportError:
            pass
    from app.db.session import firm_session

    with firm_session(schema_name) as db:
        return open_virtual_disk(db, job_id)


def shard_worker_v45(
    payload: dict,
    progress: Any,
    flusher: Any | None,
    stop_poller: Any | None,
    *,
    shared_vd: VirtualDisk | None = None,
    event_bus: ShardEventBus | None = None,
) -> dict:
    """Extract one shard to a zstd tar part and upload it. Never touches the DB."""
    schema_name = payload["schema_name"]
    job_id = payload["job_id"]
    shard_id = int(payload["shard_id"])
    shard_count = int(payload["shard_count"])
    nodes = sorted(
        payload["nodes"],
        key=lambda n: (
            n.get("inode") is None,
            int(n["inode"]) if n.get("inode") is not None else 0,
            n.get("path", ""),
        ),
    )
    zstd_level = max(int(payload.get("zstd_level") or 1), 1)
    hash_files = bool(payload.get("hash_files"))
    stop_check_interval = max(int(payload.get("stop_check_interval") or 200), 1)
    tar_bufsize = max(int(payload.get("tar_bufsize") or 1_048_576), 65_536)
    bus = event_bus
    emit = bus.emit if bus is not None else (lambda *a, **k: None)

    part_name = f"parts/part-{shard_id:05d}.tar.zst"
    part_key = f"{payload.get('part_prefix') or f'jobs/{job_id}/extracted-disk'}/{part_name}"

    index_entries: list[dict] = []
    bytes_written = 0
    skip_count = 0
    stopped = False
    owns_vd = shared_vd is None
    vd = shared_vd or open_shard_vd(schema_name, job_id, payload)
    gate = read_gate()
    chunk = read_chunk_size(vd)
    spool_dir = SCRATCH_DIR if SCRATCH_DIR and os.path.isdir(SCRATCH_DIR) else None
    forward = None
    if any(n.get("inode") is not None for n in nodes):
        zips = [Path(str(p)) for p in (getattr(vd, "segment_paths", None) or []) if str(p).lower().endswith(".zip")]
        if len(zips) == 1:
            try:
                from app.services.virtual_disk import ZipForwardReader

                forward = ZipForwardReader(zips[0])
            except Exception:
                log.debug("forward zip reader unavailable", exc_info=True)
                forward = None

    emit(
        f"Shard {shard_id}/{shard_count - 1} started — {len(nodes):,} files "
        f"(stream, gate={_read_gate_size}, chunk={chunk // (1 << 20)} MiB, mode={vd.mode}"
        f"{', forward-zip' if forward is not None else ''})",
        metadata={"shard_id": shard_id, "files_in_shard": len(nodes), "mode": vd.mode, "v45": True, "forward_zip": forward is not None},
    )

    try:
        from app.services.adaptive_semaphore import cpu_backoff_delay
    except Exception:
        cpu_backoff_delay = None
    thermal_check_every = 64

    fd, tmp_name = tempfile.mkstemp(suffix=".tar.zst", dir=spool_dir)
    os.close(fd)
    tmp_path = Path(tmp_name)
    part_uri = ""
    file_idx = 0
    detail_every = max(stop_check_interval * 10, 5_000)
    t0 = time.monotonic()
    read_seconds = 0.0
    pack_seconds = 0.0
    upload_seconds = 0.0
    directly_streamed = 0

    try:
        cctx = zstd.ZstdCompressor(level=zstd_level, threads=1)
        # Large writes keep the stream compressor near one-shot speed. The
        # default chunk size spends most of its time in the Python wrapper.
        with tmp_path.open("wb") as raw_out, cctx.stream_writer(raw_out, write_size=8 * 1024 * 1024) as compressed, tarfile.open(
            fileobj=compressed, mode="w|", bufsize=tar_bufsize, copybufsize=8 * 1024 * 1024
        ) as tar:
            offset = 0
            for node in nodes:
                file_idx += 1
                if cpu_backoff_delay is not None and file_idx % thermal_check_every == 0:
                    try:
                        delay = float(cpu_backoff_delay())
                        if delay > 0:
                            time.sleep(delay)
                    except Exception:
                        pass
                if file_idx % stop_check_interval == 0 and stop_poller is not None and stop_poller.is_requested():
                    stopped = True
                    break
                rel = node["path"]
                inode = node.get("inode")
                size_hint = int(node.get("size_bytes") or 0)
                progress.set_current(rel, action="reading", shard_id=shard_id)
                if flusher and (file_idx == 1 or file_idx % max(stop_check_interval, 200) == 0):
                    flusher.mark_dirty()
                streamed = False
                spool = None
                nbytes = 0
                digest = ""
                try:
                    if forward is not None and inode is not None:
                        # A ZIP member is already iterable in source order. Use
                        # the *same* read to hash and pack it: the previous code
                        # disabled this fast path when SHA-256 was enabled and
                        # returned to a costly read/spool/re-read cycle.
                        progress.set_current(rel, action="packing", shard_id=shard_id)
                        reader = _VerifiedTarReader(
                            forward.iter_member(int(inode), chunk), hash_files=hash_files,
                        )
                        info = tarfile.TarInfo(name=rel.replace("\\", "/"))
                        info.size = size_hint
                        info.mtime = int(node.get("mtime") or 0) or int(time.time())
                        started = time.monotonic()
                        with gate:
                            tar.addfile(info, reader if size_hint else None)
                            nbytes, digest = reader.verify(size_hint)
                        took = time.monotonic() - started
                        read_seconds += reader.read_seconds
                        pack_seconds += max(took - reader.read_seconds, 0.0)
                        directly_streamed += 1
                        streamed = True
                    elif DIRECT_TAR_STREAM and vd.mode in ("ewf", "raw") and inode is not None and size_hint > 0:
                        # Direct input-to-tar for regular known-size E01 files.
                        # Keep the original source read gate and independent
                        # EWF reader.  Failure here is fatal to this shard,
                        # not a silently skipped forensic file.
                        info = tarfile.TarInfo(name=rel.replace("\\", "/"))
                        info.size = size_hint
                        info.mtime = int(node.get("mtime") or 0) or int(time.time())
                        reader = _VerifiedTarReader(
                            iter_file_from_disk(vd, rel, inode=int(inode), chunk_size=chunk),
                            hash_files=hash_files,
                        )
                        started = time.monotonic()
                        with gate:
                            progress.set_current(rel, action="streaming", shard_id=shard_id)
                            tar.addfile(info, reader)
                            nbytes, digest = reader.verify(size_hint)
                        took = time.monotonic() - started
                        read_seconds += reader.read_seconds
                        pack_seconds += max(took - reader.read_seconds, 0.0)
                        directly_streamed += 1
                        streamed = True
                    else:
                        started = time.monotonic()
                        with gate:   # bounded concurrent image reads
                            spool, nbytes, digest = _stream_into_spool(
                                iter_file_from_disk(
                                    vd, rel, inode=int(inode) if inode is not None else None, chunk_size=chunk
                                ),
                                hash_files=hash_files,
                                spool_dir=spool_dir,
                            )
                        read_seconds += time.monotonic() - started
                        progress.set_current(rel, action="packing", shard_id=shard_id)
                        info = tarfile.TarInfo(name=rel.replace("\\", "/"))
                        info.size = nbytes
                        info.mtime = int(node.get("mtime") or 0) or int(time.time())
                        started = time.monotonic()
                        tar.addfile(info, spool if nbytes else None)
                        pack_seconds += time.monotonic() - started
                except Exception as exc:
                    if streamed or (DIRECT_TAR_STREAM and vd.mode in ("ewf", "raw") and inode is not None and size_hint > 0) or (forward is not None and inode is not None):
                        emit(
                            f"Shard {shard_id} failed: {exc}",
                            level="error",
                            metadata={"shard_id": shard_id, "error": str(exc)[:500]},
                        )
                        raise
                    skip_count += 1
                    progress.record_read_skipped()
                    progress.set_current(rel, action="skip_unreadable", shard_id=shard_id)
                    if skip_count <= 10:
                        emit(
                            f"Shard {shard_id}: could not read {rel} — {exc}",
                            level="warning",
                            metadata={"shard_id": shard_id, "current_path": rel, "error": str(exc)[:300], "action": "skip_unreadable"},
                        )
                    continue
                finally:
                    if spool is not None:
                        spool.close()
                index_entries.append(
                    {"path": rel, "size_bytes": nbytes, "sha256": digest, "part_id": shard_id, "offset": offset}
                )
                offset += nbytes
                bytes_written += nbytes
                progress.record_extracted(nbytes)
                progress.set_current(rel, action="stored", shard_id=shard_id)
                if file_idx == 1 or file_idx % detail_every == 0:
                    emit(
                        f"Shard {shard_id}: processed #{file_idx:,}/{len(nodes):,} — {rel} ({nbytes:,} bytes"
                        + (f", listed {size_hint:,}" if size_hint and size_hint != nbytes else "")
                        + ")",
                        metadata={"shard_id": shard_id, "file_index": file_idx, "files_in_shard": len(nodes), "current_path": rel, "action": "processed"},
                    )

        if index_entries and not stopped:
            progress.set_current(f"part-{shard_id:05d}.tar.zst", action="uploading", shard_id=shard_id)
            # Upload on this evidence slot; a nested uploader pool multiplied the
            # real concurrency beyond the four source work units.
            started = time.monotonic()
            part_uri = put_file(part_key, tmp_path, "application/zstd")
            upload_seconds = time.monotonic() - started
    except JobStopRequested:
        stopped = True
    except Exception as exc:
        emit(f"Shard {shard_id} failed: {exc}", level="error", metadata={"shard_id": shard_id, "error": str(exc)[:500]})
        raise
    finally:
        if forward is not None:
            forward.close()
        tmp_path.unlink(missing_ok=True)
        if owns_vd and vd is not None:
            try:
                vd.close()
            except Exception:
                pass

    if stopped:
        raise JobStopRequested()

    elapsed = max(time.monotonic() - t0, 0.001)
    emit(
        f"Shard {shard_id} complete — {len(index_entries):,} files, {bytes_written:,} bytes "
        f"in {elapsed:,.0f}s ({bytes_written / elapsed / 1048576:,.1f} MiB/s)"
        f"; source/spool={read_seconds:.1f}s, tar={pack_seconds:.1f}s, upload={upload_seconds:.1f}s, direct={directly_streamed}"
        + (f", {skip_count} read skips" if skip_count else ""),
        metadata={"shard_id": shard_id, "files": len(index_entries), "bytes": bytes_written, "seconds": round(elapsed, 1), "mib_per_s": round(bytes_written / elapsed / 1048576, 2), "source_read_seconds": round(read_seconds, 3), "tar_pack_seconds": round(pack_seconds, 3), "upload_seconds": round(upload_seconds, 3), "direct_files": directly_streamed},
    )
    progress.mark_shard_done(shard_id)
    return {
        "shard_id": shard_id,
        "part_key": part_key if part_uri else None,
        "part_uri": part_uri or None,
        "index_entries": index_entries,
        "files_extracted": len(index_entries),
        "bytes_extracted": bytes_written,
        "files_skipped": skip_count,
    }
