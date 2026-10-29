"""Cached tar shard reader — streams zstd tar parts without loading whole archives."""

from __future__ import annotations

import io
import logging
import tarfile
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator

import zstandard as zstd

from app.services.storage import open_object_stream

log = logging.getLogger("tar_cache")

_CACHE_MAX = 8
_MAX_CACHED_FILE_BYTES = 10_000_000
_lock = threading.Lock()
_cache: OrderedDict[str, dict[str, bytes | None]] = OrderedDict()


def _decompress_zstd(raw: bytes) -> bytes | None:
    """Decompress single-frame zstd blobs (e.g. index.jsonl.zst)."""
    if not raw:
        return None
    try:
        return zstd.ZstdDecompressor().decompress(raw)
    except zstd.ZstdError:
        return None


def _cache_file(part_uri: str, path: str, content: bytes | None) -> None:
    if content is None or len(content) > _MAX_CACHED_FILE_BYTES:
        return
    with _lock:
        bucket = _cache.setdefault(part_uri, {})
        bucket[path] = content
        _cache.move_to_end(part_uri)
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


def _cached_file(part_uri: str, path: str) -> bytes | None:
    with _lock:
        bucket = _cache.get(part_uri)
        if bucket is not None and path in bucket:
            _cache.move_to_end(part_uri)
            return bucket[path]
    return None


def iter_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
    max_bytes_by_path: dict[str, int | None] | None = None,
    verify_sha256_by_path: dict[str, str | None] | None = None,
    verify_size_by_path: dict[str, int] | None = None,
    repeat_by_path: dict[str, int] | None = None,
    on_progress=None,
    on_detail=None,
) -> Iterator[tuple[str, bytes | None]]:
    """Yield ``(path, content)`` for wanted members via streamed MinIO/zstd/tar.

    Never buffers the compressed shard in RAM (parts can be 5–13+ GB).
    ``max_bytes_by_path`` applies a per-file cap in one pass so callers do not
    decompress the same shard once for every read budget. ``on_progress`` is
    ``(members_scanned, files_yielded)`` and lets a long scan stay alive.
    ``on_detail`` receives bytes read, the current member, and the wanted-file
    fraction about once a second, including while a large member is draining.
    Optional hashes/sizes validate each entire source while retaining just the
    requested prefix: derived forensic header records must never bypass evidence
    integrity merely because they only need the first 4 KiB.
    """
    wanted = {p.replace("\\", "/") for p in paths}
    if not wanted:
        return

    # Tiny cache hits are complete bytes. Apply the per-path budget and verify
    # the entire cached source when the caller requests forensic provenance.
    # A path extracted more than once is read from the archive in member order,
    # not served twice from the first cached copy.
    remaining = {
        p: max(1, int((repeat_by_path or {}).get(p, 1)))
        for p in wanted
    }

    def _consume(name: str) -> None:
        left = int(remaining.get(name, 0))
        if left <= 1:
            remaining.pop(name, None)
        else:
            remaining[name] = left - 1

    for p in list(remaining):
        if remaining[p] != 1:
            continue
        cached = _cached_file(part_uri, p)
        if cached is None:
            continue
        expected_size = (verify_size_by_path or {}).get(p)
        expected_hash = (verify_sha256_by_path or {}).get(p)
        if expected_size is not None and len(cached) != int(expected_size):
            log.error("Cached extracted evidence size mismatch part=%s path=%s", part_uri, p)
            _consume(p)
            yield p, None
            continue
        if expected_hash:
            import hashlib
            if hashlib.sha256(cached).hexdigest().lower() != str(expected_hash).lower():
                log.error("Cached extracted evidence SHA-256 mismatch part=%s path=%s", part_uri, p)
                _consume(p)
                yield p, None
                continue
        cap = (max_bytes_by_path or {}).get(p, max_bytes)
        _consume(p)
        yield p, cached[:cap] if cap is not None else cached
    if not remaining:
        return

    stream = open_object_stream(part_uri)
    if stream is None:
        for name, left in list(remaining.items()):
            for _ in range(int(left)):
                yield name, None
        return

    scanned = 0
    yielded = 0
    bytes_seen = 0
    wanted_total = len(wanted)
    last_progress = time.monotonic()
    # 8 MiB matches the extractor's write size. The tar/zstd defaults (8–128 KiB)
    # spend the scan in the Python wrapper, which is what makes a shard of small
    # files look frozen for tens of minutes.
    chunk = 8 * 1024 * 1024

    def _emit(*, force: bool = False, current: str | None = None, current_read: int = 0, current_size: int = 0) -> None:
        nonlocal last_progress
        if on_progress is None and on_detail is None:
            return
        now = time.monotonic()
        if not force and (now - last_progress) < 1.0:
            return
        last_progress = now
        if on_progress is not None:
            try:
                on_progress(scanned, yielded)
            except Exception:
                log.debug("Shard scan progress callback failed", exc_info=True)
        if on_detail is not None:
            try:
                on_detail({
                    "members_scanned": scanned,
                    "files_yielded": yielded,
                    "files_wanted": wanted_total,
                    "bytes_seen": bytes_seen,
                    "current_path": current or "",
                    "current_read": int(current_read or 0),
                    "current_size": int(current_size or 0),
                })
            except Exception:
                log.debug("Shard scan detail callback failed", exc_info=True)

    def _drain(handle, nbytes: int, *, current: str) -> None:
        nonlocal bytes_seen
        left = int(nbytes or 0)
        size = left
        while left > 0:
            block = handle.read(min(left, chunk))
            if not block:
                break
            left -= len(block)
            bytes_seen += len(block)
            _emit(current=current, current_read=size - left, current_size=size)

    try:
        dctx = zstd.ZstdDecompressor()
        try:
            reader = dctx.stream_reader(stream, read_size=chunk)
        except TypeError:
            reader = dctx.stream_reader(stream)
        with reader as zreader:
            with tarfile.open(fileobj=zreader, mode="r|", bufsize=chunk) as tar:
                for member in tar:
                    if not remaining:
                        break
                    scanned += 1
                    if not member.isfile():
                        _emit(current=getattr(member, "name", "") or "")
                        continue
                    norm = member.name.replace("\\", "/")
                    member_size = int(member.size or 0)
                    # Consume skipped members in large reads. Leaving them for
                    # tarfile's default skip uses a tiny buffer and reports nothing
                    # until the next header, which is the frozen "streaming N files" card.
                    if norm not in remaining:
                        handle = tar.extractfile(member)
                        if handle is not None and member_size > 0:
                            _drain(handle, member_size, current=norm)
                        else:
                            _emit(current=norm)
                        continue
                    f = tar.extractfile(member)
                    if not f:
                        _consume(norm)
                        yielded += 1
                        _emit(force=True, current=norm)
                        yield norm, None
                        continue
                    cap = max_bytes
                    if max_bytes_by_path is not None:
                        cap = max_bytes_by_path.get(norm, max_bytes)
                    expected_hash = (verify_sha256_by_path or {}).get(norm)
                    expected_size = (verify_size_by_path or {}).get(norm)
                    if expected_hash or expected_size is not None:
                        import hashlib
                        digest = hashlib.sha256() if expected_hash else None
                        prefix = bytearray()
                        read_size = 0
                        while True:
                            block = f.read(chunk)
                            if not block:
                                break
                            read_size += len(block)
                            bytes_seen += len(block)
                            if digest is not None:
                                digest.update(block)
                            if cap is None:
                                prefix.extend(block)
                            elif len(prefix) < cap:
                                prefix.extend(block[: cap - len(prefix)])
                            _emit(current=norm, current_read=read_size, current_size=member_size)
                        valid_size = expected_size is None or read_size == int(expected_size)
                        valid_hash = not expected_hash or digest.hexdigest().lower() == str(expected_hash).lower()
                        if not valid_size or not valid_hash:
                            log.error("Extracted evidence failed size/SHA-256 check part=%s path=%s size_ok=%s hash_ok=%s",
                                      part_uri, norm, valid_size, valid_hash)
                            content = None
                        else:
                            content = bytes(prefix)
                    elif cap is None and member_size > chunk:
                        buf = bytearray()
                        while True:
                            block = f.read(chunk)
                            if not block:
                                break
                            buf.extend(block)
                            bytes_seen += len(block)
                            _emit(current=norm, current_read=len(buf), current_size=member_size)
                        content = bytes(buf)
                    else:
                        content = f.read(cap) if cap is not None else f.read()
                        got = len(content or b"")
                        bytes_seen += got
                        if cap is not None and member_size > got:
                            _drain(f, member_size - got, current=norm)
                        else:
                            _emit(current=norm, current_read=got, current_size=member_size)
                    if cap is None and content is not None and remaining.get(norm) == 1:
                        _cache_file(part_uri, norm, content)
                    _consume(norm)
                    yielded += 1
                    _emit(force=True, current=norm, current_read=member_size, current_size=member_size)
                    yield norm, content
        _emit(force=True)
    except Exception as exc:
        # A stage cancel is raised on the main thread from SIGTERM. Do not treat
        # it as a short read and keep parsing the rest of the shard.
        if type(exc).__name__ == "StageWaiting":
            raise
        log.warning("Streamed tar read failed part=%s: %s", part_uri, exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass

    for name, left in list(remaining.items()):
        for _ in range(int(left)):
            yield name, None


def iter_spilled_files_from_part(part_uri: str, paths: set[str], *, directory: str | None = None):
    """Stream wanted members to temp files in one shard pass.

    Callers review one file and delete it before the next member is read, so a
    shard is decompressed once instead of once per picture.
    """
    import os
    import tempfile

    wanted = {p.replace("\\", "/") for p in paths}
    if not wanted:
        return
    stream = open_object_stream(part_uri)
    if stream is None:
        return
    try:
        dctx = zstd.ZstdDecompressor()
        try:
            reader = dctx.stream_reader(stream, read_size=8 * 1024 * 1024)
        except TypeError:
            reader = dctx.stream_reader(stream)
        with reader as zreader:
            with tarfile.open(fileobj=zreader, mode="r|", bufsize=8 * 1024 * 1024) as tar:
                for member in tar:
                    if not wanted:
                        break
                    if not member.isfile():
                        continue
                    norm = member.name.replace("\\", "/")
                    if norm not in wanted:
                        continue
                    handle = tar.extractfile(member)
                    if handle is None:
                        wanted.discard(norm)
                        yield norm, None
                        continue
                    suffix = os.path.splitext(norm)[1][:16]
                    tmp = tempfile.NamedTemporaryFile(
                        prefix="aetheris-media-",
                        suffix=suffix,
                        dir=directory or "/tmp",
                        delete=False,
                    )
                    try:
                        while True:
                            chunk = handle.read(1024 * 1024)
                            if not chunk:
                                break
                            tmp.write(chunk)
                        tmp.flush()
                    except Exception:
                        tmp.close()
                        os.unlink(tmp.name)
                        raise
                    tmp.close()
                    wanted.discard(norm)
                    yield norm, tmp.name
    except Exception as exc:
        if type(exc).__name__ == "StageWaiting":
            raise
        log.warning("Streamed tar spill failed part=%s: %s", part_uri, exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def read_file_from_part(part_uri: str, path: str, *, max_bytes: int | None = None) -> bytes | None:
    """Read a single file from a tar shard (streaming — low memory)."""
    for _norm, content in iter_files_from_part(part_uri, {path}, max_bytes=max_bytes):
        return content
    return None


def read_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
) -> dict[str, bytes | None]:
    """Read many paths from one shard in a single streaming pass.

    Prefer :func:`iter_files_from_part` when callers can process members
    incrementally — this helper still materializes the full result dict.
    """
    wanted = {p.replace("\\", "/") for p in paths}
    found: dict[str, bytes | None] = {p: None for p in wanted}
    for norm, content in iter_files_from_part(part_uri, wanted, max_bytes=max_bytes):
        found[norm] = content
    return found


def clear_tar_cache() -> None:
    with _lock:
        _cache.clear()
