"""Read-only FUSE filesystem backed by the Client Evidence Agent (HTTP Range reads).

Run as a detached daemon by :mod:`app.services.client_evidence.mount`::

    python -m app.services.client_evidence.fusefs --share-id ce… --mountpoint /client-evidence/ce…

Design notes
------------
* The file tree is the *frozen* manifest captured when the examiner selected
  the folder.  Nothing can be added, renamed or written (``EROFS``).
* Bytes are fetched in aligned blocks (default 4 MiB) and kept in a bounded
  LRU cache.  Sequential access triggers background readahead, so pyewf/pytsk3
  walks and ZIP/UFDR parsing stream at close to LAN speed.
* Every block response must carry the ETag recorded in the manifest.  A file
  that changes on the workstation during processing returns ``EIO`` instead of
  silently mixing old and new evidence bytes.
* Transient network loss (Wi-Fi roam, sleep, cable swap) is retried for
  ``CLIENT_EVIDENCE_RETRY_SECONDS`` (default 10 min) across every known agent
  address before a read fails, so a short outage pauses extraction instead of
  failing a multi-hour job.
"""

from __future__ import annotations

import argparse
import errno
import logging
import os
import stat
import subprocess
import sys
import threading
import time
import zlib
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

from app.services.client_evidence import relay

log = logging.getLogger("client_evidence.fusefs")


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(lo, min(hi, value))


class EvidenceReadError(OSError):
    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(errno.EIO, message)
        self.fatal = fatal


class RemoteReader:
    """Cached, retrying reader over the agent: direct HTTP or the outbound relay.

    The cache unit is a small block (default 128 KiB). A miss fetches a *run* of
    consecutive blocks in one request: a single block for scattered reads (MFT
    records, registry cells, LNK files, event-log chunks) and a run that doubles
    up to ``CLIENT_EVIDENCE_MAX_RUN_MB`` (default 8 MiB) while a file is read
    sequentially. Small random reads therefore stay cheap on a slow uplink, and
    large sequential reads still move in big requests with read-ahead.

    The agent may send a block as ``zero`` (all zero bytes, nothing on the wire)
    or ``deflate`` (compressed). Bytes are decoded here and length-checked; the
    ETag check against the selection-time manifest is unchanged.
    """

    def __init__(
        self,
        *,
        share_id: str,
        token: str,
        base_urls: list[str],
        files: list[dict[str, Any]],
        block_size: int | None = None,
        cache_bytes: int | None = None,
        readahead_blocks: int | None = None,
        workers: int | None = None,
        retry_seconds: float | None = None,
        on_health=None,
        max_run_bytes: int | None = None,
        encoding: str | None = None,
        on_stats=None,
    ) -> None:
        if not base_urls:
            raise ValueError("at least one agent URL is required")
        self.share_id = share_id
        self._token = token
        self._urls = list(dict.fromkeys(u.rstrip("/") for u in base_urls))
        self.files = files
        self.block_size = block_size or _env_int("CLIENT_EVIDENCE_BLOCK_KB", 128, 16, 65536) * 1024
        run_bytes = max_run_bytes or _env_int("CLIENT_EVIDENCE_MAX_RUN_MB", 8, 1, 64) * 1024 * 1024
        self.max_run = max(1, run_bytes // self.block_size)
        self.cache_limit = cache_bytes or _env_int("CLIENT_EVIDENCE_CACHE_MB", 256, 16, 8192) * 1024 * 1024
        self.readahead = readahead_blocks if readahead_blocks is not None else _env_int(
            "CLIENT_EVIDENCE_READAHEAD_BLOCKS", self.max_run, 0, 4096
        )
        # Over the outbound connection bytes are the bottleneck: prefetching data that may
        # belong to other files costs more than the latency it hides. Off by default there.
        self.relay_readahead = _env_int("CLIENT_EVIDENCE_RELAY_READAHEAD", 0, 0, 1) == 1
        self.retry_seconds = (
            retry_seconds if retry_seconds is not None else float(_env_int("CLIENT_EVIDENCE_RETRY_SECONDS", 600, 5, 86400))
        )
        n_workers = workers or _env_int("CLIENT_EVIDENCE_PREFETCH_WORKERS", 4, 1, 32)
        # A large run over a slow home uplink can take tens of seconds.
        self.relay_timeout = float(_env_int("CLIENT_EVIDENCE_RELAY_TIMEOUT", 120, 10, 3600))
        mode = (encoding if encoding is not None else os.environ.get("CLIENT_EVIDENCE_WIRE_ENCODING", "auto")).strip().lower()
        if mode == "auto":
            # LAN: skipping empty blocks is free; compression could cost more CPU than it saves.
            # Outbound/home uplink: bytes are the bottleneck, so compress too.
            self._accept_direct, self._accept_relay = "zero", "zero,deflate"
        elif mode in ("", "none", "off"):
            self._accept_direct = self._accept_relay = ""
        else:
            self._accept_direct = self._accept_relay = mode
        self._on_health = on_health
        self._on_stats = on_stats
        self._lock = threading.Lock()
        self._cache: OrderedDict[tuple[int, int], bytes] = OrderedDict()
        self._cache_bytes = 0
        self._inflight: dict[tuple[int, int], Future] = {}
        self._seq: dict[int, tuple[int, int]] = {}
        self._prefetch = ThreadPoolExecutor(max_workers=n_workers, thread_name_prefix="ce-readahead")
        self._prefetch_pending = 0
        self._http = httpx.Client(
            timeout=httpx.Timeout(60.0, connect=5.0),
            limits=httpx.Limits(max_connections=n_workers + 16, max_keepalive_connections=n_workers + 16),
            headers={"User-Agent": "PolaronForensicServer/1.0 (client-evidence-fuse)"},
            follow_redirects=False,
            trust_env=False,
        )
        self.bytes_fetched = 0      # evidence bytes delivered (after decoding)
        self.wire_bytes = 0         # bytes that crossed the network
        self.zero_bytes = 0         # bytes sent as "all zero" markers
        self.requests = 0
        self.blocks_fetched = 0
        self.cache_hits = 0
        self._pending_stats = {"logical_bytes": 0, "wire_bytes": 0, "zero_bytes": 0, "requests": 0}
        self._last_stats_flush = time.monotonic()
        self._failed: str | None = None
        self._last_health = 0.0

    # -- public API -------------------------------------------------------

    def close(self) -> None:
        self._flush_stats(force=True)
        self._prefetch.shutdown(wait=False, cancel_futures=True)
        self._http.close()

    def read(self, index: int, offset: int, size: int) -> bytes:
        meta = self.files[index]
        fsize = int(meta["size"])
        if size <= 0 or offset >= fsize:
            return b""
        end = min(offset + size, fsize)
        bs = self.block_size
        first, last = offset // bs, (end - 1) // bs
        window = self._window(index, first, last)
        out = bytearray()
        for block in range(first, last + 1):
            data = self._block(index, block, max(window, last - block + 1))
            bstart = block * bs
            lo = max(offset, bstart) - bstart
            hi = min(end, bstart + len(data)) - bstart
            out += data[lo:hi]
        if window >= self.max_run:  # sustained streaming only, not one artifact in a segment
            self._schedule_readahead(index, last, fsize, window)
        return bytes(out)

    # -- internals --------------------------------------------------------

    def _window(self, index: int, first: int, last: int) -> int:
        """Blocks to fetch per miss: 1 for scattered access, doubling while sequential."""
        with self._lock:
            previous = self._seq.get(index)
            if previous is not None and previous[0] <= first <= previous[0] + 1:
                window = min(previous[1] * 2, self.max_run)
            else:
                window = 1
            self._seq[index] = (last, window)
            return window

    def _block(self, index: int, block: int, run: int = 1) -> bytes:
        key = (index, block)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                self.cache_hits += 1
                return cached
            fut = self._inflight.get(key)
            if fut is None:
                # Own a run starting here; stop at the file end or at a block someone already has.
                max_block = (int(self.files[index]["size"]) - 1) // self.block_size
                blocks = []
                for b in range(block, min(block + max(1, run), max_block + 1)):
                    k = (index, b)
                    if b != block and (k in self._cache or k in self._inflight):
                        break
                    blocks.append(b)
                futures = {b: Future() for b in blocks}
                for b, f in futures.items():
                    self._inflight[(index, b)] = f
                fut = None
        if fut is not None:
            return fut.result()
        try:
            data = self._fetch(index, blocks[0], len(blocks))
        except BaseException as exc:
            with self._lock:
                for b in blocks:
                    self._inflight.pop((index, b), None)
            for f in futures.values():
                f.set_exception(exc)
            raise
        bs = self.block_size
        with self._lock:
            for i, b in enumerate(blocks):
                chunk = data[i * bs:(i + 1) * bs]
                self._store((index, b), chunk)
                self._inflight.pop((index, b), None)
                futures[b].set_result(chunk)
        return futures[block].result()

    def _store(self, key: tuple[int, int], data: bytes) -> None:
        if key in self._cache:
            return
        self._cache[key] = data
        self._cache_bytes += len(data)
        while self._cache_bytes > self.cache_limit and len(self._cache) > 1:
            _, old = self._cache.popitem(last=False)
            self._cache_bytes -= len(old)

    def _schedule_readahead(self, index: int, block: int, fsize: int, window: int) -> None:
        if self.readahead <= 0:
            return
        if relay.is_relay_url(self._urls[0]) and not self.relay_readahead:
            return
        span = min(window, self.readahead)
        max_block = (fsize - 1) // self.block_size
        limit = min(max_block, block + span)
        with self._lock:
            # Keep `span` blocks ahead of the reader: skip what is already cached or
            # on its way and prefetch from the first missing block.
            nxt = block + 1
            while nxt <= limit and ((index, nxt) in self._cache or (index, nxt) in self._inflight):
                nxt += 1
            if nxt > limit:
                return
            if self._prefetch_pending >= 4:
                return
            self._prefetch_pending += 1
        self._prefetch.submit(self._readahead_one, index, nxt, span)

    def _readahead_one(self, index: int, block: int, span: int) -> None:
        try:
            self._block(index, block, span)
        except Exception:
            pass  # a demand read will retry and report the error
        finally:
            with self._lock:
                self._prefetch_pending = max(0, self._prefetch_pending - 1)

    def _health(self, state: str, detail: str = "", *, force: bool = False) -> None:
        self._flush_stats()
        if not self._on_health:
            return
        now = time.monotonic()
        if not force and now - self._last_health < 5.0:
            return
        self._last_health = now
        try:
            self._on_health({
                "state": state,
                "detail": detail,
                "agent_url": self._urls[0],
                "bytes_fetched": self.bytes_fetched,
                "wire_bytes": self.wire_bytes,
                "blocks_fetched": self.blocks_fetched,
                "cache_hits": self.cache_hits,
            })
        except Exception:
            pass

    def _count(self, logical: int, wire: int, zero: int) -> None:
        with self._lock:
            self.bytes_fetched += logical
            self.wire_bytes += wire
            self.zero_bytes += zero
            self.requests += 1
            p = self._pending_stats
            p["logical_bytes"] += logical
            p["wire_bytes"] += wire
            p["zero_bytes"] += zero
            p["requests"] += 1

    def _flush_stats(self, *, force: bool = False) -> None:
        if not self._on_stats:
            return
        with self._lock:
            if not force and time.monotonic() - self._last_stats_flush < 2.0:
                return
            pending = dict(self._pending_stats)
            if not any(pending.values()):
                return
            self._pending_stats = {k: 0 for k in pending}
            self._last_stats_flush = time.monotonic()
        try:
            self._on_stats(pending)
        except Exception:
            pass

    def _decode(self, body: bytes, encoding: str, expected_len: int) -> bytes:
        if encoding == "zero":
            if body:
                raise ValueError("zero block with a body")
            return bytes(expected_len)
        if encoding == "deflate":
            return zlib.decompress(body, -15)
        if encoding:
            raise ValueError(f"unknown wire encoding {encoding!r}")
        return body

    def _fetch(self, index: int, block: int, count: int = 1) -> bytes:
        if self._failed:
            raise EvidenceReadError(self._failed, fatal=True)
        meta = self.files[index]
        fsize = int(meta["size"])
        start = block * self.block_size
        stop = min(start + count * self.block_size, fsize) - 1
        expected_len = stop - start + 1
        expected_etag = f"{int(meta['size'])}-{int(meta['mtime_ms'])}"
        deadline = time.monotonic() + self.retry_seconds
        delay = 0.5
        last_error = ""
        while True:
            for url in list(self._urls):
                try:
                    status, headers, body = self._get(url, index, start, stop)
                except (httpx.HTTPError, relay.RelayError) as exc:
                    shown = "outbound connection" if relay.is_relay_url(url) else url
                    last_error = f"{shown}: {exc if isinstance(exc, relay.RelayError) else type(exc).__name__}"
                    continue
                if status in (401, 403, 404):
                    self._failed = (
                        f"Client evidence share {self.share_id} was revoked or expired on the workstation "
                        f"(HTTP {status}). Reconnect the evidence folder."
                    )
                    self._health("failed", self._failed, force=True)
                    raise EvidenceReadError(self._failed, fatal=True)
                if status == 409:
                    self._failed = (
                        f"{meta['path']} changed on the client workstation after it was selected. "
                        "Processing stopped to protect evidence integrity."
                    )
                    self._health("failed", self._failed, force=True)
                    raise EvidenceReadError(self._failed, fatal=True)
                if status not in (200, 206):
                    last_error = f"{url}: HTTP {status}"
                    continue
                etag = headers.get("etag", "").strip().strip('"')
                if etag and etag != expected_etag:
                    self._failed = f"{meta['path']} no longer matches the selected evidence (ETag {etag})."
                    self._health("failed", self._failed, force=True)
                    raise EvidenceReadError(self._failed, fatal=True)
                wire = len(body)
                encoding = (headers.get("encoding") or headers.get("x-polaron-encoding") or "").strip().lower()
                try:
                    data = self._decode(body, encoding, expected_len)
                except (zlib.error, ValueError) as exc:
                    last_error = f"{url}: undecodable {encoding or 'raw'} block ({exc})"
                    continue
                if status == 200 and not encoding:
                    data = data[start:stop + 1]
                if len(data) != expected_len:
                    last_error = f"{url}: short read {len(data)}/{expected_len}"
                    continue
                if url != self._urls[0]:
                    with self._lock:
                        self._urls.remove(url)
                        self._urls.insert(0, url)
                self.blocks_fetched += count
                self._count(expected_len, wire, expected_len if encoding == "zero" else 0)
                self._health("ok")
                return data
            if time.monotonic() >= deadline:
                msg = (
                    f"Client workstation unreachable for {int(self.retry_seconds)} s while reading "
                    f"{meta['path']} ({last_error}). Keep the computer awake and on the network, then Resume."
                )
                self._health("waiting", msg, force=True)
                raise EvidenceReadError(msg)
            self._health("waiting", f"Waiting for client workstation: {last_error}")
            time.sleep(delay)
            delay = min(delay * 2, 15.0)

    def _get(self, url: str, index: int, start: int, stop: int) -> tuple[int, dict[str, str], bytes]:
        """One range request over the chosen transport: direct HTTP or the outbound relay."""
        if relay.is_relay_url(url):
            reply = relay.get_range(self.share_id, index, start, stop, timeout=self.relay_timeout,
                                    accept=self._accept_relay)
            return reply.status, reply.headers, reply.body
        headers = {"Authorization": f"Bearer {self._token}", "Range": f"bytes={start}-{stop}"}
        if self._accept_direct:
            headers["X-Polaron-Accept-Encoding"] = self._accept_direct
        resp = self._http.get(f"{url}/s/{self.share_id}/f/{index}", headers=headers)
        return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content


def build_tree(files: list[dict[str, Any]], dirs: list[str] | None = None) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Return ``(file_index_by_path, children_by_dir)`` with POSIX paths rooted at ``/``."""
    file_index: dict[str, int] = {}
    children: dict[str, set[str]] = {"/": set()}

    def ensure_dir(path: str) -> None:
        # Register every missing ancestor first so each directory is linked
        # into its parent's listing (a/b must make "a" visible under "/").
        missing: list[str] = []
        while path not in children:
            missing.append(path)
            path = path.rpartition("/")[0] or "/"
        for directory in reversed(missing):
            parent, _, name = directory.rpartition("/")
            children[parent or "/"].add(name)
            children[directory] = set()

    for d in dirs or []:
        rel = str(d).replace("\\", "/").strip("/")
        if rel:
            ensure_dir("/" + rel)
    for idx, item in enumerate(files):
        rel = str(item["path"]).replace("\\", "/").strip("/")
        full = "/" + rel
        parent, _, name = full.rpartition("/")
        parent = parent or "/"
        ensure_dir(parent)
        children[parent].add(name)
        file_index[full] = idx
    return file_index, {k: sorted(v) for k, v in children.items()}


def _make_operations():
    from fuse import FuseOSError, Operations

    class ClientEvidenceFS(Operations):
        def __init__(self, reader: RemoteReader, manifest: dict[str, Any]):
            self.reader = reader
            self.files = manifest["files"]
            self.file_index, self.children = build_tree(self.files, manifest.get("dirs") or [])
            self.mount_time = time.time()
            self.total_bytes = sum(int(f["size"]) for f in self.files)

        def getattr(self, path, fh=None):
            idx = self.file_index.get(path)
            if idx is not None:
                meta = self.files[idx]
                mtime = int(meta["mtime_ms"]) / 1000.0
                size = int(meta["size"])
                return {
                    "st_mode": stat.S_IFREG | 0o444,
                    "st_nlink": 1,
                    "st_size": size,
                    "st_blocks": (size + 511) // 512,
                    "st_mtime": mtime,
                    "st_atime": mtime,
                    "st_ctime": mtime,
                    "st_uid": 0,
                    "st_gid": 0,
                }
            if path in self.children:
                return {
                    "st_mode": stat.S_IFDIR | 0o555,
                    "st_nlink": 2,
                    "st_mtime": self.mount_time,
                    "st_atime": self.mount_time,
                    "st_ctime": self.mount_time,
                    "st_uid": 0,
                    "st_gid": 0,
                }
            raise FuseOSError(errno.ENOENT)

        def readdir(self, path, fh):
            if path not in self.children:
                raise FuseOSError(errno.ENOTDIR if path in self.file_index else errno.ENOENT)
            return [".", "..", *self.children[path]]

        def access(self, path, amode):
            if amode & os.W_OK:
                raise FuseOSError(errno.EROFS)
            if path not in self.file_index and path not in self.children:
                raise FuseOSError(errno.ENOENT)
            return 0

        def open(self, path, flags):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC | os.O_CREAT):
                raise FuseOSError(errno.EROFS)
            idx = self.file_index.get(path)
            if idx is None:
                raise FuseOSError(errno.ENOENT)
            return idx

        def read(self, path, size, offset, fh):
            try:
                return self.reader.read(int(fh), int(offset), int(size))
            except EvidenceReadError as exc:
                log.error("%s", exc.strerror)
                raise FuseOSError(errno.EIO)
            except Exception:
                log.exception("unexpected read failure %s @%s", path, offset)
                raise FuseOSError(errno.EIO)

        def statfs(self, path):
            blocks = max(1, (self.total_bytes + 4095) // 4096)
            return {
                "f_bsize": 4096,
                "f_frsize": 4096,
                "f_blocks": blocks,
                "f_bfree": 0,
                "f_bavail": 0,
                "f_files": len(self.files),
                "f_ffree": 0,
                "f_namemax": 255,
            }

    return ClientEvidenceFS


def _watch_revocation(share_id: str, mountpoint: str, stop: threading.Event) -> None:
    """Unmount when the share disappears from the registry (job deleted / source released)."""
    from app.services.client_evidence import registry

    misses = 0
    while not stop.wait(15.0):
        try:
            present = share_id in registry.all_share_ids()
        except Exception:
            continue  # Redis unavailable: keep serving
        misses = 0 if present else misses + 1
        if misses >= 2:
            log.warning("share %s released — unmounting %s", share_id, mountpoint)
            subprocess.run(["umount", "-l", mountpoint], check=False, capture_output=True)
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Polaron client evidence FUSE daemon")
    parser.add_argument("--share-id", required=True)
    parser.add_argument("--mountpoint", required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from app.services.client_evidence import agent_client, registry
    from app.services.client_evidence import ClientEvidenceError

    record = registry.load_share(args.share_id)
    if record is None:
        print(f"share {args.share_id} is not registered", file=sys.stderr)
        return 2
    try:
        url, manifest = agent_client.choose_reachable(
            record.candidates(),
            share_id=record.share_id,
            token=record.token,
            expected_digest=record.manifest_sha256 or None,
        )
    except ClientEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        registry.write_health(record.share_id, {"state": "failed", "detail": str(exc)})
        return 3

    def on_health(payload: dict[str, Any]) -> None:
        registry.write_health(record.share_id, payload)

    urls = [url, *[u for u in record.candidates() if u != url]]
    def on_stats(deltas: dict[str, int]) -> None:
        registry.add_transfer_stats(record.share_id, deltas)

    reader = RemoteReader(
        share_id=record.share_id,
        token=record.token,
        base_urls=urls,
        files=manifest["files"],
        on_health=on_health,
        on_stats=on_stats,
    )
    try:
        from fuse import FUSE
    except (ImportError, OSError, EnvironmentError) as exc:
        print(f"libfuse is not available in this container: {exc}", file=sys.stderr)
        return 4

    fs_cls = _make_operations()
    fs = fs_cls(reader, manifest)
    Path(args.mountpoint).mkdir(parents=True, exist_ok=True)
    registry.write_health(record.share_id, {"state": "ok", "detail": "mounted", "agent_url": url})
    stop = threading.Event()
    threading.Thread(
        target=_watch_revocation, args=(record.share_id, args.mountpoint, stop), daemon=True
    ).start()
    log.info("mounting %s (%d files) from %s at %s", record.share_id, len(manifest["files"]), url, args.mountpoint)
    try:
        FUSE(
            fs,
            args.mountpoint,
            foreground=True,
            nothreads=False,
            ro=True,
            allow_other=True,
            kernel_cache=True,
            attr_timeout=86400,
            entry_timeout=86400,
            negative_timeout=30,
            max_read=131072,
            fsname=f"polaron-client:{record.share_id}",
            subtype="polaron",
        )
    finally:
        stop.set()
        reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
