"""Checks that declare their own long timeout, and caps for them (V1.9.3).

Why this exists
---------------
OpenVAS decides a check's time limit in pluginlaunch.c ``plugin_timeout()``:
it reads the NVT preference ``timeout`` (id 0, set by ``script_timeout()`` in
the NASL description block) FIRST, and only when that is 0/absent falls back to
``plugins_timeout`` (320 s) or ``scanner_plugins_timeout``. A check that
declares ``script_timeout(3600)`` therefore runs for an hour, and one that
declares ``script_timeout(-1)`` is never killed. Those are the checks that hold
a host at 98-99 % long after everything else finished (field job 3c4f45e0:
192.168.1.9 at 98 % for 30+ min while the 5 static SSL caps were in place).

A fixed OID list cannot find them, because they vary with the feed. This
module reads the feed itself: every ``.nasl`` file on the read-only plugins
volume, its ``script_oid`` and its ``script_timeout``. Checks whose own limit
is above ``SCAN_NVT_MAX_SEC`` (default 900 s) or unbounded are capped to it on
the Aetheris profile config clone, through the same
``<oid>:0:entry:timeout`` preference the static/learned caps already use.

The index is built in a background thread (a full feed is ~1-2 min of disk
reads), cached as JSON keyed by the feed version, and never blocks a scan
start: until it exists, scans run with the static/learned caps only.
It never raises an NVT's limit: only checks whose declared value is above the
cap (or unbounded) are written.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

INDEX_VERSION = 1
_READ_BYTES = 64 * 1024  # the description block is at the top of every NASL file

_OID_RE = re.compile(rb'script_oid\s*\(\s*"([0-9][0-9.]{6,80})"\s*\)')
_TIMEOUT_RE = re.compile(rb"script_timeout\s*\(\s*([^;]{1,40}?)\s*\)\s*;")
_NAME_RE = re.compile(rb'script_name\s*\(\s*"([^"]{1,200})"')
_FAMILY_RE = re.compile(rb'script_family\s*\(\s*"([^"]{1,100})"')
_PLUGIN_SET_RE = re.compile(r'PLUGIN_SET\s*=\s*"([^"]+)"')


def plugins_dir() -> Path:
    return Path(os.environ.get("OPENVAS_PLUGINS_DIR") or "/var/lib/openvas/plugins")


def index_file() -> Path:
    return Path(os.environ.get("NVT_TIMEOUT_INDEX_FILE") or "/app/logs/nvt_timeout_index.json")


def _eval_timeout(expr: bytes) -> int | None:
    """Integer value of a script_timeout() argument, or None if not a literal.

    Accepts literals and simple arithmetic (``30*60``, ``-1``). A variable or
    function call returns None and the check is left alone (never guessed).
    """
    try:
        tree = ast.parse(expr.decode("ascii", "strict").strip(), mode="eval")
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return None

    def ev(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return int(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            val = ev(node.operand)
            return -val if isinstance(node.op, ast.USub) else val
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add, ast.Sub)):
            left, right = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Mult):
                return left * right
            return left + right if isinstance(node.op, ast.Add) else left - right
        raise ValueError("not a literal")

    try:
        value = ev(tree)
    except (ValueError, RecursionError):
        return None
    return value if -1 <= value <= 7 * 86400 else None


def parse_nasl(data: bytes) -> dict[str, Any] | None:
    """OID, declared timeout, name and family of one NASL file, or None.

    Only files that call script_timeout() with a usable literal are returned.
    """
    if b"script_timeout" not in data:
        return None
    oid = _OID_RE.search(data)
    tmo = _TIMEOUT_RE.search(data)
    if not oid or not tmo:
        return None
    seconds = _eval_timeout(tmo.group(1))
    if seconds is None:
        return None
    name = _NAME_RE.search(data)
    family = _FAMILY_RE.search(data)
    return {
        "oid": oid.group(1).decode("ascii", "replace"),
        "timeout": seconds,
        "name": name.group(1).decode("utf-8", "replace") if name else "",
        "family": family.group(1).decode("utf-8", "replace") if family else "",
    }


def feed_signature(root: Path | None = None) -> str | None:
    """Feed version of the plugins directory (PLUGIN_SET + file mtime), or None."""
    base = root or plugins_dir()
    info = base / "plugin_feed_info.inc"
    try:
        text = info.read_text(errors="replace")
        stamp = int(info.stat().st_mtime)
    except OSError:
        try:
            return f"dir-mtime-{int(base.stat().st_mtime)}" if base.is_dir() else None
        except OSError:
            return None
    match = _PLUGIN_SET_RE.search(text)
    return f"{match.group(1) if match else 'unknown'}@{stamp}"


def build_index(root: Path | None = None, *, yield_every: int = 500) -> dict[str, Any]:
    """Walk the plugins directory and record every check with its own timeout."""
    base = root or plugins_dir()
    started = time.monotonic()
    nvts: dict[str, list[Any]] = {}
    scanned = 0
    for dirpath, _dirs, files in os.walk(base):
        for fname in files:
            if not fname.endswith(".nasl"):
                continue
            scanned += 1
            if yield_every and scanned % yield_every == 0:
                time.sleep(0.001)  # stay out of the scanner's way
            try:
                with open(os.path.join(dirpath, fname), "rb") as fh:
                    data = fh.read(_READ_BYTES)
            except OSError:
                continue
            row = parse_nasl(data)
            if row and row["timeout"] != 0:
                nvts[row["oid"]] = [row["timeout"], row["name"][:120], row["family"][:80]]
    return {
        "version": INDEX_VERSION,
        "signature": feed_signature(base),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build_sec": round(time.monotonic() - started, 1),
        "files_scanned": scanned,
        "nvts": nvts,
    }


class TimeoutIndex:
    """Cached, feed-versioned index; rebuilt in the background when the feed changes."""

    def __init__(self, root: Path | None = None, cache: Path | None = None) -> None:
        self.root = root
        self.cache = cache
        self._lock = threading.Lock()
        self._data: dict[str, Any] | None = None
        self._building = False
        self._checked_at: float | None = None
        self._last_sig: str | None = None
        self._status = "not loaded"

    def _root(self) -> Path:
        return self.root or plugins_dir()

    def _cache(self) -> Path:
        return self.cache or index_file()

    def status(self) -> str:
        return self._status

    def invalidate(self) -> None:
        """Re-check the feed version on the next get() (no 60 s reuse)."""
        with self._lock:
            self._checked_at = None

    def _load_cache(self, sig: str) -> dict[str, Any] | None:
        try:
            data = json.loads(self._cache().read_text())
        except (OSError, ValueError):
            return None
        if data.get("version") == INDEX_VERSION and data.get("signature") == sig and isinstance(data.get("nvts"), dict):
            return data
        return None

    def _build(self, sig: str) -> None:
        try:
            data = build_index(self._root())
            try:
                path = self._cache()
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data))
                tmp.replace(path)
            except OSError:
                log.warning("Could not save the NVT timeout index to %s", self._cache(), exc_info=True)
            with self._lock:
                self._data = data
                self._status = (f"built for feed {data.get('signature')}: {data['files_scanned']} checks read, "
                                f"{len(data['nvts'])} declare their own timeout ({data['build_sec']} s)")
            log.info("NVT timeout index %s", self._status)
        except Exception as exc:  # pragma: no cover - defensive
            with self._lock:
                self._status = f"build failed: {exc.__class__.__name__}: {exc}"
            log.warning("NVT timeout index build failed", exc_info=True)
        finally:
            with self._lock:
                self._building = False

    def get(self, *, wait: float = 0.0) -> dict[str, Any] | None:
        """The index for the current feed, or None while it is being built.

        Never blocks unless ``wait`` > 0 (tests / diagnostics).
        """
        now = time.monotonic()
        with self._lock:
            fresh = (self._data is not None and self._checked_at is not None
                     and now - self._checked_at < 60)
            if fresh:
                return self._data
        sig = feed_signature(self._root())
        with self._lock:
            self._checked_at = now
            if sig is None:
                self._data = None
                self._status = (f"unavailable: plugins not readable at {self._root()} "
                                "(mount gvm_vt_data read-only into scanner-agent)")
                return None
            if self._data is not None and self._data.get("signature") == sig:
                return self._data
        cached = self._load_cache(sig)
        start = False
        with self._lock:
            if cached is not None:
                self._data = cached
                self._status = (f"loaded for feed {sig}: {len(cached['nvts'])} checks declare their own timeout")
                return cached
            if not self._building:
                self._building = True
                start = True
                self._status = f"building for feed {sig} (first scan after a feed update uses static caps only)"
            stale = self._data
        if start:
            thread = threading.Thread(target=self._build, args=(sig,), name="aetheris-nvt-index", daemon=True)
            thread.start()
            if wait > 0:
                thread.join(wait)
                with self._lock:
                    if self._data is not None and self._data.get("signature") == sig:
                        return self._data
        return stale


_INDEX: TimeoutIndex | None = None
_INDEX_LOCK = threading.Lock()


def timeout_index() -> TimeoutIndex:
    global _INDEX
    with _INDEX_LOCK:
        if _INDEX is None:
            _INDEX = TimeoutIndex()
        return _INDEX


def long_timeout_caps(max_sec: int, index: dict[str, Any] | None = None) -> dict[str, int]:
    """{oid: max_sec} for checks whose own timeout is above max_sec or unbounded.

    Port scanners, service detection and web crawlers are never capped: every
    later check depends on what they find.
    """
    from agent.scan_performance import _is_cappable

    if max_sec <= 0:
        return {}
    data = index if index is not None else timeout_index().get()
    if not data:
        return {}
    caps: dict[str, int] = {}
    for oid, row in (data.get("nvts") or {}).items():
        try:
            declared = int(row[0])
            name = str(row[1] if len(row) > 1 else "")
        except (TypeError, ValueError, IndexError):
            continue
        if (declared < 0 or declared > max_sec) and _is_cappable(oid, name):
            caps[oid] = int(max_sec)
    return caps


def describe_long_checks(index: dict[str, Any] | None, max_sec: int, limit: int = 10) -> list[str]:
    """Human-readable sample of the longest declared timeouts (for the start log)."""
    rows = []
    for oid, row in ((index or {}).get("nvts") or {}).items():
        try:
            declared = int(row[0])
        except (TypeError, ValueError, IndexError):
            continue
        if declared < 0 or declared > max_sec:
            rows.append((10**9 if declared < 0 else declared, oid, str(row[1] if len(row) > 1 else "")))
    rows.sort(reverse=True)
    return [f"{name or oid} ({'no limit' if secs == 10**9 else f'{secs}s'})" for secs, oid, name in rows[:limit]]
