"""Read-only virtual disk access from registered host segment paths (no local image copy)."""

from __future__ import annotations

import json
import logging
import os
import re
import struct
import threading
import time
import zipfile
import zlib
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall

log = logging.getLogger("virtual_disk")

MOBILE_FOLDER_FORMATS = frozenset({"pas", "ufd", "ufdx", "zip", "mobile"})
PORTABLE_ZIP_SUFFIXES = frozenset({".zip", ".pas", ".ufd"})

SEGMENT_NAME_RE = re.compile(r"\.(?:e(?:\d{2}|(?!xe|wf)[a-z]{2})|\d{3})$", re.I)


def ewf_segment_number(name: str) -> int | None:
    """EnCase segment number. E01–E99 are 1–99. EAA–EZZ continue at 100.

    A 1TB image often uses EAA–EAM after E99. Leaving those out makes pyewf
    report a missing segment near the end of the disk.
    """
    suffix = Path(name).suffix.lower()
    if len(suffix) != 4 or not suffix.startswith(".e"):
        return None
    tail = suffix[2:]
    if tail.isdigit():
        number = int(tail)
        return number or None
    if tail.isalpha() and tail not in {"xe", "wf", "rr", "ml", "ps"}:
        return 100 + (ord(tail[0]) - ord("a")) * 26 + (ord(tail[1]) - ord("a"))
    return None

ProgressCb = Callable[[str, dict[str, Any] | None], None]

_pyewf = None
_pytsk3 = None
try:
    import pyewf  # type: ignore

    _pyewf = pyewf
except ImportError:
    pass
try:
    import pytsk3  # type: ignore

    _pytsk3 = pytsk3
except ImportError:
    pass


@dataclass
class VirtualDisk:
    job_id: str
    mode: str  # ewf | raw | folder
    segment_paths: list[str] = field(default_factory=list)
    segment_hashes: list[str] = field(default_factory=list)
    base_name: str = ""
    format: str = ""
    root_folder: str | None = None
    members: list["VirtualDisk"] = field(default_factory=list)
    _img_info: object | None = field(default=None, repr=False)
    _fs_info: object | None = field(default=None, repr=False)
    # Reuse ZipFile handles — reopening a 130k-entry UFED dump for every member is ~100× slower.
    _zip_handles: dict[str, zipfile.ZipFile] = field(default_factory=dict, repr=False)
    _zip_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _zip_resolve_cache: dict[str, tuple[str, str]] = field(default_factory=dict, repr=False)
    _sealed_roots: dict[str, Path] = field(default_factory=dict, repr=False)

    def open_zip(self, archive: Path) -> zipfile.ZipFile:
        key = str(archive.resolve()) if archive.exists() else str(archive)
        with self._zip_lock:
            zf = self._zip_handles.get(key)
            if zf is None:
                zf = zipfile.ZipFile(archive, "r", allowZip64=True)
                self._zip_handles[key] = zf
            return zf

    def sealed_root(self, name: str) -> Path | None:
        """Resolve ORIGINAL_PATH for a metadata ZIP once, then reuse it per file."""
        if not name:
            return None
        hit = self._sealed_roots.get(name)
        if hit is not None:
            return hit
        with self._zip_lock:
            hit = self._sealed_roots.get(name)
            if hit is not None:
                return hit
            for seg in self.segment_paths:
                try:
                    archive = _resolve_evidence_path(seg)
                except Exception:
                    archive = Path(seg)
                if not is_portable_zip_archive(archive):
                    continue
                for sealed in _package_original_dirs(archive):
                    self._sealed_roots.setdefault(sealed.name, sealed)
            return self._sealed_roots.get(name)

    def close(self) -> None:
        for member in list(self.members):
            try:
                member.close()
            except Exception:
                pass
        with self._zip_lock:
            for zf in self._zip_handles.values():
                try:
                    zf.close()
                except Exception:
                    pass
            self._zip_handles.clear()
            self._zip_resolve_cache.clear()
            self._sealed_roots.clear()
        img = self._img_info
        if img is not None and hasattr(img, "close"):
            try:
                img.close()  # type: ignore[union-attr]
            except Exception:
                pass
            self._img_info = None
        self._fs_info = None


def forensic_libs_available() -> dict[str, bool]:
    return {"pyewf": _pyewf is not None, "pytsk3": _pytsk3 is not None}


def _emit(on_progress: ProgressCb | None, message: str, metadata: dict[str, Any] | None = None) -> None:
    if on_progress:
        try:
            on_progress(message, metadata)
        except Exception:
            log.debug("progress callback failed", exc_info=True)



if _pytsk3 is not None:

    class EwfImgInfo(_pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            self._block_cache: OrderedDict = OrderedDict()
            super().__init__(url="", type=_pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            callback = getattr(self, "_diagnostic_emit", None)
            if callback is not None:
                try:
                    now = time.monotonic()
                    if now >= getattr(self, "_next_read_diagnostic_at", 0.0):
                        period = max(5., float(os.environ.get("EXTRACT_TSK_EWF_READ_TRACE_SEC", "20")))
                        self._next_read_diagnostic_at = now + period
                        callback("EWF/TSK source read - waiting on image bytes", {
                            "action": "ewf_read_enter",
                            "reader_phase": getattr(self, "_diagnostic_state", {}).get("reader_phase", "root_open"),
                            "last_source_read_offset": int(offset),
                            "last_source_read_size": int(size),
                        })
                except Exception:
                    # A diagnostic failure must never interrupt evidence I/O.
                    log.debug("EWF read diagnostic failed", exc_info=True)
            return cached_image_read(self._ewf_handle, self._block_cache, int(offset), int(size))

        def get_size(self):
            return self._ewf_handle.get_media_size()

        def set_read_diagnostic(self, emit: ProgressCb, state: dict) -> None:
            # A read callback is entered before a potentially blocked libewf
            # seek/read. Rate limiting keeps the audit log bounded.
            self._diagnostic_emit = emit
            self._diagnostic_state = state
            self._next_read_diagnostic_at = 0.0
            self._read_requests = 0


else:

    class EwfImgInfo:  # type: ignore[no-redef]
        def __init__(self, ewf_handle):
            raise RuntimeError("pytsk3 unavailable")


def _path_from_uri(uri: str) -> Path:
    if uri.startswith("file://"):
        return Path(uri[7:])
    return Path(uri)


_evidence_path_cache: dict[str, Path] = {}


def _resolve_evidence_path(raw: str) -> Path:
    """Resolve a registered host_path to a path visible in this container.

    Prefer the stored /host/<drive>/… mount. If that mount is missing (e.g. worker
    without drive binds), fall back to the shared /evidence volume when the path
    sits under …/evidence/….
    """
    stripped = (raw or "").strip()
    if not stripped:
        raise ValueError("empty evidence path")
    cached = _evidence_path_cache.get(stripped)
    if cached is not None:
        try:
            if cached.exists():
                return cached
        except OSError:
            pass
        # A miss during a Docker drive-mount blip must not stick for the process lifetime.
        _evidence_path_cache.pop(stripped, None)

    primary = _path_from_uri(f"file://{stripped}" if not stripped.startswith("file://") else stripped)
    try:
        if primary.exists():
            _evidence_path_cache[stripped] = primary
            return primary
    except OSError:
        pass

    norm = stripped.replace("\\", "/")
    marker = "/evidence/"
    idx = norm.lower().find(marker)
    if idx >= 0:
        alt = Path("/evidence") / norm[idx + len(marker) :]
        try:
            if alt.exists():
                if stripped not in _evidence_path_cache:
                    log.info("Resolved evidence via /evidence fallback: %s → %s", stripped, alt)
                _evidence_path_cache[stripped] = alt
                return alt
        except OSError:
            pass

    try:
        from app.services.host_evidence import resolve_host_path

        resolved = resolve_host_path(stripped, strict=False)
        try:
            if resolved.exists():
                _evidence_path_cache[stripped] = resolved
                return resolved
        except OSError:
            pass
        return resolved
    except Exception:
        return primary


def require_visible_evidence_paths(raw_paths: list[str], *, attempts: int = 4) -> list[Path]:
    """Resolve evidence paths, retrying while a Docker drive mount is still attaching.

    ``Path.exists()`` is briefly false right after a worker restart even when the
    file is on the host. Caching that miss made the next open fail immediately.
    """
    last_missing: list[str] = []
    for attempt in range(max(int(attempts), 1)):
        resolved = [_resolve_evidence_path(p) for p in raw_paths]
        missing: list[str] = []
        for raw, path in zip(raw_paths, resolved):
            try:
                visible = path.exists()
            except OSError:
                visible = False
            if not visible:
                missing.append(str(path))
                _evidence_path_cache.pop((raw or "").strip(), None)
        if not missing:
            return resolved
        last_missing = missing
        if attempt + 1 < attempts:
            time.sleep(1.5 * (attempt + 1))
    shown = last_missing[0] if last_missing else "(none)"
    extra = f" (+{len(last_missing) - 1} more)" if len(last_missing) > 1 else ""
    raise ValueError(
        "Evidence path(s) not accessible in this worker "
        f"(path not visible at the registered location): {shown}{extra}"
    )


def _segment_sort_key(path: Path) -> tuple:
    name = path.name
    number = ewf_segment_number(name)
    if number is not None:
        return (Path(name).stem.lower(), number)
    m = re.match(r"^(?P<base>.+)\.(?P<part>\d{3})$", name)
    if m:
        return (m.group("base").lower(), int(m.group("part")))
    m = re.match(r"^(?P<base>.+)\.pas(?P<part>\d+)$", name, re.I)
    if m:
        return (m.group("base").lower(), int(m.group("part")))
    return (name.lower(), 0)


def is_portable_zip_archive(path: Path) -> bool:
    """True for ZIP containers used as mobile dumps (UFED FileDump .zip / Aetheris packages).

    Native Cellebrite ``.pas`` (PA BinaryFormatter) and ``.ufd`` (INI) are NOT zips —
    the payload is the sibling FileDump ``.zip`` referenced by the ``.ufd``.
    """
    try:
        if not path.is_file():
            return False
        lower = path.suffix.lower()
        if lower in {".ufdx"}:
            return False
        if lower == ".ufd":
            head = path.read_bytes()[:64]
            if head.startswith(b"[DeviceInfo]") or b"[Dumps]" in head or b"[FileDump]" in head:
                return False
        if lower == ".pas":
            head = path.read_bytes()[:64]
            if head.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff") or b"Logic" in head or b"PA.Data" in head:
                return False
        # Never treat extensionless iOS backup blobs (40-hex names) as packages.
        # zipfile.is_zipfile() on those opens every hashed file and expands
        # nested docx/xlsx/jar into the extract plan — hours of false unzip.
        if lower in PORTABLE_ZIP_SUFFIXES or lower == ".zip":
            return zipfile.is_zipfile(path)
    except OSError:
        return False
    return False


def resolve_zip_archive_member(
    root: Path,
    rel_path: str,
    *,
    cache: dict[str, tuple[str, str]] | None = None,
) -> tuple[Path, str] | None:
    """Split ``archive.zip/inner/path`` into (archive_path, member) under root."""
    rel = rel_path.replace("\\", "/").lstrip("/")
    if not rel:
        return None
    if cache is not None and rel in cache:
        archive_s, member = cache[rel]
        return Path(archive_s), member
    # Fast path: first path component is often the dump zip name.
    parts = rel.split("/")
    if len(parts) >= 2:
        head = root / parts[0]
        try:
            if head.is_file() and is_portable_zip_archive(head):
                member = "/".join(parts[1:])
                if member:
                    if cache is not None:
                        cache[rel] = (str(head), member)
                    return head, member
        except OSError:
            pass
    for i in range(1, len(parts)):
        candidate = root.joinpath(*parts[:i])
        try:
            if candidate.is_file() and is_portable_zip_archive(candidate):
                member = "/".join(parts[i:])
                if member:
                    if cache is not None:
                        cache[rel] = (str(candidate), member)
                    return candidate, member
        except OSError:
            continue
    return None


def stamp_zip_read_offsets(vd: VirtualDisk, nodes: list[dict]) -> int:
    """Set inode to each member's local-header offset for one payload zip.

    Saved extract plans list members in path order. Reading them that way
    seeks across the archive for every file. Header order is one forward pass.
    """
    if not nodes:
        return 0
    archives: list[Path] = []
    for raw in getattr(vd, "segment_paths", None) or []:
        path = Path(str(raw))
        if path.suffix.lower() == ".zip" and path.is_file():
            archives.append(path)
    if len(archives) != 1:
        return 0
    archive = archives[0]
    prefix = archive.name + "/"
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            offsets = {
                info.filename.replace("\\", "/").lstrip("/"): int(info.header_offset)
                for info in zf.infolist()
                if not info.is_dir()
            }
    except (OSError, zipfile.BadZipFile):
        return 0
    stamped = 0
    for node in nodes:
        if node.get("inode") is not None:
            continue
        rel = str(node.get("path") or "").replace("\\", "/")
        member = ""
        if rel.startswith(prefix):
            member = rel[len(prefix):]
        elif f"/{prefix}" in rel:
            member = rel.split(f"/{prefix}", 1)[1]
        off = offsets.get(member) if member else None
        if off is None:
            continue
        node["inode"] = off
        stamped += 1
    return stamped


class ZipForwardError(Exception):
    """This member cannot be streamed from the current forward position."""


class ZipForwardReader:
    """Read zip members in local-header order with one open file.

    ``ZipFile.open`` seeks for every member. On a Docker drive mount that seek
    dominates, even when the next member sits at the current position. This
    reader parses the local header and continues forward.
    """

    _LOCAL = struct.Struct("<4sHHHHHIIIHH")

    def __init__(self, archive: Path) -> None:
        self._path = archive
        self._f = archive.open("rb")
        self._by_off: dict[int, zipfile.ZipInfo] = {}
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                self._by_off[int(info.header_offset)] = info
        self._pos: int | None = None
        self._file_pos = 0
        self._buf = b""
        self._buf_off = -1

    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass

    def iter_member(self, header_offset: int, chunk_size: int = 8 * 1024 * 1024) -> Iterator[bytes]:
        info = self._by_off.get(int(header_offset))
        if info is None:
            raise ZipForwardError(f"no member at offset {header_offset}")
        if info.flag_bits & 0x1:
            raise ZipForwardError("encrypted member")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ZipForwardError(f"unsupported method {info.compress_type}")
        if info.compress_size >= 0xFFFFFFFF or info.file_size >= 0xFFFFFFFF:
            raise ZipForwardError("zip64 member")
        self._align(int(header_offset))
        header = self._read_exact(30)
        sig, _ver, flags, _method, _time, _date, _crc, _csize, _usize, name_len, extra_len = self._LOCAL.unpack(header)
        if sig != b"PK\x03\x04":
            raise ZipForwardError("bad local header")
        self._read_exact(name_len + extra_len)
        remaining = int(info.compress_size)
        decompressor = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
        while remaining > 0:
            n = min(max(int(chunk_size), 1), remaining)
            data = self._read_exact(n)
            remaining -= len(data)
            if decompressor is None:
                if data:
                    yield data
                continue
            out = decompressor.decompress(data)
            if out:
                yield out
        if decompressor is not None:
            tail = decompressor.flush()
            if tail:
                yield tail
        if flags & 0x08:
            self._skip_data_descriptor()

    def _align(self, header_offset: int) -> None:
        if self._pos == header_offset:
            return
        if self._pos is not None and 0 <= header_offset - self._pos <= (1 << 20):
            if header_offset > self._pos:
                self._read_exact(header_offset - self._pos)
            return
        self._pos = header_offset
        self._buf = b""
        self._buf_off = -1

    def _fill(self) -> None:
        if self._pos is None:
            raise ZipForwardError("position unknown")
        if self._file_pos != self._pos:
            self._f.seek(self._pos)
            self._file_pos = self._pos
        data = self._f.read(8 * 1024 * 1024)
        self._file_pos += len(data)
        if not data:
            raise ZipForwardError("eof")
        self._buf = data
        self._buf_off = self._pos

    def _read_exact(self, n: int) -> bytes:
        if n <= 0:
            return b""
        if self._pos is None:
            raise ZipForwardError("position unknown")
        out = bytearray()
        while len(out) < n:
            if not (self._buf_off <= self._pos < self._buf_off + len(self._buf)):
                self._fill()
            start = self._pos - self._buf_off
            take = min(n - len(out), len(self._buf) - start)
            if take <= 0:
                raise ZipForwardError("eof")
            out += self._buf[start:start + take]
            self._pos += take
        return bytes(out)

    def _skip_data_descriptor(self) -> None:
        peek = self._read_exact(4)
        if peek == b"PK\x07\x08":
            self._read_exact(12)
            return
        if peek in (b"PK\x03\x04", b"PK\x01\x02"):
            if self._pos is not None:
                self._pos -= 4
            return
        # Peek was the CRC of a descriptor that has no signature.
        self._read_exact(8)


_package_original_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


def _package_original_dirs(archive: Path) -> list[Path]:
    """Resolve sealed ORIGINAL_PATH / aetheris_package.json targets from a portable ZIP."""
    out: list[Path] = []
    if not is_portable_zip_archive(archive):
        return out
    try:
        cache_key = str(archive.resolve())
        mtime = float(archive.stat().st_mtime)
    except OSError:
        cache_key = str(archive)
        mtime = 0.0
    cached = _package_original_cache.get(cache_key)
    if cached and cached[0] == mtime:
        return [Path(item) for item in cached[1]]
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = {n.replace("\\", "/") for n in zf.namelist()}
            candidates: list[str] = []
            if "ORIGINAL_PATH.txt" in names:
                candidates.append(zf.read("ORIGINAL_PATH.txt").decode("utf-8", errors="replace").strip())
            if "aetheris_package.json" in names:
                try:
                    meta = json.loads(zf.read("aetheris_package.json"))
                except Exception:
                    meta = {}
                if isinstance(meta, dict) and meta.get("original_path"):
                    candidates.append(str(meta["original_path"]))
        for raw in candidates:
            if not raw:
                continue
            try:
                resolved = _resolve_evidence_path(raw)
            except Exception:
                resolved = Path(raw)
            try:
                if resolved.is_dir():
                    out.append(resolved)
            except OSError:
                continue
    except (OSError, zipfile.BadZipFile) as exc:
        log.debug("package original lookup failed %s: %s", archive, exc)
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    _package_original_cache[cache_key] = (mtime, tuple(str(p) for p in uniq))
    return uniq


def _is_ewf_segment(path: Path) -> bool:
    return bool(SEGMENT_NAME_RE.search(path.name)) or path.suffix.lower() in (".e01", ".ex01")


def _sorted_segment_paths(paths: list[Path]) -> list[Path]:
    return sorted(paths, key=_segment_sort_key)


def _open_filesystem(img) -> object | None:
    if not _pytsk3:
        return None
    try:
        return _pytsk3.FS_Info(img)
    except Exception:
        pass
    try:
        volume = _pytsk3.Volume_Info(img)
        block_size = getattr(volume.info, "block_size", 512) or 512
        candidates: list[tuple[int, str, object]] = []
        for part in volume:
            if part.len <= 0:
                continue
            desc = part.desc.decode("utf-8", errors="replace")
            lower = desc.lower()
            if any(
                token in lower
                for token in (
                    "unallocated",
                    "extended",
                    "meta",
                    "gpt header",
                    "partition table",
                    "safety table",
                )
            ):
                continue
            try:
                fs = _pytsk3.FS_Info(img, offset=part.start * block_size)
                candidates.append((part.len, desc, fs))
            except Exception:
                continue
        if not candidates:
            return None

        def partition_score(item: tuple[int, str, object]) -> int:
            length, desc, _ = item
            lower = desc.lower()
            bonus = 0
            if "basic data" in lower or "ntfs" in lower:
                bonus = 10**18
            elif "microsoft" in lower and "reserved" not in lower:
                bonus = 10**16
            if "efi" in lower or "reserved" in lower or "recovery" in lower:
                bonus -= 10**15
            return bonus + length

        candidates.sort(key=partition_score, reverse=True)
        return candidates[0][2]
    except Exception as exc:
        log.warning("partition scan failed: %s", exc)
    return None


def _open_img_info(paths: list[Path]):
    if not paths:
        raise ValueError("no segment paths")
    try:
        # Client-workstation evidence: make sure this process's container has
        # the read-only FUSE mount before pyewf/pytsk3 open the segments.
        from app.services.client_evidence.mount import ensure_mounted_for_paths

        ensure_mounted_for_paths(paths)
    except Exception as exc:
        log.warning("client evidence mount before image open failed: %s", exc)
    sorted_paths = _sorted_segment_paths(paths)

    if _pyewf and _pytsk3 and any(_is_ewf_segment(p) for p in sorted_paths):
        try:
            filenames = [str(p) for p in sorted_paths]
            log.info("Opening EWF image %s (%s segment file(s))", filenames[0], len(filenames))
            ewf_handle = _pyewf.handle()
            ewf_handle.open(filenames)
            log.info("Opened EWF image %s", filenames[0])
            return EwfImgInfo(ewf_handle), "ewf"
        except Exception as e:
            log.warning("pyewf open failed, falling back to folder mode: %s", e)
            return None, "folder"

    if _pytsk3 and sorted_paths[0].suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx", ".aff", ".aff4"):
        try:
            return _pytsk3.Img_Info(str(sorted_paths[0])), "raw"
        except Exception as e:
            log.warning("pytsk3 raw open failed: %s", e)
            return None, "folder"
    return None, "folder"


_IMAGE_SEGMENT_RE = re.compile(r"\.(?:e(?:\d{2}|(?!xe|wf)[a-z]{2})|\d{3}|dd|raw|vmdk|vhdx|aff4?)$", re.I)
_IMAGE_BASE_RE = re.compile(r"^(?P<base>.*)\.(?:e(?:\d{2}|(?!xe|wf)[a-z]{2})|\d{3})$", re.I)


def _image_group_key(path: Path) -> str:
    match = _IMAGE_BASE_RE.match(path.name)
    base = match.group("base") if match else path.stem
    return f"{str(path.parent).lower()}|{base.lower()}"


def _image_group_label(path: Path) -> str:
    match = _IMAGE_BASE_RE.match(path.name)
    base = match.group("base") if match else path.stem
    label = re.sub(r'[<>:"/\\|?*]+', "_", base).strip(" .")
    return label or "disk"


def split_image_sets(
    paths: list[Path],
    hashes: list[str] | None = None,
) -> list[tuple[list[Path], list[str]]] | None:
    """Split a registration into separate disk images.

    One image, with or without sidecar files, stays on the normal opener.
    Directories that each contain their own .E01/.001 set are opened one by
    one and then presented as a single disk.
    """
    hashes = list(hashes or [])
    groups: dict[str, list[Path]] = {}
    grouped_hashes: dict[str, list[str]] = {}
    order: list[str] = []
    for index, path in enumerate(paths):
        if not _IMAGE_SEGMENT_RE.search(path.name):
            continue
        key = _image_group_key(path)
        if key not in groups:
            groups[key] = []
            grouped_hashes[key] = []
            order.append(key)
        groups[key].append(path)
        grouped_hashes[key].append(hashes[index] if index < len(hashes) else "")
    if len(order) <= 1:
        return None
    return [(groups[key], grouped_hashes[key]) for key in order]


def open_compound_disk(
    job_id: str,
    groups: list[tuple[list[Path], list[str]]],
    *,
    all_paths: list[str],
    all_hashes: list[str],
) -> VirtualDisk:
    used: dict[str, int] = {}
    members: list[VirtualDisk] = []
    labels: list[str] = []
    for group_paths, group_hashes in groups:
        raw = _image_group_label(group_paths[0])
        used[raw] = used.get(raw, 0) + 1
        label = raw if used[raw] == 1 else f"{raw}_{used[raw]}"
        labels.append(label)
        member = open_virtual_disk_from_paths(
            job_id,
            [str(path) for path in group_paths],
            hashes=group_hashes,
            base_name=label,
            combine_image_sets=False,
        )
        member.base_name = label
        members.append(member)
    title = labels[0] if len(labels) == 1 else f"{labels[0]}+{len(labels) - 1}"
    return VirtualDisk(
        job_id=job_id,
        mode="compound",
        segment_paths=list(all_paths),
        segment_hashes=list(all_hashes),
        base_name=title,
        format="multi",
        members=members,
    )


def _evidence_host_path(row: dict) -> str:
    host = str(row.get("host_path") or "").strip()
    if host:
        return host
    uri = str(row.get("storage_uri") or "")
    if uri.startswith("file://"):
        return uri[7:]
    return ""


def list_image_directories(files: list[dict]) -> list[dict]:
    """Image segments grouped by parent directory, in first-seen order.

    A single directory is included. Callers that must keep the one-image
    opener use ``evidence_directory_groups``, which returns None in that case.
    """
    groups: dict[str, dict] = {}
    order: list[str] = []
    for row in files:
        host = _evidence_host_path(row)
        if not host:
            continue
        path = Path(host)
        if not _IMAGE_SEGMENT_RE.search(path.name):
            continue
        parent = str(path.parent)
        key = parent.lower()
        if key not in groups:
            groups[key] = {
                "directory": parent,
                "label": path.parent.name or _image_group_label(path),
                "paths": [],
                "hashes": [],
            }
            order.append(key)
        groups[key]["paths"].append(host)
        groups[key]["hashes"].append(str(row.get("sha256") or ""))
    return [groups[key] for key in order]


def evidence_directory_groups(files: list[dict]) -> list[dict] | None:
    """Group image segments by parent directory.

    One directory stays on the normal single-image opener. Two or more
    directories are separate images and must be extracted one after another.
    """
    groups = list_image_directories(files)
    if len(groups) <= 1:
        return None
    return groups


def open_directory_images(job_id: str, groups: list[dict]) -> VirtualDisk:
    """Mount each evidence directory on its own, in order.

    A directory whose image cannot be mounted is not walked as a folder of
    segment files. Callers combine the mounted images, then filter once.
    """
    used: dict[str, int] = {}
    members: list[VirtualDisk] = []
    warnings: list[str] = []
    all_paths: list[str] = []
    all_hashes: list[str] = []
    for group in groups:
        path_objs = [Path(path) for path in group["paths"]]
        hashes = list(group["hashes"])
        subsets = split_image_sets(path_objs, hashes)
        if subsets is None:
            subsets = [(path_objs, hashes)]
        for subset_paths, subset_hashes in subsets:
            raw = _image_group_label(subset_paths[0])
            used[raw] = used.get(raw, 0) + 1
            label = raw if used[raw] == 1 else f"{raw}_{used[raw]}"
            member = open_virtual_disk_from_paths(
                job_id,
                [str(path) for path in subset_paths],
                hashes=subset_hashes,
                base_name=label,
                combine_image_sets=False,
            )
            mounted = member._fs_info is not None and member.mode in {"ewf", "raw"}
            if not mounted:
                warnings.append(
                    f"Could not mount {label} ({len(subset_paths)} segment file(s) in "
                    f"{group['directory']}). Its segment files were not used as extracted files."
                )
                member.close()
                continue
            member.base_name = label
            members.append(member)
            all_paths.extend(str(path) for path in subset_paths)
            all_hashes.extend(subset_hashes)
    if not members:
        detail = " ".join(warnings) or "No evidence directory could be mounted."
        raise ValueError(detail)
    title = members[0].base_name if len(members) == 1 else f"{members[0].base_name}+{len(members) - 1}"
    vd = VirtualDisk(
        job_id=job_id,
        mode="compound",
        segment_paths=all_paths,
        segment_hashes=all_hashes,
        base_name=title,
        format="multi",
        members=members,
    )
    vd.mount_warnings = warnings  # type: ignore[attr-defined]
    return vd


def open_virtual_disk(
    db: Session,
    job_id: str,
    *,
    on_progress: ProgressCb | None = None,
) -> VirtualDisk:
    files = fetchall(
        db,
        """SELECT * FROM evidence_files WHERE job_id=:job_id AND status IN ('registered','assembled')
           ORDER BY segment_part NULLS LAST, original_name""",
        {"job_id": job_id},
    )
    if not files:
        raise ValueError("no registered evidence files")

    _emit(on_progress, f"Resolving {len(files)} evidence segment path(s)…", {"segments": len(files)})

    paths: list[str] = []
    hashes: list[str] = []
    for f in files:
        hp = f.get("host_path") or (f.get("storage_uri") or "")[7:]
        if hp:
            paths.append(hp)
            hashes.append(f.get("sha256") or "")

    if not paths:
        raise ValueError("no host paths on registered evidence files")

    path_objs = require_visible_evidence_paths(paths)

    # Prefer resolved container paths for subsequent open/walk
    paths = [str(p) for p in path_objs]
    first = path_objs[0]

    if all(p.is_file() for p in path_objs):
        image_groups = split_image_sets(path_objs, hashes)
        if image_groups is not None:
            _emit(
                on_progress,
                f"Opening {len(image_groups)} disk image(s) one by one as one disk…",
                {"disks": len(image_groups)},
            )
            return open_compound_disk(
                job_id,
                image_groups,
                all_paths=paths,
                all_hashes=hashes,
            )

    if first.is_dir():
        _emit(on_progress, "Using folder-mode virtual disk (directory evidence)", {"mode": "folder"})
        return VirtualDisk(
            job_id=job_id,
            mode="folder",
            segment_paths=paths,
            segment_hashes=hashes,
            base_name=files[0].get("segment_base") or first.name,
            format="backup",
            root_folder=str(first),
        )

    base_name = files[0].get("segment_base") or first.stem
    fmt = first.suffix.lstrip(".").lower() or "raw"

    vd = VirtualDisk(
        job_id=job_id,
        mode="folder",
        segment_paths=paths,
        segment_hashes=hashes,
        base_name=base_name,
        format=fmt,
    )

    if all(p.is_file() for p in path_objs):
        suffixes = {p.suffix.lower() for p in path_objs}
        mobile_only = suffixes.issubset(MOBILE_FOLDER_FORMATS | {".ufd", ".ufdx", ".zip", ".pas", ""})
        if mobile_only or suffixes & {".pas", ".ufd", ".ufdx", ".zip"}:
            vd.mode = "folder"
            vd.root_folder = str(first.parent)
            vd.format = "mobile"
            _emit(on_progress, "Mobile extraction folder — using folder mode", {"mode": "folder", "format": "mobile"})
            return vd

    if all(p.is_file() for p in path_objs) and any(
        _is_ewf_segment(p) or p.suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx") for p in path_objs
    ):
        _emit(
            on_progress,
            f"Opening forensic image handle ({len(path_objs)} segment(s), format={fmt})…",
            {"segments": len(path_objs), "format": fmt},
        )
        img, mode = _open_img_info(path_objs)
        if img and _pytsk3 and mode != "folder":
            vd.mode = mode
            vd._img_info = img
            _emit(on_progress, f"Image handle ready — mode={mode}; scanning partitions…", {"mode": mode})
            fs = _open_filesystem(img)
            if fs:
                vd._fs_info = fs
                _emit(on_progress, "Filesystem mounted successfully", {"mode": mode})
            else:
                log.warning("FS_Info failed for job %s — no readable partition", job_id)
                vd.mode = "folder"
                vd.root_folder = str(first.parent)
                _emit(
                    on_progress,
                    "No readable partition found — falling back to folder mode",
                    {"mode": "folder"},
                )
        else:
            vd.mode = "folder"
            vd.root_folder = str(first.parent)
            _emit(on_progress, "Image open unavailable — using folder mode", {"mode": "folder"})

    return vd


def open_virtual_disk_from_paths(
    job_id: str,
    paths: list[str],
    *,
    hashes: list[str] | None = None,
    base_name: str = "",
    fmt: str = "",
    root_folder: str | None = None,
    combine_image_sets: bool = True,
) -> VirtualDisk:
    """V45: open a VirtualDisk from an already-resolved plan — no DB session.

    Shard threads use this so they never compete for the Celery worker's tiny
    Postgres pool. Mirrors ``open_virtual_disk`` after path resolution.
    """
    if not paths:
        raise ValueError("no segment paths")
    path_objs = require_visible_evidence_paths(paths)
    first = path_objs[0]
    resolved = [str(p) for p in path_objs]
    hashes = list(hashes or [])
    if root_folder or first.is_dir():
        return VirtualDisk(
            job_id=job_id,
            mode="folder",
            segment_paths=resolved,
            segment_hashes=hashes,
            base_name=base_name or first.name,
            format=fmt or "backup",
            root_folder=root_folder or str(first),
        )
    if combine_image_sets:
        image_groups = split_image_sets(path_objs, hashes)
        if image_groups is not None:
            return open_compound_disk(
                job_id,
                image_groups,
                all_paths=resolved,
                all_hashes=hashes,
            )
    vd = VirtualDisk(
        job_id=job_id,
        mode="folder",
        segment_paths=resolved,
        segment_hashes=hashes,
        base_name=base_name or first.stem,
        format=fmt or (first.suffix.lstrip(".").lower() or "raw"),
    )
    if any(_is_ewf_segment(p) or p.suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx") for p in path_objs):
        img, mode = _open_img_info(path_objs)
        if img and _pytsk3 and mode != "folder":
            vd.mode = mode
            vd._img_info = img
            fs = _open_filesystem(img)
            if fs:
                vd._fs_info = fs
                return vd
    vd.mode = "folder"
    vd.root_folder = str(first.parent)
    return vd


def vd_plan(vd: VirtualDisk) -> dict:
    """Serializable description a shard can reopen the disk from (V45)."""
    return {
        "segment_paths": list(vd.segment_paths),
        "segment_hashes": list(vd.segment_hashes),
        "base_name": vd.base_name,
        "format": vd.format,
        "root_folder": vd.root_folder,
        "mode": vd.mode,
    }


_VD_CACHE: dict[str, tuple[VirtualDisk, float]] = {}
_VD_CACHE_LOCK = threading.Lock()
_VD_CACHE_TTL_SEC = 600.0
_VD_CACHE_MAX_JOBS = 2


def open_virtual_disk_cached(
    db: Session,
    job_id: str,
    *,
    on_progress: ProgressCb | None = None,
) -> VirtualDisk:
    """Reuse an open image handle across preview/content requests (avoids OOM from repeated EWF mounts)."""
    now = time.time()
    with _VD_CACHE_LOCK:
        entry = _VD_CACHE.get(job_id)
        if entry and now - entry[1] < _VD_CACHE_TTL_SEC:
            return entry[0]

        stale = [key for key, (_, ts) in _VD_CACHE.items() if now - ts >= _VD_CACHE_TTL_SEC]
        for key in stale:
            _VD_CACHE.pop(key, None)
        while len(_VD_CACHE) >= _VD_CACHE_MAX_JOBS:
            oldest = min(_VD_CACHE.items(), key=lambda item: item[1][1])[0]
            _VD_CACHE.pop(oldest, None)

        vd = open_virtual_disk(db, job_id, on_progress=on_progress)
        _VD_CACHE[job_id] = (vd, now)
        return vd


def clear_virtual_disk_cache(job_id: str | None = None) -> None:
    with _VD_CACHE_LOCK:
        if job_id:
            _VD_CACHE.pop(job_id, None)
        else:
            _VD_CACHE.clear()


def _tsk_meta_type(value) -> int:
    return value.value if hasattr(value, "value") else int(value)


def filesystem_root_inode(fs_info) -> int | None:
    """Inode of the filesystem root. NTFS uses 5 when TSK does not report one.

    ``open_dir(path='/')`` resolves that same directory by name and, on a
    multi-segment E01, seeks tens of gigabytes apart before the first entry.
    Opening the inode skips that lookup.
    """
    info = getattr(fs_info, "info", None)
    raw = getattr(info, "root_inum", None)
    try:
        inode = int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        inode = None
    if inode:
        return inode
    ftype = getattr(info, "ftype", None)
    name = str(getattr(ftype, "name", "") or "")
    value = getattr(ftype, "value", ftype)
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        numeric = None
    if "NTFS" in name.upper() or numeric == 1:
        return 5
    return None


_EWF_CACHE_BLOCK = 256 * 1024
_EWF_CACHE_BLOCKS = 128
_EWF_CACHE_DIRECT = 4 * 1024 * 1024


def cached_image_read(handle, cache: OrderedDict, offset: int, size: int) -> bytes:
    """Read image bytes, reusing 256 KiB windows.

    TSK root-open issues many small reads of the same NTFS metadata. Each one
    otherwise seeks and decompresses the E01 again.
    """
    if size <= 0:
        return b""
    if size > _EWF_CACHE_DIRECT:
        handle.seek(int(offset))
        return handle.read(int(size))
    end = int(offset) + int(size)
    pos = int(offset)
    out = bytearray()
    while pos < end:
        block_off = pos - (pos % _EWF_CACHE_BLOCK)
        block = cache.get(block_off)
        if block is None:
            handle.seek(block_off)
            block = handle.read(_EWF_CACHE_BLOCK) or b""
            cache[block_off] = block
            while len(cache) > _EWF_CACHE_BLOCKS:
                cache.popitem(last=False)
        else:
            cache.move_to_end(block_off)
        start = pos - block_off
        if start >= len(block):
            break
        take = min(len(block) - start, end - pos)
        out += block[start:start + take]
        pos += take
    return bytes(out)


def enumerate_all_files(
    vd: VirtualDisk,
    *,
    on_progress: ProgressCb | None = None,
    progress_every: int = 25_000,
    progress_interval_sec: float = 15.0,
    root_open_strategy: str = "inode",
) -> list[dict]:
    """Walk filesystem and return every regular file (complete disk index).

    Open the TSK root by its filesystem inode first: this avoids pathname
    resolution in an image with damaged/huge directory metadata. A bounded
    parent process may retry with the alternate path-based strategy; never
    switch strategies inside a potentially blocked native call.
    """
    if vd.mode == "compound" and vd.members:
        nodes: list[dict] = []
        for member in vd.members:
            part = enumerate_all_files(
                member,
                on_progress=on_progress,
                progress_every=progress_every,
                progress_interval_sec=progress_interval_sec,
                root_open_strategy=root_open_strategy,
            )
            label = member.base_name or "disk"
            for node in part:
                copied = dict(node)
                rel = str(copied.get("path") or "").replace("\\", "/").lstrip("/")
                copied["path"] = f"{label}/{rel}" if rel else label
                nodes.append(copied)
        _emit(
            on_progress,
            f"Combined {len(vd.members)} disk image(s) — {len(nodes):,} files",
            {"files_found": len(nodes), "disks": len(vd.members)},
        )
        return nodes
    # EWF/RAW directory enumeration can be parallelized safely only with
    # independent handles. The isolated watchdog still owns termination.
    if (vd._fs_info and _pytsk3 and vd.mode in ("ewf", "raw")
            and getattr(vd, "segment_paths", None) and getattr(vd, "job_id", None)):
        from app.services.tsk_parallel_inventory import inventory_readers, enumerate_tsk_parallel
        readers, _ = inventory_readers(vd)
        if readers > 1:
            return enumerate_tsk_parallel(
                vd, on_progress=on_progress, root_open_strategy=root_open_strategy,
                workers=readers, progress_interval_sec=progress_interval_sec)
    nodes: list[dict] = []
    last_emit = time.monotonic()
    every_n = max(int(progress_every), 1_000)
    every_sec = max(float(progress_interval_sec), 5.0)

    def _maybe_progress(force: bool = False) -> None:
        nonlocal last_emit
        now = time.monotonic()
        count = len(nodes)
        if not force and count > 0 and count % every_n != 0 and (now - last_emit) < every_sec:
            return
        if count == 0 and not force:
            return
        last_emit = now
        _emit(
            on_progress,
            f"Filesystem walk — {count:,} files found so far…",
            {"files_found": count},
        )

    if vd._fs_info and _pytsk3:
        reg_type = _tsk_meta_type(_pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG)
        dir_type = _tsk_meta_type(_pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR)
        if root_open_strategy not in {"inode", "path"}:
            raise ValueError(f"Invalid TSK root-open strategy: {root_open_strategy}")
        root_inode = filesystem_root_inode(vd._fs_info)
        actual_strategy = "inode" if root_open_strategy == "inode" and root_inode is not None else "path"
        _emit(on_progress, "Starting TSK filesystem walk…", {
            "mode": vd.mode, "action": "tsk_walk_start", "reader_phase": "root_open",
            "root_open_strategy": actual_strategy, "root_inode": root_inode})

        # An iterative walk avoids recursion-depth crashes on deeply nested
        # NTFS images, and protects against cycles through directory aliases.
        # Track *directory* inodes only; file hardlinks remain visible as paths.
        seen_directories: set[int] = set()
        directories_scanned = 0
        entries_scanned = 0
        unreadable_directories = 0
        alias_directories_skipped = 0
        last_path = "/"
        _emit(on_progress, f"TSK: opening root directory ({actual_strategy})...", {
            "action": "tsk_root_open", "reader_phase": "root_open",
            "root_open_strategy": actual_strategy, "root_inode": root_inode})
        root_start = time.monotonic()
        if actual_strategy == "inode":
            root_dir = vd._fs_info.open_dir(inode=root_inode)
        else:
            root_dir = vd._fs_info.open_dir(path="/")
        root_elapsed = time.monotonic() - root_start
        _emit(on_progress, f"TSK root directory opened in {root_elapsed:.1f}s; reading first entry...", {
            "action": "tsk_root_opened", "reader_phase": "root_first_entry",
            "root_open_strategy": actual_strategy,
            "root_open_elapsed_sec": round(root_elapsed, 3), "root_inode": root_inode})
        pending = [(root_dir, "<root>", None)]
        last_emit = time.monotonic()

        while pending:
            directory, prefix, inode = pending.pop()
            if inode is not None:
                if inode in seen_directories:
                    alias_directories_skipped += 1
                    continue
                seen_directories.add(inode)
            directories_scanned += 1
            last_path = prefix
            try:
                for entry in directory:
                    entries_scanned += 1
                    if entries_scanned == 1:
                        _emit(on_progress, "TSK root first entry readable; traversing filesystem...", {
                            "action": "tsk_root_first_entry", "reader_phase": "walking",
                            "files_found": len(nodes), "directories_scanned": directories_scanned,
                            "entries_scanned": entries_scanned, "last_path": prefix})
                    try:
                        info = entry.info
                        name_bytes = info.name.name if info and info.name else None
                        if not name_bytes or name_bytes in (b".", b".."):
                            continue
                        name = (name_bytes.decode("utf-8", errors="replace")
                                if isinstance(name_bytes, bytes) else str(name_bytes))
                        rel = name if prefix == "<root>" else f"{prefix}/{name}"
                        meta = info.meta
                        if not meta:
                            continue
                        typ = _tsk_meta_type(meta.type)
                        addr = getattr(meta, "addr", None)
                        inode_number = int(addr) if addr is not None else None
                        if typ == reg_type:
                            nodes.append({
                                "path": rel,
                                "name": name,
                                "size_bytes": meta.size or 0,
                                "inode": inode_number,
                            })
                        elif typ == dir_type:
                            if inode_number is not None and inode_number in seen_directories:
                                continue
                            try:
                                child = entry.as_directory()
                            except Exception as exc:
                                unreadable_directories += 1
                                if unreadable_directories <= 5:
                                    _emit(on_progress, f"Unreadable TSK directory {rel}: {exc}", {
                                        "action": "tsk_directory_error", "path": rel,
                                        "unreadable_directories": unreadable_directories,
                                    })
                            else:
                                pending.append((child, rel, inode_number))
                    except Exception as exc:
                        unreadable_directories += 1
                        if unreadable_directories <= 5:
                            _emit(on_progress, f"TSK entry error at {prefix}: {exc}", {
                                "action": "tsk_entry_error", "path": prefix,
                                "unreadable_directories": unreadable_directories,
                            })
                    now = time.monotonic()
                    if now - last_emit >= every_sec:
                        last_emit = now
                        _emit(on_progress,
                            f"TSK filesystem walk — {len(nodes):,} files, "
                            f"{directories_scanned:,} directories, {entries_scanned:,} entries",
                            {"action": "tsk_walk_progress", "files_found": len(nodes),
                             "directories_scanned": directories_scanned,
                             "entries_scanned": entries_scanned,
                             "pending_directories": len(pending),
                             "unreadable_directories": unreadable_directories,
                             "alias_directories_skipped": alias_directories_skipped,
                             "reader_phase": "walking", "last_path": rel if 'rel' in locals() else prefix})
            except Exception as exc:
                unreadable_directories += 1
                _emit(on_progress, f"TSK directory iteration failed at {prefix}: {exc}", {
                    "action": "tsk_directory_error", "path": prefix,
                    "unreadable_directories": unreadable_directories,
                })
        _emit(on_progress,
              f"TSK walk complete — {len(nodes):,} files, {directories_scanned:,} directories"
              + (f", {unreadable_directories:,} unreadable entries/directories" if unreadable_directories else ""),
              {"action": "tsk_walk_complete", "reader_phase": "complete", "files_found": len(nodes),
               "directories_scanned": directories_scanned,
               "entries_scanned": entries_scanned,
               "unreadable_directories": unreadable_directories,
               "alias_directories_skipped": alias_directories_skipped,
               "last_path": last_path})
        return nodes

    root = Path(vd.root_folder) if vd.root_folder else _path_from_uri(f"file://{vd.segment_paths[0]}").parent
    if not root.is_dir():
        return nodes
    _emit(on_progress, f"Starting folder walk under {root}…", {"mode": "folder"})

    seen_sealed: set[str] = set()

    def _emit_directory_batches(
        archive_label: str,
        directories: list[str],
        *,
        batch_size: int = 40,
    ) -> None:
        """Write every discovered directory into extract logs (batched for UI readability)."""
        total = len(directories)
        if total == 0:
            _emit(
                on_progress,
                f"Unzip directories [{archive_label}] — none found",
                {"directories": 0, "archive": archive_label},
            )
            return
        _emit(
            on_progress,
            f"Unzip directories [{archive_label}] — {total:,} directories discovered; listing…",
            {"directories": total, "archive": archive_label},
        )
        for i in range(0, total, batch_size):
            batch = directories[i : i + batch_size]
            start = i + 1
            end = i + len(batch)
            _emit(
                on_progress,
                f"Unzip directories [{archive_label}] ({start:,}–{end:,} of {total:,}): "
                + " · ".join(batch),
                {
                    "archive": archive_label,
                    "directories": batch,
                    "directory_range": [start, end, total],
                },
            )

    def _collect_parent_dirs(member: str, into: set[str], *, include_self: bool = False) -> None:
        parts = [p for p in member.replace("\\", "/").strip("/").split("/") if p]
        end = len(parts) if include_self else max(len(parts) - 1, 0)
        for i in range(1, end + 1):
            into.add("/".join(parts[:i]))

    def _append_file(path: Path, rel: str) -> None:
        try:
            nodes.append({"path": rel, "name": path.name, "size_bytes": path.stat().st_size})
        except OSError:
            nodes.append({"path": rel, "name": path.name, "size_bytes": 0})
        _maybe_progress()

    def _walk_zip(archive: Path, prefix: str) -> None:
        label = archive.name
        try:
            size_mb = archive.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0.0
        _emit(
            on_progress,
            f"Opening mobile package for unzip — {label} ({size_mb:,.1f} MiB); listing members…",
            {"archive": str(archive), "prefix": prefix, "action": "unzip_open"},
        )
        dir_set: set[str] = set()
        file_count = 0
        last_member = ""
        try:
            with zipfile.ZipFile(archive, "r") as zf:
                infos = zf.infolist()
                _emit(
                    on_progress,
                    f"Unzip index loaded — {label}: {len(infos):,} ZIP entries; expanding directories/files…",
                    {"archive": label, "zip_entries": len(infos), "action": "unzip_index"},
                )
                for info in infos:
                    member = info.filename.replace("\\", "/").lstrip("/")
                    if not member:
                        continue
                    if info.is_dir():
                        _collect_parent_dirs(member.rstrip("/"), dir_set, include_self=True)
                        continue
                    _collect_parent_dirs(member, dir_set, include_self=False)
                    rel = f"{prefix}/{member}".replace("\\", "/").lstrip("/")
                    nodes.append({
                        "path": rel,
                        "name": Path(member).name,
                        "size_bytes": info.file_size,
                        # Local-header offset: shards read the archive forward.
                        "inode": int(info.header_offset),
                    })
                    file_count += 1
                    last_member = member
                    if file_count == 1 or file_count % 5_000 == 0:
                        _emit(
                            on_progress,
                            f"Unzip listing [{label}] — taking entry #{file_count:,}: {member} "
                            f"({int(info.file_size or 0):,} bytes) · {len(dir_set):,} dirs so far",
                            {
                                "archive": label,
                                "files_found": file_count,
                                "directories": len(dir_set),
                                "current_path": member,
                                "action": "unzip_list",
                            },
                        )
                    _maybe_progress()
        except (OSError, zipfile.BadZipFile) as exc:
            log.warning("zip walk failed for %s: %s", archive, exc)
            _emit(
                on_progress,
                f"Unzip failed for {label}: {exc}",
                {"archive": str(archive), "error": str(exc), "action": "unzip_error"},
            )
            return

        directories = sorted(dir_set, key=lambda d: (d.count("/"), d.lower()))
        _emit_directory_batches(label, directories)
        _emit(
            on_progress,
            f"ZIP member enumeration complete — {label}: {file_count:,} files, {len(directories):,} directories"
            + (f" · last={last_member}" if last_member else ""),
            {
                "archive": label,
                "files_found": file_count,
                "directories": len(directories),
                "action": "unzip_complete",
            },
        )

    def _walk_tree(base: Path, *, rel_prefix: str | None = None) -> None:
        """Walk a directory; expand UFED FileDump .zip / Aetheris ZIP packages like disk images."""
        from app.services.dir_walk import iter_files_following_dir_links

        folder_dirs: set[str] = set()
        files: list[tuple[Path, str]] = []
        skip_derived = frozenset({
            "readable_artifacts",
            "_package_marker",
            "05_exports",
            "03_working_copy",
            ".git",
            "__pycache__",
            "node_modules",
        })
        try:
            for idx, (p, found_rel) in enumerate(
                iter_files_following_dir_links(base, skip_dir_names=skip_derived),
                start=1,
            ):
                files.append((p, found_rel))
                if idx == 1 or idx % 5000 == 0:
                    _emit(
                        on_progress,
                        f"Folder walk — {idx:,} files so far · last={found_rel}",
                        {"files_found": idx, "last": found_rel, "action": "folder_walk_progress"},
                    )
                parent_rel = str(Path(found_rel).parent).replace("\\", "/")
                if parent_rel and parent_rel not in (".", ""):
                    folder_dirs.add(parent_rel)
                    _collect_parent_dirs(parent_rel, folder_dirs, include_self=True)
        except OSError as exc:
            log.warning("directory listing failed for %s: %s", base, exc)

        if folder_dirs:
            _emit_directory_batches(
                f"folder:{base.name}",
                sorted(folder_dirs, key=lambda d: (d.count("/"), d.lower())),
            )

        for p, found_rel in files:
            if not p.is_file():
                continue
            if SEGMENT_NAME_RE.search(p.name):
                continue
            rel = found_rel if not rel_prefix else f"{rel_prefix}/{found_rel}".replace("\\", "/").lstrip("/")
            rel_l = rel.replace("\\", "/").lower()
            sealed_walk = bool(
                (rel_prefix and str(rel_prefix).replace("\\", "/").lower().startswith("_sealed/"))
                or "/ios_image/" in rel_l
                or rel_l.startswith("ios_image/")
            )

            # Native Cellebrite .ufd → follow FileDump zip (Dump/…) — AXIOM/PA layout.
            if p.suffix.lower() == ".ufd" and not is_portable_zip_archive(p):
                _emit(
                    on_progress,
                    f"Found UFED unit descriptor — {rel}; resolving FileDump zip…",
                    {"ufd": rel, "action": "ufd_resolve"},
                )
                _append_file(p, rel)
                try:
                    from app.services.mobile_forensic.cellebrite_ufed import resolve_ufd_dump_zip

                    resolved = resolve_ufd_dump_zip(p)
                except Exception:
                    resolved = None
                if resolved:
                    dump_zip, logical = resolved
                    try:
                        dump_key = str(dump_zip.resolve())
                    except OSError:
                        dump_key = str(dump_zip)
                    if dump_key not in seen_sealed and is_portable_zip_archive(dump_zip):
                        seen_sealed.add(dump_key)
                        try:
                            dump_rel = str(dump_zip.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            dump_rel = dump_zip.name
                        _emit(
                            on_progress,
                            f"UFED FileDump zip — expanding {dump_zip.name} "
                            f"(logical root {logical}/) into extract plan…",
                            {
                                "mode": "folder",
                                "ufd": str(p),
                                "dump_zip": str(dump_zip),
                                "logical_root": logical,
                                "action": "ufd_expand",
                            },
                        )
                        _walk_zip(dump_zip, dump_rel)
                else:
                    _emit(
                        on_progress,
                        f"UFED descriptor {rel} has no readable FileDump zip beside it",
                        {"ufd": rel, "action": "ufd_missing_dump"},
                    )
                continue

            # Cellebrite .ufdx → follow Extraction Path= to sibling .ufd / .pas / dump zip.
            if p.suffix.lower() == ".ufdx":
                _emit(
                    on_progress,
                    f"Found UFED evidence index — {rel}; resolving Extraction paths…",
                    {"ufdx": rel, "action": "ufdx_resolve"},
                )
                _append_file(p, rel)
                try:
                    from app.services.mobile_forensic.cellebrite_ufed import (
                        resolve_ufd_dump_zip,
                        resolve_ufdx_referenced_paths,
                    )

                    refs = resolve_ufdx_referenced_paths(p)
                except Exception:
                    refs = []
                for ref in refs:
                    try:
                        ref_key = str(ref.resolve())
                    except OSError:
                        ref_key = str(ref)
                    if ref_key in seen_sealed:
                        continue
                    suf = ref.suffix.lower()
                    if suf == ".ufd":
                        seen_sealed.add(ref_key)
                        try:
                            resolved = resolve_ufd_dump_zip(ref)
                        except Exception:
                            resolved = None
                        if resolved:
                            dump_zip, logical = resolved
                            try:
                                dump_key = str(dump_zip.resolve())
                            except OSError:
                                dump_key = str(dump_zip)
                            if dump_key not in seen_sealed and is_portable_zip_archive(dump_zip):
                                seen_sealed.add(dump_key)
                                try:
                                    dump_rel = str(dump_zip.relative_to(root)).replace("\\", "/")
                                except ValueError:
                                    dump_rel = dump_zip.name
                                _emit(
                                    on_progress,
                                    f"UFEDX → FileDump zip — expanding {dump_zip.name} "
                                    f"(logical root {logical}/)…",
                                    {
                                        "ufdx": rel,
                                        "ufd": str(ref),
                                        "dump_zip": str(dump_zip),
                                        "action": "ufdx_expand",
                                    },
                                )
                                _walk_zip(dump_zip, dump_rel)
                    elif is_portable_zip_archive(ref):
                        seen_sealed.add(ref_key)
                        try:
                            dump_rel = str(ref.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            dump_rel = ref.name
                        _emit(
                            on_progress,
                            f"UFEDX → dump zip — expanding {ref.name}…",
                            {"ufdx": rel, "dump_zip": str(ref), "action": "ufdx_zip"},
                        )
                        _walk_zip(ref, dump_rel)
                    else:
                        # .pas or other referenced file — inventory only (native PAS is not a zip).
                        try:
                            ref_rel = str(ref.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            ref_rel = ref.name
                        _append_file(ref, ref_rel)
                continue

            if (not sealed_walk) and is_portable_zip_archive(p):
                try:
                    zip_key = str(p.resolve())
                except OSError:
                    zip_key = str(p)
                if zip_key in seen_sealed:
                    continue
                seen_sealed.add(zip_key)
                sealed_dirs = _package_original_dirs(p)
                has_payload = True
                try:
                    from app.services.mobile_segments import mobile_package_has_payload

                    has_payload = mobile_package_has_payload(p)
                except Exception:
                    has_payload = True
                if has_payload or not sealed_dirs:
                    _emit(
                        on_progress,
                        f"Found portable ZIP package — {rel}; starting unzip listing…",
                        {"archive": rel, "action": "zip_found"},
                    )
                    _walk_zip(p, rel)
                    if has_payload:
                        continue
                else:
                    _emit(
                        on_progress,
                        f"Metadata package — skipping ZIP payload, walking sealed original ({rel})",
                        {"archive": rel, "action": "zip_metadata_skip"},
                    )
                for sealed in sealed_dirs:
                    try:
                        sealed_key = str(sealed.resolve())
                    except OSError:
                        sealed_key = str(sealed)
                    if sealed_key in seen_sealed:
                        continue
                    try:
                        sealed.relative_to(root)
                        seen_sealed.add(sealed_key)
                        continue
                    except ValueError:
                        pass
                    seen_sealed.add(sealed_key)
                    _emit(
                        on_progress,
                        f"Walking sealed original extraction — {sealed.name}",
                        {"mode": "folder", "sealed": str(sealed), "action": "sealed_walk"},
                    )
                    _walk_tree(sealed, rel_prefix=f"_sealed/{sealed.name}")
                continue
            _append_file(p, rel)

    dir_segs = [Path(p) for p in (vd.segment_paths or []) if Path(p).is_dir()]
    payload_zips: list[Path] = []
    try:
        from app.services.mobile_segments import list_payload_zip_archives

        payload_zips = list_payload_zip_archives(root, list(vd.segment_paths or []))
    except Exception:
        payload_zips = []
    if payload_zips:
        for archive in payload_zips:
            try:
                zip_key = str(archive.resolve())
            except OSError:
                zip_key = str(archive)
            if zip_key in seen_sealed:
                continue
            seen_sealed.add(zip_key)
            try:
                rel = str(archive.relative_to(root)).replace("\\", "/")
            except ValueError:
                rel = archive.name
            _emit(
                on_progress,
                f"Payload ZIP — enumerating members only ({archive.name}); sealed folder is not walked",
                {"archive": rel, "action": "zip_payload_only"},
            )
            _walk_zip(archive, rel)
        _emit(
            on_progress,
            f"Zip-only enumeration complete — {len(nodes):,} files from {len(payload_zips)} payload archive(s)",
            {"files_found": len(nodes), "payload_zips": len(payload_zips)},
        )
        return nodes
    if len(dir_segs) > 1:
        for seg in dir_segs:
            _walk_tree(seg, rel_prefix=seg.name)
    else:
        _walk_tree(root)
    _emit(
        on_progress,
        f"Folder walk complete — {len(nodes):,} files enumerated",
        {"files_found": len(nodes)},
    )
    return nodes


def iter_file_from_disk(
    vd: VirtualDisk,
    rel_path: str,
    *,
    inode: int | None = None,
    max_bytes: int | None = None,
    chunk_size: int = 1_048_576,
) -> Iterator[bytes]:
    """Yield file bytes in chunks (UFED zip members, folders, or disk FS)."""
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    if vd.mode == "compound" and vd.members:
        prefix, sep, rest = rel_path.partition("/")
        if sep:
            for member in vd.members:
                if member.base_name == prefix:
                    yield from iter_file_from_disk(
                        member,
                        rest,
                        inode=inode,
                        max_bytes=max_bytes,
                        chunk_size=chunk_size,
                    )
                    return
        return
    remaining = max_bytes

    def _bounded_read(handle, n: int) -> bytes:
        nonlocal remaining
        if remaining is not None:
            if remaining <= 0:
                return b""
            n = min(n, remaining)
        data = handle.read(n)
        if remaining is not None and data:
            remaining -= len(data)
        return data

    if vd._fs_info and _pytsk3:
        if inode is not None:
            try:
                fentry = vd._fs_info.open_meta(inode)
            except Exception:
                fentry = vd._fs_info.open(rel_path)
        else:
            fentry = vd._fs_info.open(rel_path)
        size = fentry.info.meta.size or 0
        if size <= 0:
            return
        if max_bytes is not None:
            size = min(size, max_bytes)
        offset = 0
        while offset < size:
            n = min(chunk_size, size - offset)
            yield fentry.read_random(offset, n)
            offset += n
        return

    root = Path(vd.root_folder) if vd.root_folder else _path_from_uri(f"file://{vd.segment_paths[0]}").parent

    if rel_path.startswith("_sealed/"):
        parts = rel_path.split("/", 2)
        if len(parts) >= 3:
            sealed_name, inner = parts[1], parts[2]
            sealed = vd.sealed_root(sealed_name)
            if sealed is not None:
                full = sealed / inner.replace("/", os.sep)
                if full.is_file():
                    with full.open("rb") as handle:
                        while True:
                            chunk = _bounded_read(handle, chunk_size)
                            if not chunk:
                                return
                            yield chunk
                    return
                split = resolve_zip_archive_member(sealed, inner, cache=vd._zip_resolve_cache)
                if split:
                    archive_path, member = split
                    zf = vd.open_zip(archive_path)
                    with vd._zip_lock:
                        with zf.open(member) as handle:
                            while True:
                                chunk = _bounded_read(handle, chunk_size)
                                if not chunk:
                                    return
                                yield chunk
                    return

    full = root / rel_path.replace("/", os.sep)
    if full.is_file():
        with full.open("rb") as handle:
            while True:
                chunk = _bounded_read(handle, chunk_size)
                if not chunk:
                    return
                yield chunk
        return

    # Portable package members: ``vivo_V2403.zip/Dump/…`` — reuse cached ZipFile handle.
    split = resolve_zip_archive_member(root, rel_path, cache=vd._zip_resolve_cache)
    if split:
        archive_path, member = split
        try:
            zf = vd.open_zip(archive_path)
            with vd._zip_lock:
                with zf.open(member) as handle:
                    while True:
                        chunk = _bounded_read(handle, chunk_size)
                        if not chunk:
                            return
                        yield chunk
            return
        except KeyError as exc:
            raise FileNotFoundError(rel_path) from exc

    raise FileNotFoundError(rel_path)


def read_file_range_from_disk(
    vd: VirtualDisk,
    rel_path: str,
    *,
    start_offset: int = 0,
    inode: int | None = None,
    max_bytes: int = 8 * 1024 * 1024,
) -> bytes:
    """Read one byte range. Does not scan from the start of a large file."""
    rel_path = (rel_path or "").replace("\\", "/").lstrip("/")
    start = max(int(start_offset or 0), 0)
    want = max(int(max_bytes or 0), 0)
    if want <= 0:
        return b""
    if vd._fs_info and _pytsk3:
        fentry = None
        if inode is not None:
            try:
                fentry = vd._fs_info.open_meta(int(inode))
            except Exception:
                fentry = None
        if fentry is None and rel_path:
            for candidate in (rel_path, rel_path.lstrip("/")):
                try:
                    fentry = vd._fs_info.open(candidate)
                    break
                except Exception:
                    fentry = None
        if fentry is None:
            return b""
        size = int(getattr(getattr(fentry.info, "meta", None), "size", 0) or 0)
        if size and start >= size:
            return b""
        n = min(want, size - start) if size else want
        if n <= 0:
            return b""
        data = fentry.read_random(start, n)
        return bytes(data or b"")

    root = Path(vd.root_folder) if vd.root_folder else None
    if root is not None and rel_path:
        full = root / rel_path.replace("/", os.sep)
        if full.is_file():
            with full.open("rb") as handle:
                handle.seek(start)
                return handle.read(want)
    return b""


def read_full_file_from_disk(
    vd: VirtualDisk,
    rel_path: str,
    *,
    inode: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    chunks = list(iter_file_from_disk(vd, rel_path, inode=inode, max_bytes=max_bytes))
    return b"".join(chunks)
