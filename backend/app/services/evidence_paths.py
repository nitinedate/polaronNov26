"""Paths and text that PostgreSQL can store and that extracted archives can still find."""

from __future__ import annotations

from pathlib import PurePosixPath


def storage_text(value: str) -> str:
    """Return text PostgreSQL accepts.

    NUL is illegal in text and jsonb. Lone surrogates are not legal UTF-8.
    Other characters, including ``$`` and ``~`` in file names, are kept.
    """
    if not value:
        return ""
    cleaned = value.replace("\x00", "").replace("\u0000", "")
    return cleaned.encode("utf-8", errors="replace").decode("utf-8")


def inventory_path(source: str, ordinal: int) -> str:
    """Unique inventory path for one extracted member.

    The first copy keeps the archive member name. A later copy of that same
    name keeps the extension so parsers still recognize the file, and records
    the original name separately as ``source_path``.
    """
    if ordinal <= 0:
        return source
    path = PurePosixPath(source)
    suffix = path.suffix
    stem = path.name[: -len(suffix)] if suffix else path.name
    name = f"{stem}#copy-{ordinal}{suffix}"
    parent = path.parent.as_posix()
    if parent in ("", "."):
        return name
    return f"{parent}/{name}"
