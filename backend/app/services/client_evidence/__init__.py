"""Client-workstation evidence: images stay on the examiner PC, the server processes them.

The examiner selects a folder on *their own* computer.  A small read-only agent
on that computer (``polaron-client-evidence-agent.ps1``) publishes exactly that
folder as a token-protected "share".  The forensic server never copies the
image: every processing container mounts the share read-only through FUSE at
``/client-evidence/<share_id>`` and reads byte ranges over the LAN on demand.

Because the mount looks like any other local directory, list-folder, segment
registration, pyewf/pytsk3 extraction, mobile package parsing and hashing run
through exactly the same code as server-attached HDD/SSD/USB evidence.

Paths
-----
* Virtual (stored in the job, shown in logs):  ``client-evidence://<share_id>/<rel>``
* Container (opened by workers):              ``/client-evidence/<share_id>/<rel>``

This module is intentionally import-light: it is imported by the path resolver
and by the FUSE daemon entry point.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

VIRTUAL_SCHEME = "client-evidence://"
SHARE_ID_RE = re.compile(r"^ce[0-9a-f]{16,64}$")
DEFAULT_AGENT_PORT = 9877


class ClientEvidenceError(RuntimeError):
    """A client-evidence operation failed with an examiner-facing message."""


def enabled() -> bool:
    return os.environ.get("CLIENT_EVIDENCE_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def mount_root() -> Path:
    return Path(os.environ.get("CLIENT_EVIDENCE_MOUNT_ROOT", "/client-evidence"))


def is_valid_share_id(share_id: str | None) -> bool:
    return bool(share_id) and bool(SHARE_ID_RE.match(str(share_id)))


def virtual_root(share_id: str) -> str:
    return f"{VIRTUAL_SCHEME}{share_id}"


def _clean_rel(rel: str) -> str:
    parts = [p for p in rel.replace("\\", "/").split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise ClientEvidenceError("Client evidence paths may not contain '..'")
    return "/".join(parts)


def is_client_evidence_path(raw: str | os.PathLike | None) -> bool:
    """True for ``client-evidence://…`` paths and for paths inside the FUSE mount root."""
    if raw is None:
        return False
    text = str(raw).strip()
    if not text:
        return False
    if text.lower().startswith(VIRTUAL_SCHEME):
        return True
    norm = text.replace("\\", "/")
    root = str(mount_root()).replace("\\", "/").rstrip("/")
    return norm == root or norm.startswith(root + "/")


def split_client_path(raw: str | os.PathLike) -> tuple[str, str]:
    """Return ``(share_id, relative_path)`` for a virtual or mounted client path."""
    text = str(raw).strip()
    if text.lower().startswith(VIRTUAL_SCHEME):
        rest = text[len(VIRTUAL_SCHEME):]
    else:
        norm = text.replace("\\", "/")
        root = str(mount_root()).replace("\\", "/").rstrip("/")
        if not (norm == root or norm.startswith(root + "/")):
            raise ClientEvidenceError(f"Not a client evidence path: {text}")
        rest = norm[len(root):]
    rest = rest.replace("\\", "/").lstrip("/")
    share_id, _, rel = rest.partition("/")
    share_id = share_id.strip().lower()
    if not is_valid_share_id(share_id):
        raise ClientEvidenceError(f"Invalid client evidence share id in path: {text}")
    return share_id, _clean_rel(rel)


def to_virtual_path(raw: str | os.PathLike) -> str:
    share_id, rel = split_client_path(raw)
    return f"{virtual_root(share_id)}/{rel}" if rel else virtual_root(share_id)


def to_container_path(raw: str | os.PathLike) -> Path:
    share_id, rel = split_client_path(raw)
    base = mount_root() / share_id
    return base / PurePosixPath(rel) if rel else base


__all__ = [
    "VIRTUAL_SCHEME",
    "DEFAULT_AGENT_PORT",
    "ClientEvidenceError",
    "enabled",
    "mount_root",
    "is_valid_share_id",
    "virtual_root",
    "is_client_evidence_path",
    "split_client_path",
    "to_virtual_path",
    "to_container_path",
]
