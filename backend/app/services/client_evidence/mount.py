"""Mount client shares inside *this* container on demand.

Each processing container (API, disk/mobile build, parse, OCR, report …) gets
its own FUSE mount at ``/client-evidence/<share_id>`` the first time it needs
the evidence.  No container restart and no Docker bind-mount change is needed,
unlike server drive letters.  Requires ``/dev/fuse`` + ``CAP_SYS_ADMIN`` (see
the ``x-client-evidence-fuse`` block in the compose files).
"""

from __future__ import annotations

import fcntl
import logging
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from app.services.client_evidence import (
    ClientEvidenceError,
    enabled,
    is_client_evidence_path,
    is_valid_share_id,
    mount_root,
    split_client_path,
)

log = logging.getLogger(__name__)

_APP_ROOT = Path(__file__).resolve().parents[3]


def mountpoint_for(share_id: str) -> Path:
    if not is_valid_share_id(share_id):
        raise ClientEvidenceError("Invalid share id")
    return mount_root() / share_id


def _decode_mountinfo(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def mounted_points() -> set[str]:
    try:
        text = Path("/proc/self/mountinfo").read_text()
    except OSError:
        return set()
    points: set[str] = set()
    for line in text.splitlines():
        cols = line.split(" ")
        if len(cols) > 4:
            points.add(_decode_mountinfo(cols[4]))
    return points


def is_mounted(mp: Path) -> bool:
    return str(mp) in mounted_points()


def is_healthy(mp: Path) -> bool:
    try:
        os.stat(mp)
        os.listdir(mp)
        return True
    except OSError:
        return False


def _lazy_unmount(mp: Path) -> None:
    for cmd in (["fusermount3", "-uz", str(mp)], ["fusermount", "-uz", str(mp)], ["umount", "-l", str(mp)]):
        try:
            subprocess.run(cmd, check=False, capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if not is_mounted(mp):
            return


def fuse_ready() -> tuple[bool, str]:
    dev = Path("/dev/fuse")
    if not dev.exists():
        return False, (
            "/dev/fuse is not available in this container. Recreate the forensic containers so the "
            "client-evidence settings (devices: /dev/fuse, cap_add: SYS_ADMIN) take effect."
        )
    if not os.access(dev, os.R_OK | os.W_OK):
        return False, "/dev/fuse is present but not accessible to the forensic service user."
    try:
        import fuse  # noqa: F401  (loads libfuse.so.2 via ctypes)
    except (ImportError, OSError, EnvironmentError) as exc:
        return False, f"libfuse is not installed in this image ({exc}). Rebuild the backend image."
    return True, ""


@contextmanager
def _share_lock(share_id: str):
    path = Path(tempfile.gettempdir()) / f"polaron-client-evidence-{share_id}.lock"
    with open(path, "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _log_path(share_id: str) -> Path:
    return Path(tempfile.gettempdir()) / f"polaron-client-evidence-{share_id}.log"


def _tail(path: Path, limit: int = 1200) -> str:
    try:
        data = path.read_text(errors="replace")
    except OSError:
        return ""
    return data[-limit:].strip()


def ensure_mounted(share_id: str, *, wait_sec: float = 45.0) -> Path:
    """Mount the share in this container (idempotent); return the mount point."""
    if not enabled():
        raise ClientEvidenceError("Client workstation evidence is disabled on this server (CLIENT_EVIDENCE_ENABLED)")
    mp = mountpoint_for(share_id)
    if is_mounted(mp) and is_healthy(mp):
        return mp
    with _share_lock(share_id):
        if is_mounted(mp):
            if is_healthy(mp):
                return mp
            log.warning("client evidence mount %s is stale — remounting", mp)
            _lazy_unmount(mp)
        ok, reason = fuse_ready()
        if not ok:
            raise ClientEvidenceError(reason)
        from app.services.client_evidence import registry

        if registry.load_share(share_id) is None:
            raise ClientEvidenceError(
                f"Client evidence share {share_id} is not registered on this server. Select the folder again."
            )
        mp.mkdir(parents=True, exist_ok=True)
        log_file = _log_path(share_id)
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_APP_ROOT), env.get("PYTHONPATH", "")]))
        with open(log_file, "ab") as out:
            proc = subprocess.Popen(
                [sys.executable, "-m", "app.services.client_evidence.fusefs", "--share-id", share_id, "--mountpoint", str(mp)],
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                cwd=str(_APP_ROOT),
                env=env,
                start_new_session=True,
                close_fds=True,
            )
        deadline = time.monotonic() + wait_sec
        while time.monotonic() < deadline:
            if is_mounted(mp) and is_healthy(mp):
                log.info("client evidence share %s mounted at %s (pid %s)", share_id, mp, proc.pid)
                return mp
            code = proc.poll()
            if code is not None:
                detail = _tail(log_file) or f"daemon exited with code {code}"
                raise ClientEvidenceError(f"Could not open the client evidence share: {detail.splitlines()[-1]}")
            time.sleep(0.2)
        proc.kill()
        raise ClientEvidenceError(
            "Timed out connecting to the client workstation. Make sure the Client Evidence Agent is running "
            "and reachable from the forensic server."
        )


def unmount(share_id: str) -> None:
    try:
        mp = mountpoint_for(share_id)
    except ClientEvidenceError:
        return
    if is_mounted(mp):
        _lazy_unmount(mp)
    try:
        mp.rmdir()
    except OSError:
        pass


def ensure_mounted_for_paths(paths: Iterable[str | os.PathLike]) -> list[Path]:
    """Mount every share referenced by ``paths``. Non-client paths are ignored."""
    mounted: list[Path] = []
    seen: set[str] = set()
    for raw in paths:
        if not is_client_evidence_path(raw):
            continue
        try:
            share_id, _ = split_client_path(raw)
        except ClientEvidenceError:
            continue
        if share_id in seen:
            continue
        seen.add(share_id)
        mounted.append(ensure_mounted(share_id))
    return mounted


def ensure_job_mounts(job_id: str) -> list[Path]:
    """Mount every share registered for ``job_id`` (used before Celery tasks run)."""
    from app.services.client_evidence import registry

    out: list[Path] = []
    for share_id in registry.shares_for_job(job_id):
        try:
            out.append(ensure_mounted(share_id))
        except ClientEvidenceError as exc:
            log.warning("client evidence share %s for job %s not mounted: %s", share_id, job_id, exc)
    return out
