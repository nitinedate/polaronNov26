"""Drive Mount Agent — consult Windows letters and remount every attached drive."""

from __future__ import annotations

import json
import logging
import os
import re
import string
import time
import urllib.request
from pathlib import Path
from typing import Any

from app.services.host_evidence import (
    _host_mount_prefix,
    _is_stale_host_mount,
    _safe_is_dir,
    follow_host_junction,
)
from app.services.hostdrive_agent import probe_helper, proxy_refresh_mounts, wait_for_refresh

log = logging.getLogger("drive_mount_agent")

_SKIP_DRIVE_TYPES = frozenset({"cdrom", "cd-rom", "cd_rom"})


def inspect_local_host_letters() -> list[dict[str, Any]]:
    """What THIS container can see under /host/<letter>."""
    prefix = _host_mount_prefix()
    out: list[dict[str, Any]] = []
    for letter in string.ascii_lowercase:
        path = prefix / letter
        exists = _safe_is_dir(path)
        stale = bool(exists and _is_stale_host_mount(path))
        entries = 0
        if exists and not stale:
            try:
                entries = sum(1 for _ in path.iterdir())
            except OSError:
                stale = True
                entries = 0
        out.append(
            {
                "letter": letter,
                "path": str(path),
                "exists": exists,
                "stale": stale,
                "mounted": bool(exists and not stale),
                "entries": entries,
            }
        )
    return out


def _peer_api_bases() -> list[str]:
    extra = (os.environ.get("FORENSIC_API_URL") or os.environ.get("API_INTERNAL_URL") or "").strip()
    bases = [extra, "http://api:8080", "http://127.0.0.1:8080"]
    seen: set[str] = set()
    out: list[str] = []
    for raw in bases:
        base = raw.rstrip("/")
        if not base or base in seen:
            continue
        seen.add(base)
        out.append(base)
    return out


def inspect_peer_api_letters() -> list[dict[str, Any]] | None:
    """Ask the API container — worker-agent has no /host binds of its own."""
    for base in _peer_api_bases():
        try:
            req = urllib.request.Request(f"{base}/internal/host-mounts")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8") or "{}")
            rows = data.get("inspect") if isinstance(data, dict) else None
            if isinstance(rows, list) and any(r.get("mounted") for r in rows if isinstance(r, dict)):
                return [r for r in rows if isinstance(r, dict)]
        except Exception as exc:
            log.debug("peer host-mounts %s: %s", base, exc)
    return None


def inspect_host_letters() -> list[dict[str, Any]]:
    """API-visible /host/<letter> mounts (local first, then the API peer)."""
    local = inspect_local_host_letters()
    if mounted_letters(local):
        return local
    peer = inspect_peer_api_letters()
    return peer if peer else local


def mounted_letters(rows: list[dict[str, Any]] | None = None) -> list[str]:
    rows = rows if rows is not None else inspect_host_letters()
    return [str(r["letter"]).upper() for r in rows if r.get("mounted")]


def windows_attached_letters(helper: dict[str, Any] | None = None) -> list[str]:
    """Drive letters Windows reports ready for read-only forensic access.

    Windows considers USB SSDs 'fixed' and flash sticks 'removable', so do not
    filter based on drive_type. Exclude explicitly unready / locked volumes and
    CD-ROM placeholders. Keep old helpers compatible when `ready` is absent.
    """
    helper = helper if helper is not None else probe_helper()
    seen: set[str] = set()
    blocked: set[str] = set()
    letters: list[str] = []

    def _normalized(raw: object) -> str:
        candidate = str(raw or "").strip().upper().rstrip(":")
        return candidate if len(candidate) == 1 and candidate.isalpha() else ""

    for vol in helper.get("volumes") or []:
        if not isinstance(vol, dict):
            continue
        letter = _normalized(vol.get("letter"))
        if not letter:
            continue
        drive_type = str(vol.get("drive_type") or "").lower().replace(" ", "")
        if drive_type in _SKIP_DRIVE_TYPES or vol.get("ready") is False:
            blocked.add(letter)
            continue
        if letter not in seen:
            seen.add(letter)
            letters.append(letter)

    # Older Windows helpers only provide a raw drives array. Never re-add a
    # letter that the structured volumes list explicitly marked as not ready.
    for raw in helper.get("drives") or []:
        letter = _normalized(raw)
        if letter and letter not in seen and letter not in blocked:
            seen.add(letter)
            letters.append(letter)
    return letters


def missing_windows_letters(
    helper: dict[str, Any] | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Windows letters that Docker cannot read yet (stale stub or unmounted)."""
    wanted = windows_attached_letters(helper)
    mounted = set(mounted_letters(rows))
    return [letter for letter in wanted if letter not in mounted]


def mounts_ready(
    rows: list[dict[str, Any]] | None = None,
    helper: dict[str, Any] | None = None,
) -> bool:
    """True when Docker already has at least one usable /host/<letter>.

    Extra Windows letters (USB, DVD, unused volumes) must not keep Drive Mount
    running or remount the stack. List Folder can pick G: from the letters that
    are already visible. ``helper`` is kept for callers; it is not a gate.
    """
    rows = rows if rows is not None else inspect_host_letters()
    _ = helper
    return bool(mounted_letters(rows))


def _wait_until_readable(required_path: str, *, timeout_sec: float) -> dict[str, Any]:
    """Return as soon as Docker can read the folder, without waiting for other stacks."""
    deadline = time.time() + max(float(timeout_sec), 8.0)
    last: dict[str, Any] = {}
    while time.time() < deadline:
        if path_is_readable(required_path):
            return {
                "status": "done",
                "ok": True,
                "required_path": required_path,
                "message": f"Selected path is already readable: {required_path}",
            }
        last = wait_for_refresh(timeout_sec=2.0)
        status = str(last.get("status") or "").lower()
        if status in ("done", "error"):
            return last
        if status in ("idle", "offline") and not last.get("busy") and not last.get("timed_out"):
            return last
    if path_is_readable(required_path):
        return {
            "status": "done",
            "ok": True,
            "required_path": required_path,
            "message": f"Selected path is already readable: {required_path}",
        }
    last["timed_out"] = True
    return last


def _refresh_covers_path(waited: dict[str, Any], required_path: str) -> bool:
    """True when the finished helper job was for this exact Windows folder."""
    wanted = required_path.replace("/", "\\").rstrip("\\").lower()
    covered = str(waited.get("required_path") or "").replace("/", "\\").rstrip("\\").lower()
    if covered and covered == wanted:
        return True
    message = str(waited.get("message") or "").replace("/", "\\").lower()
    return bool(wanted and wanted in message)


def _required_path_for_missing(missing: list[str]) -> str | None:
    if not missing:
        return None
    return f"{missing[0]}:\\"


_WINDOWS_LETTER_RE = re.compile(r"^([A-Za-z]):")


def windows_letter_from_path(path: str | None) -> str | None:
    match = _WINDOWS_LETTER_RE.match((path or "").strip())
    if not match:
        return None
    return match.group(1).upper()


def docker_path_for_windows(required_path: str) -> Path | None:
    """Map ``G:\\DISK2\\folder`` onto ``/host/g/DISK2/folder`` inside Docker."""
    match = re.match(r"^([A-Za-z]):[/\\]?(.*)$", (required_path or "").strip())
    if not match:
        return None
    letter = match.group(1).lower()
    rest = match.group(2).replace("\\", "/").strip("/")
    base = _host_mount_prefix() / letter
    return (base / rest) if rest else base


# The HostDrive Windows helper sees actual physical/removable volumes, while
# Docker Desktop may retain a stale /host/<letter> directory after a USB disk
# is unplugged and a different volume receives the same letter. Before using a
# selected evidence folder, compare bounded filename/size metadata across the
# two independently accessed views. Never open an evidence file for writing.
_EVIDENCE_FILENAME = re.compile(
    r"(?i)\.(?:e[0-9a-z]{2}|ex[0-9a-z]{2}|s\d{2}|\d{3}|dd|raw|img|aff4?|vmdk|vhdx?|qcow2?|zip)$"
)


def source_media_matches(required_path: str) -> bool:
    """Check that the mounted folder corresponds to the Windows source.

    On a host without the helper, rely on the local Docker path. On a host
    where the helper can enumerate the selected folder, reject stale/swapped
    mounts and size mismatches. The final image hashes are verified separately
    by the forensic pipeline; this is an early source identity check.
    """
    path = docker_path_for_windows(required_path)
    if path is None:
        return False
    try:
        from app.services.hostdrive_agent import lookup_exact_path

        host = lookup_exact_path(required_path)
    except Exception:
        host = None
    if not host or not host.get("ok"):
        # The helper might not be installed on single-container/Linux setups.
        # Do not mistake helper downtime for definitive evidence loss.
        return True

    actual = follow_host_junction(path)
    try:
        directory = actual.parent if actual.is_file() else actual
        if not directory.is_dir():
            return False
        # Windows is case-insensitive while Linux may present names with
        # different case. Only inspect metadata, never content during probing.
        local = {e.name.casefold(): e for e in directory.iterdir()}
    except (OSError, PermissionError):
        return False

    entries = [e for e in host.get("entries", ()) if isinstance(e, dict)]
    evidence = [e for e in entries if e.get("kind") == "file"
                and _EVIDENCE_FILENAME.search(str(e.get("name") or ""))]
    # When the examiner selected a parent directory instead of a segment
    # directory, still compare a small deterministic set of entries.
    sample = sorted(evidence if evidence else entries,
                    key=lambda e: str(e.get("name") or "").casefold())
    # Check the first *and last* source segments. EWF images may contain more
    # than 64 segments, so testing only the first set could miss a replacement
    # or disconnected later segment of the same evidence family.
    if len(sample) > 64:
        sample = sample[:32] + sample[-32:]
    for row in sample:
        name = str(row.get("name") or "")
        if not name or name in (".", "..") or "/" in name or "\\" in name:
            return False
        item = local.get(name.casefold())
        if item is None:
            log.warning("Windows/Docker source mismatch: missing selected-media entry %s on %s", name, required_path)
            return False
        try:
            is_dir = row.get("kind") == "dir"
            if is_dir != item.is_dir():
                return False
            if not is_dir and row.get("size_bytes") is not None:
                if item.stat().st_size != int(row["size_bytes"]):
                    log.warning("Windows/Docker source mismatch: length changed for %s on %s", name, required_path)
                    return False
        except (OSError, ValueError, TypeError):
            return False
    return True


def selected_media_readable(required_path: str) -> bool:
    """A Windows file/folder is ready only if the actual media matches."""
    return path_is_readable(required_path) and source_media_matches(required_path)


def path_is_readable(required_path: str) -> bool:
    """True when Docker can actually list/stat the selected Windows path."""
    p = docker_path_for_windows(required_path)
    if p is None:
        return False
    p = follow_host_junction(p)
    try:
        if p.is_file():
            return True
        if not _safe_is_dir(p):
            return False
        if _is_stale_host_mount(p):
            return False
        next(p.iterdir(), None)
        return True
    except OSError:
        return False


def _result(
    *,
    ok: bool,
    helper: dict[str, Any],
    wanted: list[str],
    after: list[dict[str, Any]],
    refresh: dict[str, Any],
    waited: dict[str, Any],
    skipped_refresh: bool = False,
    required_path: str | None = None,
    path_ready: bool | None = None,
) -> dict[str, Any]:
    ready = mounted_letters(after)
    stale = [str(r["letter"]).upper() for r in after if r.get("exists") and r.get("stale")]
    missing = missing_windows_letters(helper, after) if helper.get("ok") else []
    if ok:
        message = (
            f"Drive Mount Agent: Windows attached {', '.join(wanted) or 'none'}; "
            f"Docker mounted {', '.join(ready) or 'none'}"
        )
        if skipped_refresh:
            message += " (already mounted — no remount)"
    elif missing:
        message = (
            "Drive Mount Agent: Windows has "
            f"{', '.join(wanted)} but Docker is missing {', '.join(missing)}. "
            + (helper.get("start_hint") or "Start scripts\\ensure-host-drive-helper.ps1")
        )
    else:
        message = (
            "Drive Mount Agent: no usable /host/<letter> yet. "
            + (helper.get("start_hint") or "Start scripts\\ensure-host-drive-helper.ps1")
        )
    if stale and missing:
        message += f" Empty stubs: {', '.join(stale)}"
    return {
        "ok": ok,
        "agent": "drive_mount_agent",
        "mounted": ready,
        "drives": wanted or ready,
        "windows_letters": wanted,
        "missing": missing,
        "stale": stale,
        "helper_online": bool(helper.get("ok")),
        "helper_drives": wanted,
        "helper_url": helper.get("helper_url"),
        "skipped_refresh": skipped_refresh,
        "required_path": required_path,
        "required_letter": windows_letter_from_path(required_path),
        "path_ready": bool(path_ready) if path_ready is not None else (ok and not required_path),
        "refresh": {
            "ok": refresh.get("ok"),
            "started": refresh.get("started"),
            "message": refresh.get("message"),
            "error": refresh.get("error"),
            "status": waited.get("status"),
        },
        "inspect": [
            r
            for r in after
            if r.get("exists") or r.get("letter") in {x.lower() for x in wanted}
        ],
        "message": message,
        "start_hint": helper.get("start_hint"),
    }


def ensure_path_mounted(required_path: str, *, wait_sec: float = 90.0) -> dict[str, Any]:
    """Remount the selected Windows letter until Docker can list that path.

    Drive Mount (any letter) can be 100% while G: is a stale stub. Call this
    when the examiner picks a folder so the evidence letter itself is healed.
    """
    raw = (required_path or "").strip()
    if not raw:
        return {
            "ok": False,
            "path_ready": False,
            "mounted": mounted_letters(),
            "message": "No path specified",
            "agent": "drive_mount_agent",
            "skipped_refresh": True,
        }

    helper = probe_helper()
    before = inspect_host_letters()
    wanted = windows_attached_letters(helper) if helper.get("ok") else []
    letter = windows_letter_from_path(raw)
    refresh: dict[str, Any] = {}
    waited: dict[str, Any] = {}

    if selected_media_readable(raw):
        result = _result(
            ok=True,
            helper=helper,
            wanted=wanted or mounted_letters(before),
            after=before,
            refresh=refresh,
            waited=waited,
            skipped_refresh=True,
            required_path=raw,
            path_ready=True,
        )
        log.info("ensure_path skip remount path=%s letter=%s", raw, letter)
        return result

    # Do not trust a mounted drive letter as proof that the selected evidence is
    # readable. Removable media can be swapped while /host/g remains a valid but
    # stale bind. The exact selected path is the authority; if it is unreadable,
    # ask the Windows HostDrive refresh job to resolve/remount that path.
    refresh = proxy_refresh_mounts(required_path=raw)
    budget = min(max(float(wait_sec), 8.0), 180.0)
    if selected_media_readable(raw):
        waited = {"status": "done", "ok": True, "required_path": raw, "message": "Selected path is already readable"}
    elif refresh.get("joined_existing"):
        waited = _wait_until_readable(raw, timeout_sec=budget)
        covered = _refresh_covers_path(waited, raw)
        if not selected_media_readable(raw) and not covered:
            # The in-flight job was a general drive scan. It does not mount the
            # folder the examiner just selected. Start that mount now.
            refresh = proxy_refresh_mounts(required_path=raw)
            waited = {}
    if not selected_media_readable(raw) and (refresh.get("started") or refresh.get("ok")):
        waited = _wait_until_readable(raw, timeout_sec=budget)
    deadline = time.time() + max(float(wait_sec), 8.0)
    after = before
    refresh_failed = str(waited.get("status") or "").lower() == "error" or waited.get("ok") is False
    while time.time() < deadline:
        after = inspect_host_letters()
        if selected_media_readable(raw):
            break
        if refresh_failed or (refresh.get("ok") is False and not refresh.get("started")):
            break
        time.sleep(2.0)

    after = inspect_host_letters()
    ready_path = selected_media_readable(raw)
    letter_ok = bool(letter and letter in mounted_letters(after))
    result = _result(
        ok=bool(ready_path or letter_ok),
        helper=helper,
        wanted=wanted or mounted_letters(after),
        after=after,
        refresh=refresh,
        waited=waited,
        required_path=raw,
        path_ready=ready_path,
    )
    if not ready_path:
        result["ok"] = False
        loc = (letter or "?").lower()
        refresh_detail = str(
            waited.get("error")
            or waited.get("message")
            or refresh.get("error")
            or refresh.get("message")
            or ""
        ).strip()
        result["refresh_error"] = refresh_detail or None
        result["message"] = (
            f"Windows can see {raw}, but Docker cannot read the same selected media "
            f"(missing, stale or mismatched /host/{loc})."
        )
        if refresh_detail:
            result["message"] += f" Mount recovery detail: {refresh_detail}"
        else:
            result["message"] += " HostDrive remount did not make the selected path readable."
    log.info(
        "ensure_path path=%s letter=%s readable=%s mounted=%s missing=%s",
        raw,
        letter,
        ready_path,
        result.get("mounted"),
        result.get("missing"),
    )
    return result


def ensure_all_drives_mounted(
    *,
    wait_sec: float = 180.0,
    required_path: str | None = None,
    sync_attached: bool = False,
) -> dict[str, Any]:
    """Remount Windows letters into Docker.

    Default (pipeline huddle): skip when any ``/host/<letter>`` is already
    usable so extract is not interrupted by an unused USB volume.

    *sync_attached=True* (Create job / folder picker): remount when Windows has
    letters Docker cannot read yet (newly attached evidence disks).

    When *required_path* is set, remount that evidence letter even if C:–F:
    are already healthy.
    """
    if required_path and str(required_path).strip():
        return ensure_path_mounted(str(required_path).strip(), wait_sec=wait_sec)

    helper = probe_helper()
    before = inspect_host_letters()
    wanted = windows_attached_letters(helper) if helper.get("ok") else []
    ready = mounted_letters(before)
    missing = missing_windows_letters(helper, before) if helper.get("ok") else []
    refresh: dict[str, Any] = {}
    waited: dict[str, Any] = {}
    need_refresh = bool(missing) if sync_attached else not ready

    if not need_refresh and ready:
        if not wanted:
            wanted = ready
        result = _result(
            ok=True,
            helper=helper,
            wanted=wanted,
            after=before,
            refresh=refresh,
            waited=waited,
            skipped_refresh=True,
        )
        result["newly_attached"] = missing
        log.info(
            "drive_mount skip remount windows=%s mounted=%s missing=%s sync=%s",
            wanted,
            ready,
            missing,
            sync_attached,
        )
        return result

    refresh = proxy_refresh_mounts(
        required_path=_required_path_for_missing(missing[:1] if missing else wanted[:1] if wanted else [])
    )
    if refresh.get("started") or refresh.get("ok"):
        waited = wait_for_refresh(timeout_sec=min(max(float(wait_sec), 8.0), 180.0))
    deadline = time.time() + max(float(wait_sec), 8.0)
    after = before
    while time.time() < deadline:
        after = inspect_host_letters()
        if sync_attached:
            still_missing = missing_windows_letters(helper, after) if helper.get("ok") else []
            if not still_missing and mounted_letters(after):
                break
        elif mounted_letters(after):
            break
        if refresh.get("ok") is False and not refresh.get("started"):
            break
        time.sleep(2.0)

    after = inspect_host_letters()
    ready = mounted_letters(after)
    result = _result(
        ok=bool(ready),
        helper=helper,
        wanted=wanted or ready,
        after=after,
        refresh=refresh,
        waited=waited,
    )
    result["newly_attached"] = missing
    log.info(
        "drive_mount helper=%s windows=%s mounted=%s missing=%s skipped=%s sync=%s",
        helper.get("ok"),
        wanted,
        ready,
        result.get("missing"),
        False,
        sync_attached,
    )
    return result
