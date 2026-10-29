"""Read-only view of OpenVAS's own log for one host (V1.6.8, reader rewritten in V1.9.2).

With ``log_whole_attack = yes`` in openvas.conf (written by the
configure-openvas service), openvas-scanner logs, per check (NVT), all at
MESSAGE level (g_message):

    Vulnerability scan <id> started for host: <ip>                 (attack.c, always)
    Launching <file> (<oid>) against <ip> [<pid>]                  (attack.c)
    <file> (<oid>) [<pid>] finished its job in <s> seconds         (pluginlaunch.c)
    <oid> (pid <pid>) is slow to finish - killing it               (pluginlaunch.c)
    Vulnerability scan <id> finished for host <ip> in <s> seconds  (attack.c, always)

Finish/kill lines carry no IP, so they are matched to a host by PID.

V1.9.2: the old reader parsed only the last 8 MB. The stock Greenbone compose
raises openvas_log.conf to DEBUG (level 128), and the SSL/TLS cipher checks
that run in a host's last 2 % then write tens of thousands of libgvm
``Key '...' already contained integer`` lines per second. The 8 MB window
held nothing but those, so field jobs 320903ac, c8416cd6 and 3c4f45e0
reported "per-check logging is off" although it was on. This reader:

* follows the file incrementally (offset + anchor), reading only new bytes;
* on first use reads back up to OPENVAS_LOG_BACKFILL_MB (default 256 MB);
* drops DEBUG lines before decoding them;
* keeps per-host state from the host's ``started for host`` line on, so it
  knows when it has the host's whole history (``host_started_seen``).

Only with the whole history may a caller conclude that nothing is running.
It never changes anything.
"""
from __future__ import annotations

import os
import re
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

_OID = r"1\.3\.6\.1\.4\.1\.25623\.1\.\d+\.\d+"
_OID_RE = re.compile(_OID)
_LAUNCH_RE = re.compile(rf"Launching (?P<name>\S+) \((?P<oid>{_OID})\) against (?P<ip>\S+) \[(?P<pid>\d+)\]")
_FINISH_RE = re.compile(
    rf"(?P<name>\S+) \((?P<oid>{_OID})\) \[(?P<pid>\d+)\] finished its job in (?P<sec>[\d.]+) seconds")
_KILL_RE = re.compile(rf"(?P<oid>{_OID}) \(pid (?P<pid>\d+)\) is slow to finish - killing it")
_HOST_START_RE = re.compile(r"Vulnerability scan \S+ started for host: (?P<ip>[^\s(]+)")
_HOST_DONE_RE = re.compile(r"Vulnerability scan \S+ finished for host (?P<ip>\S+) in (?P<sec>[\d.]+) seconds")
# An IPv4 address that is not part of a longer dotted number (e.g. an OID).
_IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\d)(?!\.\d)")
_ANY_IP_B = re.compile(rb"\d\.\d{1,3}\.\d{1,3}\.\d")
# gvm/openvas log timestamps look like "2026-10-14 04h54.08 utc"
_TS_RE_B = re.compile(rb"(\d{4}-\d{2}-\d{2}) (\d{2})h(\d{2})\.(\d{2})")

_CHUNK = 4 * 1024 * 1024
_ANCHOR = 64
_MAX_HOSTS = 2048
_MAX_CONTEXT_IPS = 4096
_LOCK = threading.Lock()
_STATE: dict[str, Any] = {}


def _log_path() -> Path:
    return Path(os.environ.get("OPENVAS_LOG_FILE") or "/var/log/openvas/openvas.log")


def _backfill_bytes() -> int:
    try:
        mb = int(os.environ.get("OPENVAS_LOG_BACKFILL_MB") or 256)
    except (TypeError, ValueError):
        mb = 256
    return max(1, min(4096, mb)) * 1024 * 1024


def reset() -> None:
    """Forget everything read so far (tests; a rotated log is detected automatically)."""
    with _LOCK:
        _STATE.clear()


def _fresh(path: Path, inode: tuple[int, int]) -> None:
    _STATE.clear()
    _STATE.update(path=str(path), inode=inode, offset=0, anchor=b"", carry=b"", skip_partial=False,
                  window_start=0, hosts={}, pid_host={}, context={}, last_ts=None, whole=False,
                  debug_lines=0, lines_read=0)


def _new_host() -> dict[str, Any]:
    return {"start_seen": False, "started": None, "finished": False, "seconds": None, "running": {},
            "slow": [], "killed": [], "launches": 0}


def _host(ip: str) -> dict[str, Any]:
    hosts = _STATE["hosts"]
    h = hosts.get(ip)
    if h is None:
        if len(hosts) >= _MAX_HOSTS:  # drop the oldest idle host
            for key in list(hosts):
                if not hosts[key]["running"]:
                    hosts.pop(key, None)
                    break
        h = hosts[ip] = _new_host()
    return h


def _context(ip: str, line: str) -> None:
    ctx = _STATE["context"]
    dq = ctx.get(ip)
    if dq is None:
        if len(ctx) >= _MAX_CONTEXT_IPS:
            ctx.pop(next(iter(ctx)), None)
        dq = ctx[ip] = deque(maxlen=15)
    dq.append(line.strip()[:400])


def _ingest(raw: bytes) -> None:
    _STATE["lines_read"] += 1
    if raw.find(b"DEBUG:", 0, 64) != -1:  # libgvm/openvas debug output: never needed here
        _STATE["debug_lines"] += 1
        return
    stamp = _advance_clock(raw)
    has_launch = b"Launching " in raw
    has_finish = b"finished its job" in raw
    has_kill = b"slow to finish" in raw
    has_host = b"Vulnerability scan " in raw
    if not (has_launch or has_finish or has_kill or has_host) and not _ANY_IP_B.search(raw):
        return
    line = raw.decode("utf-8", errors="replace")
    if has_launch:
        m = _LAUNCH_RE.search(line)
        if m:
            _STATE["whole"] = True
            ip, pid = m.group("ip"), m.group("pid")
            h = _host(ip)
            h["launches"] += 1
            h["running"][pid] = {"oid": m.group("oid"), "name": m.group("name"), "pid": int(pid), "started": stamp}
            _STATE["pid_host"][pid] = ip
            _context(ip, line)
            return
    if has_finish:
        m = _FINISH_RE.search(line)
        if m:
            ip = _STATE["pid_host"].pop(m.group("pid"), None)
            if ip and ip in _STATE["hosts"]:
                h = _STATE["hosts"][ip]
                h["running"].pop(m.group("pid"), None)
                sec = float(m.group("sec"))
                if sec >= 60:
                    h["slow"].append({"oid": m.group("oid"), "name": m.group("name"), "seconds": round(sec, 1)})
                    del h["slow"][:-50]
            return
    if has_kill:
        m = _KILL_RE.search(line)
        if m:
            ip = _STATE["pid_host"].pop(m.group("pid"), None)
            if ip and ip in _STATE["hosts"]:
                h = _STATE["hosts"][ip]
                item = h["running"].pop(m.group("pid"), None) or {"oid": m.group("oid")}
                h["killed"].append({"oid": m.group("oid"), "name": item.get("name")})
                del h["killed"][:-50]
            return
    if has_host:
        m = _HOST_START_RE.search(line)
        if m:
            ip = m.group("ip")
            old = _STATE["hosts"].get(ip)
            if old:
                for pid in old["running"]:
                    _STATE["pid_host"].pop(pid, None)
            h = _STATE["hosts"][ip] = _new_host()
            h.update(start_seen=True, started=stamp)
            _context(ip, line)
            return
        m = _HOST_DONE_RE.search(line)
        if m:
            ip = m.group("ip")
            h = _host(ip)
            for pid in h["running"]:
                _STATE["pid_host"].pop(pid, None)
            h["running"].clear()
            h.update(finished=True, seconds=float(m.group("sec")))
            _context(ip, line)
            return
    for ip in set(_IPV4_RE.findall(line)):
        _context(ip, line)


def _parse_ts(raw: bytes) -> datetime | None:
    m = _TS_RE_B.search(raw, 0, 96)  # the stamp sits in the line head
    if not m:
        return None
    try:
        return datetime.strptime(
            f"{m.group(1).decode()} {m.group(2).decode()}:{m.group(3).decode()}:{m.group(4).decode()}",
            "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _advance_clock(raw: bytes) -> datetime | None:
    """Parse the line's stamp and move the log clock forward; returns the line's own stamp."""
    stamp = _parse_ts(raw)
    if stamp and (_STATE["last_ts"] is None or stamp > _STATE["last_ts"]):
        _STATE["last_ts"] = stamp
    return stamp


def _anchor_ok(handle: Any) -> bool:
    anchor = _STATE.get("anchor") or b""
    if not anchor:
        return True
    handle.seek(_STATE["offset"] - len(anchor))
    return handle.read(len(anchor)) == anchor


def _refresh(path: Path) -> None:
    """Read new bytes of the log into _STATE (caller holds _LOCK)."""
    st = path.stat()
    inode = (st.st_dev, st.st_ino)
    with path.open("rb") as handle:
        if (_STATE.get("path") != str(path) or _STATE.get("inode") != inode
                or st.st_size < _STATE.get("offset", 0) or not _anchor_ok(handle)):
            _fresh(path, inode)
            start = max(0, st.st_size - _backfill_bytes())
            _STATE.update(offset=start, window_start=start, skip_partial=start > 0)
        elif st.st_size - _STATE["offset"] > 2 * _backfill_bytes():
            # A huge backlog (DEBUG flood between calls): re-window instead of
            # reading gigabytes. History is lost, so callers will wait, not stop.
            _fresh(path, inode)
            start = st.st_size - _backfill_bytes()
            _STATE.update(offset=start, window_start=start, skip_partial=True)
        end = st.st_size
        handle.seek(_STATE["offset"])
        pos = _STATE["offset"]
        while pos < end:
            chunk = handle.read(min(_CHUNK, end - pos))
            if not chunk:
                break
            pos += len(chunk)
            parts = (_STATE["carry"] + chunk).split(b"\n")
            _STATE["carry"] = parts.pop()
            if _STATE["skip_partial"] and parts:
                parts.pop(0)  # the backfill started mid-line
                _STATE["skip_partial"] = False
            for raw in parts:
                _ingest(raw)
            if parts:  # DEBUG lines are skipped unparsed; keep the clock from the chunk's last line
                _advance_clock(parts[-1])
        _STATE["offset"] = pos
        if pos:
            handle.seek(max(0, pos - _ANCHOR))
            _STATE["anchor"] = handle.read(min(_ANCHOR, pos))


def host_activity(host: str, *, max_lines: int = 15, **_legacy: Any) -> dict[str, object]:
    """Running/finished/killed checks for ``host`` from openvas.log."""
    path = _log_path()
    out: dict[str, object] = {
        "log_file": str(path), "available": False, "lines": [], "nvt_oids": [], "running": [],
        "slow_finished": [], "killed": [], "host_finished": False, "host_lines": 0,
        "whole_attack_logging": False, "host_started_seen": False, "host_launches": 0,
    }
    with _LOCK:
        try:
            _refresh(path)
        except OSError as exc:
            out["error"] = f"{exc.__class__.__name__}: {exc}"[:200]
            return out
        h = _STATE["hosts"].get(host) or _new_host()
        ctx = list(_STATE["context"].get(host) or [])
        last_ts = _STATE["last_ts"]
        read = max(1, int(_STATE["lines_read"]))
        out.update({
            "available": True,
            "whole_attack_logging": bool(_STATE["whole"]),
            "host_started_seen": bool(h["start_seen"]),
            "host_launches": int(h["launches"]),
            "debug_lines": int(_STATE["debug_lines"]),
            "debug_share": round(_STATE["debug_lines"] / read, 3),
            "window_start": int(_STATE["window_start"]),
            "log_bytes": int(_STATE["offset"]),
        })
        running = [dict(r) for r in h["running"].values()]
        slow = sorted(h["slow"], key=lambda r: -float(r["seconds"]))[:10]
        killed = list(h["killed"][-10:])
        finished, seconds = h["finished"], h["seconds"]
    run_list = []
    for item in running:
        started = item.get("started")
        age = int((last_ts - started).total_seconds()) if isinstance(started, datetime) and last_ts else None
        run_list.append({"oid": item["oid"], "name": item["name"], "pid": item["pid"], "running_sec": age})
    run_list.sort(key=lambda r: -(r["running_sec"] or 0))
    oids: list[str] = []
    for line in ctx[-max_lines:]:
        for oid in _OID_RE.findall(line):
            if oid not in oids:
                oids.append(oid)
    for item in run_list:
        if item["oid"] not in oids:
            oids.insert(0, str(item["oid"]))
    out.update({
        "lines": ctx[-max_lines:],
        "nvt_oids": oids,
        "running": run_list[:20],
        "slow_finished": slow,
        "killed": killed,
        "host_lines": len(ctx),
        "host_finished": bool(finished),
    })
    if finished and seconds is not None:
        out["host_scan_seconds"] = seconds
    return out


# V1.9.5: configure-openvas is a one-shot container; a plain "docker compose up -d"
# does not re-run it once it has exited, so its files keep their old values.
# OpenVAS starts a fresh process for every scan and reads both files then.
_RERUN = "docker compose up -d --force-recreate configure-openvas (takes effect from the next scan)"
FIX_WHOLE_ATTACK = f"Set OPENVAS_LOG_WHOLE_ATTACK=yes in .env, then: {_RERUN}."
FIX_LOG_LEVEL = f"Set OPENVAS_LOG_LEVEL=127 in .env, then: {_RERUN}."


def setup_warnings(health: dict[str, object]) -> list[str]:
    """Problems in the OpenVAS logging setup, read from openvas.log itself (V1.9.5).

    Both settings live in files written by configure-openvas; the agent cannot
    read those files, but their effect is visible in the log.
    """
    out: list[str] = []
    if not health.get("available"):
        return out
    lines = int(health.get("lines_read") or 0)
    share = float(health.get("debug_share") or 0)
    if lines >= 1000 and share >= 0.5:
        out.append(f"openvas.log is {int(share * 100)}% DEBUG lines: OpenVAS still logs at DEBUG level, which "
                   f"buries the lines the agent needs (and may log passwords). {FIX_LOG_LEVEL}")
    if int(health.get("hosts_started") or 0) > 0 and not health.get("whole_attack_logging"):
        out.append("OpenVAS scanned hosts but logged no check launches: per-check logging is off, so a host "
                   f"waiting at 98-99% cannot be explained. {FIX_WHOLE_ATTACK} Scan configs made by agent "
                   "1.9.3 also switched it off; 1.9.5 replaces them automatically.")
    if out:
        out.append("These checks read the scans already in openvas.log; after fixing, they clear once a "
                   "new scan has run and the agent restarts.")
    return out


def log_health() -> dict[str, object]:
    """Whole-log facts for diagnostics: size, DEBUG share, whether check launches are logged."""
    path = _log_path()
    with _LOCK:
        try:
            _refresh(path)
        except OSError as exc:
            return {"available": False, "log_file": str(path), "error": f"{exc.__class__.__name__}: {exc}"[:200]}
        read = max(1, int(_STATE["lines_read"]))
        hosts = _STATE["hosts"]
        return {"available": True, "log_file": str(path), "bytes": int(_STATE["offset"]),
                "window_start": int(_STATE["window_start"]), "lines_read": int(_STATE["lines_read"]),
                "debug_share": round(_STATE["debug_lines"] / read, 3),
                "whole_attack_logging": bool(_STATE["whole"]),
                "hosts_started": sum(1 for h in hosts.values() if h["start_seen"]),
                "checks_running": sum(len(h["running"]) for h in hosts.values())}


def describe(activity: dict[str, object]) -> str:
    """One-line human summary for logs."""
    if not activity.get("available"):
        return f"OpenVAS log unavailable ({activity.get('error') or 'not mounted'})"
    if activity.get("host_finished"):
        return (f"OpenVAS finished this host in {int(float(activity.get('host_scan_seconds') or 0))}s; "
                "Greenbone is still processing the report")
    running = activity.get("running") or []
    if running:
        parts = [f"{r['name']} ({r['oid']})" + (f" for {r['running_sec']}s" if r.get("running_sec") is not None else "")
                 for r in running[:5]]
        return f"{len(running)} check(s) still running in OpenVAS: " + "; ".join(parts)
    if activity.get("host_started_seen") and not activity.get("whole_attack_logging"):
        msg = ("OpenVAS per-check logging is off: the host's scan is in openvas.log but no check launches "
               f"are logged. {FIX_WHOLE_ATTACK}")
        if float(activity.get("debug_share") or 0) >= 0.5:
            msg += f" openvas.log is also {int(float(activity['debug_share']) * 100)}% DEBUG lines. {FIX_LOG_LEVEL}"
        return msg
    if not activity.get("host_started_seen"):
        why = "this host's scan started before the part of openvas.log the agent has read"
        if float(activity.get("debug_share") or 0) >= 0.5:
            why += (f" (openvas.log is {int(float(activity['debug_share']) * 100)}% DEBUG lines. "
                    f"{FIX_LOG_LEVEL})")
        return f"Cannot see this host's running checks: {why}"
    return "OpenVAS shows no running checks and has not finished this host"
