"""Scan the scanner laptop itself without being blocked by its own firewall (V1.8.0).

Why this exists
---------------
The portable scanner runs Greenbone inside Docker Desktop. When an authorized
target is the laptop's own Wi-Fi/LAN address (field job e158c5dc: 172.20.10.2 on
an iPhone hotspot), Windows treats the container traffic as inbound network
traffic. On a Public network profile the firewall drops every port, so the scan
finishes with "no exposed services" and nothing above Informational.

Docker Desktop forwards connections to ``host.docker.internal`` to the host's
loopback interface, which the Windows firewall does not filter. Scanning that
address instead gives the *local* view of the laptop: every service that is
listening, and the vulnerabilities in it. This is the same inside-out view an
endpoint agent (for example the Rapid7 Insight Agent) gives.

Safety rules
------------
* Only an explicitly authorized target IP that is one of the scanner host's own
  addresses is rerouted. Host addresses come from the host-side
  ``.lan-fingerprint`` file (written every 10 s by Write-LanFingerprint.ps1),
  which must be fresh, or from ``SCANNER_HOST_IPS``. A stale file is ignored so
  a client device that later gets the laptop's old address is never confused
  with the laptop.
* Results are always reported under the original target IP and are labelled
  ``self_scan`` with the network-exposure evidence kept separately.
* ``SELF_SCAN_MODE=off`` disables the whole feature.
* V1.9.1: a fingerprint without ``host_ips`` (stale pre-1.8.0 writer racing the
  current one) is re-read for up to SELF_SCAN_FINGERPRINT_WAIT_SEC; the reason
  is always reported in the ``self_target_check`` event, never dropped.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("scanner_agent.self_target")

DEFAULT_ALIAS_NAME = "host.docker.internal"
_ALIAS_STORE_ENV = "SELF_SCAN_ALIAS_STORE"
_DEFAULT_ALIAS_STORE = "/app/logs/self_target_aliases.json"
_lock = threading.Lock()


def mode() -> str:
    raw = (os.environ.get("SELF_SCAN_MODE") or "auto").strip().lower()
    return "off" if raw in {"off", "0", "false", "no", "disabled"} else "auto"


def _max_age_sec() -> float:
    try:
        return max(30.0, float(os.environ.get("SELF_SCAN_FINGERPRINT_MAX_AGE_SEC") or 300))
    except (TypeError, ValueError):
        return 300.0


def _canonical(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
        return None
    return str(parsed)


def _fingerprint_paths() -> list[Path]:
    from agent.lan_fingerprint import FINGERPRINT_PATHS

    return list(FINGERPRINT_PATHS)


def _wait_sec() -> float:
    """How long to wait for a fingerprint that carries host_ips (V1.9.1)."""
    try:
        return max(0.0, min(60.0, float(os.environ.get("SELF_SCAN_FINGERPRINT_WAIT_SEC") or 25)))
    except (TypeError, ValueError):
        return 25.0


# V1.9.1: field jobs 320903ac and 64b549f1 scanned the laptop through its own
# firewall (149 of 154 ports "no answer") because the fingerprint they read had
# no host_ips. A pre-V1.8.0 Write-LanFingerprint loop, started by an earlier
# Start-Laptop run, was still overwriting the file every 10 s without that key,
# racing the current writer. The read below retries briefly so the current
# writer's next write is seen, and a short negative cache keeps a many-IP job
# from waiting on every chunk.
_NEGATIVE_CACHE_SEC = 120.0
_negative: dict[str, Any] = {"until": 0.0, "result": None}


def _read_fingerprint(now: float) -> dict[str, Any]:
    """One pass over the fingerprint files. Adds "retry": True for conditions a rewrite can fix."""
    saw_file = False
    for path in _fingerprint_paths():
        try:
            if not path.is_file():
                continue
            saw_file = True
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            # Usually a read that landed mid-write; the writer rewrites in place.
            return {"ips": set(), "source": f"file:{path.name}", "reason": "fingerprint unreadable (mid-write?)",
                    "retry": True}
        if not isinstance(raw, dict):
            continue
        try:
            age = now - path.stat().st_mtime
        except OSError:
            age = float("inf")
        if age > _max_age_sec():
            return {"ips": set(), "source": f"file:{path.name}",
                    "reason": f"fingerprint is {int(age)} s old; host addresses not trusted "
                              "(is the Write-LanFingerprint loop running?)"}
        if "host_ips" not in raw:
            return {"ips": set(), "source": f"file:{path.name}", "retry": True, "legacy_writer": True,
                    "reason": "fingerprint has no host_ips key: a pre-1.8.0 Write-LanFingerprint loop is still "
                              "running; run Start-Laptop.cmd again (it stops stale writers)"}
        listed = raw.get("host_ips") or []
        if isinstance(listed, str):  # PowerShell can collapse a one-item array
            listed = [part for part in listed.replace(";", ",").split(",")]
        ips = {ip for ip in (_canonical(x) for x in listed) if ip}
        if not ips:
            return {"ips": set(), "source": f"file:{path.name}",
                    "reason": "fingerprint lists no usable host addresses"}
        return {"ips": ips, "source": f"file:{path.name}", "reason": "fresh host fingerprint"}
    if saw_file:
        return {"ips": set(), "source": "none", "reason": "fingerprint file is not a JSON object"}
    return {"ips": set(), "source": "none", "reason": "no host fingerprint file"}


def scanner_host_ips(*, now: float | None = None, wait_sec: float | None = None) -> dict[str, Any]:
    """Return {"ips": set[str], "source": str, "reason": str} for the scanner host.

    Explicit SCANNER_HOST_IPS wins. Otherwise the host-side fingerprint file is
    used only when it carries ``host_ips`` and was written recently. A missing
    host_ips key or an unreadable file is retried for up to
    SELF_SCAN_FINGERPRINT_WAIT_SEC, because a current writer may be racing a
    stale one. A stale file is never trusted.
    """
    explicit = [ip for ip in (_canonical(x) for x in (os.environ.get("SCANNER_HOST_IPS") or "").split(",")) if ip]
    if explicit:
        return {"ips": set(explicit), "source": "env:SCANNER_HOST_IPS", "reason": "configured"}
    fixed_now = now is not None
    clock = (lambda: now) if fixed_now else time.time
    result = _read_fingerprint(clock())
    if not result.get("retry"):
        return _public(result)
    with _lock:
        cached = _negative.get("result")
        if cached is not None and time.monotonic() < float(_negative.get("until") or 0.0):
            return _public(dict(cached))
    budget = _wait_sec() if wait_sec is None else max(0.0, float(wait_sec))
    deadline = time.monotonic() + budget
    while result.get("retry") and time.monotonic() < deadline:
        time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
        result = _read_fingerprint(clock())
    if result.get("retry"):
        result["reason"] = f"{result['reason']} (still after {int(budget)} s)"
        with _lock:
            _negative.update({"until": time.monotonic() + _NEGATIVE_CACHE_SEC, "result": dict(result)})
    return _public(result)


def _public(result: dict[str, Any]) -> dict[str, Any]:
    out = {"ips": set(result.get("ips") or set()), "source": result.get("source", ""),
           "reason": result.get("reason", "")}
    if result.get("legacy_writer"):
        out["legacy_writer"] = True
    return out


def reset_cache() -> None:
    """Forget the negative fingerprint cache (tests, and after a writer restart)."""
    with _lock:
        _negative.update({"until": 0.0, "result": None})


def loopback_address() -> str | None:
    """IP that reaches the scanner host's loopback from inside Docker."""
    explicit = (os.environ.get("SELF_SCAN_ADDRESS") or "").strip()
    if explicit:
        try:
            return str(ipaddress.ip_address(explicit))
        except ValueError:
            log.warning("Ignoring invalid SELF_SCAN_ADDRESS=%r", explicit)
            return None
    name = (os.environ.get("SELF_SCAN_ALIAS_NAME") or DEFAULT_ALIAS_NAME).strip()
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    for info in infos:
        addr = str(info[4][0])
        if _canonical(addr):
            return addr
    return None


def plan_self_targets(targets: list[str]) -> dict[str, Any]:
    """Decide which targets are the scanner host and where to scan them.

    Returns {"aliases": {target: loopback_ip}, "host_ips": [...], "source": ..., "reason": ...}.
    """
    out: dict[str, Any] = {"aliases": {}, "host_ips": [], "source": "", "reason": "", "undetermined": False}
    if mode() == "off":
        out["reason"] = "SELF_SCAN_MODE=off"
        return out
    info = scanner_host_ips()
    out["host_ips"] = sorted(info["ips"])
    out["source"] = info["source"]
    out["reason"] = info["reason"]
    out["legacy_writer"] = bool(info.get("legacy_writer"))
    # V1.9.1: True when the scanner could not tell whether a target is itself,
    # so the caller can record why the network path was used.
    out["undetermined"] = not info["ips"]
    own = [t for t in targets if _canonical(t) in info["ips"]]
    if not own:
        return out
    alias = loopback_address()
    if not alias:
        out["reason"] = (
            f"target(s) {own} are this scanner's own address, but {DEFAULT_ALIAS_NAME} does not resolve; "
            "scanning through the network path (the host firewall applies)"
        )
        return out
    if alias in {(_canonical(t) or "") for t in targets}:
        out["reason"] = "loopback alias is itself a requested target; not rerouting"
        return out
    out["aliases"] = {t: alias for t in own}
    return out


def looks_like_accept_all(states: dict[str, Any] | None, *, minimum: int = 20, ratio: float = 0.9) -> bool:
    """True when a probe saw almost every port open: a proxy, not real listeners."""
    if not isinstance(states, dict):
        return False
    opened = len(states.get("open") or [])
    total = opened + len(states.get("closed") or []) + len(states.get("filtered") or [])
    return total >= minimum and opened >= ratio * total


def remap(value: Any, mapping: dict[str, str]) -> Any:
    """Replace exact string values and dict keys (alias -> original target).

    Only whole-value matches change, so free text (plugin output) is untouched.
    """
    if not mapping:
        return value
    if isinstance(value, dict):
        return {(mapping.get(k, k) if isinstance(k, str) else k): remap(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [remap(v, mapping) for v in value]
    if isinstance(value, tuple):
        return tuple(remap(v, mapping) for v in value)
    if isinstance(value, str):
        return mapping.get(value, value)
    return value


class AliasStore:
    """task_id -> {scan_address: original_target}, persisted across agent restarts."""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path or os.environ.get(_ALIAS_STORE_ENV) or _DEFAULT_ALIAS_STORE)
        self._data: dict[str, dict[str, str]] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data = {
                    str(k): {str(a): str(b) for a, b in v.items()}
                    for k, v in raw.items() if isinstance(v, dict)
                }
        except FileNotFoundError:
            pass
        except Exception:
            log.warning("Could not read %s; self-scan aliases start empty", self.path, exc_info=True)

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            items = list(self._data.items())[-500:]
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(dict(items)), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception:
            log.warning("Could not persist self-scan aliases to %s", self.path, exc_info=True)

    def put(self, task_id: str, scan_to_target: dict[str, str]) -> None:
        if not task_id or not scan_to_target:
            return
        with _lock:
            self._load()
            self._data[str(task_id)] = dict(scan_to_target)
            self._save()

    def get(self, task_id: str) -> dict[str, str]:
        with _lock:
            self._load()
            return dict(self._data.get(str(task_id)) or {})


def annotate_self_scan(details: dict[str, Any], host: str, info: dict[str, Any]) -> dict[str, Any]:
    """Label a finished self-scan and keep the network-exposure evidence separate."""
    evidence = details.setdefault("evidence", {})
    coverages = evidence.setdefault("host_coverage", {})
    cov = coverages.get(host)
    if not isinstance(cov, dict):
        return details
    alias = str(info.get("scanned_via") or "")
    exposure = info.get("network_exposure") if isinstance(info.get("network_exposure"), dict) else None
    block = dict(cov.get("self_scan") or {})
    block.update({"scanned_via": alias, "view": "local"})
    if exposure is not None:
        block["network_exposure"] = exposure
    cov["self_scan"] = block
    notes = list(cov.get("notes") or [])
    notes.append(
        f"{host} is the scanner laptop. It was scanned through the Docker loopback ({alias}) so its own firewall "
        "did not hide its services; findings show what is installed and listening (local view)."
    )
    if exposure is not None:
        open_ports = list(exposure.get("open") or [])
        filtered = int(exposure.get("filtered_count") or 0)
        closed = int(exposure.get("closed_count") or 0)
        if open_ports:
            notes.append(f"From the network, policy port(s) {open_ports} answer; those services are exposed to other machines.")
        else:
            notes.append(
                f"From the network, no policy port answered ({filtered} dropped, {closed} refused): the laptop's "
                "firewall currently hides these services from other machines on this network."
            )
    cov["notes"] = notes[-20:]
    return details
