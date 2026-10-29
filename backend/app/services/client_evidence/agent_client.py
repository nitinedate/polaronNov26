"""Talk to the Polaron Client Evidence Agent running on the examiner workstation.

Only fixed, token-protected endpoints are ever called.  Addresses supplied by
the browser are validated against an allow-list of LAN ranges so that the
feature cannot be used to make the server probe its own container network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import httpx

from app.services.client_evidence import DEFAULT_AGENT_PORT, ClientEvidenceError

log = logging.getLogger(__name__)

USER_AGENT = "PolaronForensicServer/1.0 (client-evidence)"
_DEFAULT_ALLOWED = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7"


# ---------------------------------------------------------------------------
# Manifest integrity
# ---------------------------------------------------------------------------

def manifest_digest(files: Iterable[dict[str, Any]]) -> str:
    """SHA-256 over ``path\\tsize\\tmtime_ms\\n`` in agent order (the agent computes the same)."""
    h = hashlib.sha256()
    for item in files:
        line = f"{item['path']}\t{int(item['size'])}\t{int(item['mtime_ms'])}\n"
        h.update(line.encode("utf-8"))
    return h.hexdigest()


def validate_manifest(manifest: dict[str, Any], *, share_id: str, expected_digest: str | None) -> dict[str, Any]:
    if not isinstance(manifest, dict) or not manifest.get("ok", True):
        raise ClientEvidenceError("The agent returned an invalid manifest")
    if str(manifest.get("share_id") or "") != share_id:
        raise ClientEvidenceError("The agent answered for a different share")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ClientEvidenceError("The agent manifest has no file list")
    for item in files:
        if not isinstance(item, dict) or "path" not in item or "size" not in item or "mtime_ms" not in item:
            raise ClientEvidenceError("The agent manifest contains a malformed file entry")
        rel = str(item["path"]).replace("\\", "/")
        if rel.startswith("/") or any(part in ("", ".", "..") for part in rel.split("/")):
            raise ClientEvidenceError(f"The agent manifest contains an unsafe path: {rel!r}")
    digest = manifest_digest(files)
    reported = str(manifest.get("manifest_sha256") or "")
    if reported and reported.lower() != digest:
        raise ClientEvidenceError("The agent manifest digest does not match its file list")
    if expected_digest and expected_digest.lower() != digest:
        raise ClientEvidenceError(
            "The evidence set on the client changed after it was selected (manifest digest mismatch). "
            "Select the folder again."
        )
    manifest["manifest_sha256"] = digest
    return manifest


# ---------------------------------------------------------------------------
# Address policy
# ---------------------------------------------------------------------------

def _allowed_networks() -> list[ipaddress._BaseNetwork]:
    raw = os.environ.get("CLIENT_EVIDENCE_ALLOWED_NETWORKS", _DEFAULT_ALLOWED)
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("ignoring invalid CLIENT_EVIDENCE_ALLOWED_NETWORKS entry %r", part)
    return nets


def _container_networks() -> list[ipaddress._BaseNetwork]:
    """Subnets this container is directly attached to (Docker bridge networks)."""
    nets: list[ipaddress._BaseNetwork] = []
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return nets
    for line in lines:
        cols = line.split()
        if len(cols) < 8:
            continue
        dest, mask = cols[1], cols[7]
        if dest == "00000000":
            continue
        try:
            d = socket.inet_ntoa(bytes.fromhex(dest)[::-1])
            m = socket.inet_ntoa(bytes.fromhex(mask)[::-1])
            nets.append(ipaddress.ip_network(f"{d}/{m}", strict=False))
        except (ValueError, OSError):
            continue
    return nets


def _explicitly_allowed(ip: ipaddress._BaseAddress, allowed: list[ipaddress._BaseNetwork]) -> bool:
    """True when an allow-list entry other than the broad defaults names this range."""
    defaults = {ipaddress.ip_network(n) for n in _DEFAULT_ALLOWED.split(",")}
    return any(ip in net and net not in defaults for net in allowed)


def address_allowed(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    allowed = _allowed_networks()
    if not any(ip in net for net in allowed):
        return False
    explicit = _explicitly_allowed(ip, allowed)
    if (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified) and not explicit:
        return False
    if not explicit and any(ip in net for net in _container_networks()):
        return False
    return True


def _resolve_host(host: str) -> list[str]:
    host = host.strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    if not host or len(host) > 253:
        return []
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def _base_url(host: str, port: int) -> str:
    ip = ipaddress.ip_address(host)
    shown = f"[{host}]" if ip.version == 6 else host
    return f"http://{shown}:{int(port)}"


def build_candidates(
    *,
    port: int = DEFAULT_AGENT_PORT,
    explicit_url: str | None = None,
    request_ip: str | None = None,
    addresses: Iterable[str] = (),
    hostname: str | None = None,
) -> tuple[list[str], list[str]]:
    """Return ``(candidate_base_urls, rejected_reasons)`` in preference order."""
    port = int(port or DEFAULT_AGENT_PORT)
    if not (1 <= port <= 65535):
        raise ClientEvidenceError("Invalid agent port")
    hosts: list[tuple[str, int]] = []
    rejected: list[str] = []

    if explicit_url:
        parts = urlsplit(explicit_url.strip())
        if parts.scheme != "http" or not parts.hostname:
            raise ClientEvidenceError("The agent address must look like http://10.0.0.25:9877")
        for ip in _resolve_host(parts.hostname):
            hosts.append((ip, parts.port or port))
    if request_ip:
        hosts.append((request_ip, port))
    for addr in addresses or ():
        for ip in _resolve_host(str(addr)):
            hosts.append((ip, port))
    if hostname:
        for ip in _resolve_host(hostname):
            hosts.append((ip, port))

    urls: list[str] = []
    for ip, p in hosts:
        if not address_allowed(ip):
            rejected.append(f"{ip} (outside the allowed client networks)")
            continue
        url = _base_url(ip, p)
        if url not in urls:
            urls.append(url)
    return urls, rejected


# ---------------------------------------------------------------------------
# HTTP calls
# ---------------------------------------------------------------------------

def _client(timeout: float = 20.0) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=min(4.0, timeout)),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        trust_env=False,
    )


def fetch_manifest(base_url: str, share_id: str, token: str, *, timeout: float = 30.0) -> dict[str, Any]:
    with _client(timeout) as client:
        resp = client.get(
            f"{base_url.rstrip('/')}/s/{share_id}/manifest",
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code == 401 or resp.status_code == 403:
        raise ClientEvidenceError("The agent refused the share token (the share may have been revoked)")
    if resp.status_code == 404:
        raise ClientEvidenceError("The agent does not know this share (it may have expired)")
    if resp.status_code != 200:
        raise ClientEvidenceError(f"The agent answered HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ClientEvidenceError("The agent returned a non-JSON manifest") from exc


def probe_health(base_url: str, *, timeout: float = 3.0) -> dict[str, Any] | None:
    try:
        with _client(timeout) as client:
            resp = client.get(f"{base_url.rstrip('/')}/health")
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError):
        return None
    return None


def revoke_share(base_url: str, share_id: str, token: str, *, timeout: float = 5.0) -> bool:
    try:
        with _client(timeout) as client:
            resp = client.delete(
                f"{base_url.rstrip('/')}/shares/{share_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        return resp.status_code in (200, 204, 404)
    except httpx.HTTPError:
        return False


def choose_reachable(
    candidates: list[str],
    *,
    share_id: str,
    token: str,
    expected_digest: str | None,
    timeout: float = 30.0,
) -> tuple[str, dict[str, Any]]:
    """Return ``(base_url, manifest)`` for the first transport that serves a valid manifest.

    Direct LAN addresses are probed first, in parallel (fastest). The outbound
    relay (``relay:``), where the agent connects to this server, is the fallback
    for PCs the server cannot reach, e.g. at home behind a router.
    """
    from app.services.client_evidence import relay

    direct = [c for c in candidates if not relay.is_relay_url(c)]
    use_relay = any(relay.is_relay_url(c) for c in candidates)
    if not direct and not use_relay:
        raise ClientEvidenceError("No usable address for the client evidence agent")
    errors: dict[str, str] = {}
    integrity_error: ClientEvidenceError | None = None
    if direct:
        try:
            return _choose_direct(direct, share_id, token, expected_digest, timeout, errors)
        except ClientEvidenceError as exc:
            if "digest" in str(exc) or "changed" in str(exc):
                integrity_error = exc
    if use_relay:
        try:
            manifest = relay.get_manifest(share_id)
            return relay.RELAY_URL, validate_manifest(manifest, share_id=share_id, expected_digest=expected_digest)
        except ClientEvidenceError as exc:
            errors["outbound connection"] = str(exc)
            if "digest" in str(exc) or "changed" in str(exc):
                integrity_error = exc
        except (relay.RelayError, ValueError) as exc:
            errors["outbound connection"] = str(exc)
    if integrity_error:
        raise integrity_error
    detail = "; ".join(f"{u}: {e}" for u, e in errors.items())
    raise ClientEvidenceError(
        "The forensic server could not reach the Client Evidence Agent on this computer, directly or through "
        "its outbound connection. Check that the agent is running and that this computer can open the Polaron "
        f"console. Tried: {detail}"
    )


def _choose_direct(
    candidates: list[str],
    share_id: str,
    token: str,
    expected_digest: str | None,
    timeout: float,
    errors: dict[str, str],
) -> tuple[str, dict[str, Any]]:
    integrity_error: ClientEvidenceError | None = None
    with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as pool:
        futures = {pool.submit(fetch_manifest, url, share_id, token, timeout=timeout): url for url in candidates}
        winner: tuple[str, dict[str, Any]] | None = None
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                manifest = validate_manifest(fut.result(), share_id=share_id, expected_digest=expected_digest)
            except ClientEvidenceError as exc:
                errors[url] = str(exc)
                if "digest" in str(exc) or "changed" in str(exc):
                    integrity_error = exc
                continue
            except httpx.ConnectTimeout:
                errors[url] = "connection timed out"
                continue
            except httpx.ConnectError:
                errors[url] = "connection refused or unreachable"
                continue
            except httpx.HTTPError as exc:
                errors[url] = type(exc).__name__
                continue
            if winner is None:
                winner = (url, manifest)
        if winner:
            return winner
    if integrity_error:
        raise integrity_error
    raise ClientEvidenceError(
        "The forensic server could not reach the Client Evidence Agent on this computer over the LAN "
        "(TCP port 9877). Tried: " + "; ".join(f"{u}: {e}" for u, e in errors.items())
    )
