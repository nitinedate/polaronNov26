"""V1.21 client-workstation evidence ("This computer" in the evidence picker).

The image stays on the examiner's computer; the Polaron Client Evidence Agent
serves read-only byte ranges and every processing container mounts them
through FUSE.  These tests cover the server half end to end without Docker,
plus the shipped agent artifacts.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHARE = "ce0123456789abcdef01234567"
JOB = "11111111-2222-3333-4444-555555555555"


# ---------------------------------------------------------------------------
# A tiny in-process stand-in for the Windows agent's server-facing endpoints
# ---------------------------------------------------------------------------

class FakeAgent:
    MTIME = 1_700_000_000_000

    def __init__(self, files: dict[str, bytes], token: str = "t" * 43, share_id: str = SHARE):
        self.files = list(files.items())
        self.token = token
        self.share_id = share_id
        self.fail_next = 0
        self.force_status: int | None = None
        self.etag_override: str | None = None
        self.requests: list[str] = []
        self.ranges: list[tuple[int, int]] = []
        self.corrupt_next = 0
        agent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep pytest output clean
                pass

            def _send(self, status: int, body: bytes = b"", headers: dict | None = None):
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                agent.requests.append(self.path)
                if agent.fail_next > 0:
                    agent.fail_next -= 1
                    return self._send(503)
                if agent.force_status:
                    return self._send(agent.force_status)
                if self.headers.get("Authorization") != f"Bearer {agent.token}":
                    return self._send(401)
                parts = self.path.split("/")
                if len(parts) < 4 or parts[2] != agent.share_id:
                    return self._send(404)
                if parts[3] == "manifest":
                    from app.services.client_evidence.agent_client import manifest_digest

                    files = [{"path": n, "size": len(d), "mtime_ms": agent.MTIME} for n, d in agent.files]
                    dirs = sorted({n.rsplit("/", 1)[0] for n, _ in agent.files if "/" in n})
                    body = {
                        "ok": True, "share_id": agent.share_id, "root": "E:\\Case-0423", "hostname": "WS-EXAM-07",
                        "files": files, "dirs": dirs, "manifest_sha256": manifest_digest(files), "truncated": False,
                    }
                    return self._send(200, json.dumps(body).encode(), {"Content-Type": "application/json"})
                idx = int(parts[4])
                name, data = agent.files[idx]
                start, end = 0, len(data) - 1
                rng = self.headers.get("Range")
                if rng:
                    a, b = rng.split("=", 1)[1].split("-")
                    start, end = int(a), min(int(b), len(data) - 1)
                etag = agent.etag_override or f'"{len(data)}-{agent.MTIME}"'
                agent.ranges.append((start, end))
                body, headers = data[start:end + 1], {"ETag": etag}
                accept = self.headers.get("X-Polaron-Accept-Encoding", "")
                if rng and "zero" in accept and body and not any(body):
                    body, headers["X-Polaron-Encoding"] = b"", "zero"
                elif rng and "deflate" in accept and len(body) >= 4096:
                    import zlib

                    c = zlib.compressobj(1, zlib.DEFLATED, -15)
                    packed = c.compress(body) + c.flush()
                    if len(packed) < len(body) * 0.9:
                        body, headers["X-Polaron-Encoding"] = packed, "deflate"
                if agent.corrupt_next and headers.get("X-Polaron-Encoding") == "deflate":
                    agent.corrupt_next -= 1
                    body = b"\x00garbage" + body[10:]
                return self._send(206 if rng else 200, body, headers)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def manifest_files(self) -> list[dict]:
        return [{"path": n, "size": len(d), "mtime_ms": self.MTIME} for n, d in self.files]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _dead_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


@pytest.fixture
def agent():
    payload = os.urandom(300_000)
    fa = FakeAgent({
        "disk.E01": payload,
        "sub/notes ü.txt": "évidence".encode(),
        # Mobile export layout: payload two folders deep.
        "05_Exports/run-1/logical.zip": b"PK\x05\x06" + b"\x00" * 18,
    })
    fa.payload = payload
    yield fa
    fa.close()


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def test_virtual_and_container_paths_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_EVIDENCE_MOUNT_ROOT", str(tmp_path / "ce"))
    from app.services.client_evidence import (
        ClientEvidenceError, is_client_evidence_path, split_client_path, to_container_path, to_virtual_path,
    )

    virtual = f"client-evidence://{SHARE}/Case 1/disk.E01"
    assert is_client_evidence_path(virtual)
    assert is_client_evidence_path(str(tmp_path / "ce" / SHARE / "x"))
    assert not is_client_evidence_path("D:\\Evidence\\disk.E01")
    assert not is_client_evidence_path(str(tmp_path / "ce-other" / SHARE))
    assert split_client_path(virtual) == (SHARE, "Case 1/disk.E01")
    container = to_container_path(virtual)
    assert container == tmp_path / "ce" / SHARE / "Case 1" / "disk.E01"
    assert to_virtual_path(container) == virtual
    with pytest.raises(ClientEvidenceError):
        split_client_path(f"client-evidence://{SHARE}/../../etc/passwd")
    with pytest.raises(ClientEvidenceError):
        split_client_path("client-evidence://not-a-share/x")


# ---------------------------------------------------------------------------
# Manifest integrity
# ---------------------------------------------------------------------------

def test_manifest_digest_matches_the_agent_format_and_rejects_tampering():
    from app.services.client_evidence import ClientEvidenceError
    from app.services.client_evidence.agent_client import manifest_digest, validate_manifest

    files = [{"path": "disk.E01", "size": 10, "mtime_ms": 5}, {"path": "sub/ü.txt", "size": 2, "mtime_ms": 6}]
    expected = hashlib.sha256("disk.E01\t10\t5\nsub/ü.txt\t2\t6\n".encode()).hexdigest()
    assert manifest_digest(files) == expected
    ok = validate_manifest({"ok": True, "share_id": SHARE, "files": files, "manifest_sha256": expected},
                           share_id=SHARE, expected_digest=expected)
    assert ok["manifest_sha256"] == expected
    with pytest.raises(ClientEvidenceError, match="changed"):
        validate_manifest({"ok": True, "share_id": SHARE, "files": files}, share_id=SHARE, expected_digest="0" * 64)
    with pytest.raises(ClientEvidenceError, match="different share"):
        validate_manifest({"ok": True, "share_id": "ce" + "f" * 24, "files": files}, share_id=SHARE, expected_digest=None)
    for bad in ("../x", "/abs", "a//b", "a/./b"):
        with pytest.raises(ClientEvidenceError, match="unsafe"):
            validate_manifest({"ok": True, "share_id": SHARE, "files": [{"path": bad, "size": 1, "mtime_ms": 1}]},
                              share_id=SHARE, expected_digest=None)


# ---------------------------------------------------------------------------
# Address policy (the server only contacts LAN agents)
# ---------------------------------------------------------------------------

def test_candidate_addresses_follow_the_lan_allow_list(monkeypatch):
    from app.services.client_evidence import agent_client

    monkeypatch.delenv("CLIENT_EVIDENCE_ALLOWED_NETWORKS", raising=False)
    monkeypatch.setattr(agent_client, "_container_networks", lambda: [__import__("ipaddress").ip_network("172.18.0.0/16")])
    urls, rejected = agent_client.build_candidates(
        port=9877, request_ip="10.20.30.41",
        addresses=["10.20.30.41", "192.168.1.7", "127.0.0.1", "169.254.1.1", "172.18.0.5", "8.8.8.8", "fd00::7"],
    )
    assert urls == ["http://10.20.30.41:9877", "http://192.168.1.7:9877", "http://[fd00::7]:9877"]
    assert len(rejected) == 4  # loopback, link-local, Docker network, public internet

    monkeypatch.setenv("CLIENT_EVIDENCE_ALLOWED_NETWORKS", "127.0.0.0/8")
    urls, _ = agent_client.build_candidates(port=9877, addresses=["127.0.0.1"])
    assert urls == ["http://127.0.0.1:9877"]  # explicit allow overrides the loopback block

    with pytest.raises(Exception, match="http://"):
        agent_client.build_candidates(explicit_url="ftp://10.0.0.1/")


def test_choose_reachable_skips_dead_addresses(agent, monkeypatch):
    from app.services.client_evidence import ClientEvidenceError, agent_client

    url, manifest = agent_client.choose_reachable(
        [_dead_url(), agent.url], share_id=SHARE, token=agent.token, expected_digest=None, timeout=5,
    )
    assert url == agent.url and len(manifest["files"]) == 3
    with pytest.raises(ClientEvidenceError, match="could not reach"):
        agent_client.choose_reachable([_dead_url()], share_id=SHARE, token=agent.token, expected_digest=None, timeout=2)
    with pytest.raises(ClientEvidenceError, match="refused the share token"):
        agent_client.fetch_manifest(agent.url, SHARE, "wrong-token" * 3)


# ---------------------------------------------------------------------------
# Remote reader (what the FUSE daemon uses for every read)
# ---------------------------------------------------------------------------

def _reader(agent, urls=None, **kw):
    from app.services.client_evidence.fusefs import RemoteReader

    kw.setdefault("block_size", 64 * 1024)
    kw.setdefault("cache_bytes", 1024 * 1024)
    kw.setdefault("retry_seconds", 5)
    return RemoteReader(share_id=SHARE, token=agent.token, base_urls=urls or [agent.url],
                        files=agent.manifest_files(), **kw)


def test_reader_returns_exact_bytes_across_block_boundaries(agent):
    r = _reader(agent, readahead_blocks=0)
    data = agent.payload
    for off, n in [(0, 10), (65_530, 20), (131_000, 70_000), (299_990, 50), (300_000, 10), (5, 0)]:
        assert r.read(0, off, n) == data[off:off + n]
    assert r.read(1, 0, 100) == "évidence".encode()
    assert r.read(2, 0, 4) == b"PK\x05\x06"
    fetched = r.blocks_fetched
    assert r.read(0, 0, 10) == data[:10]
    assert r.blocks_fetched == fetched and r.cache_hits > 0
    r.close()


def test_reader_reads_ahead_on_sequential_access(agent):
    # Read-ahead starts once reading is sustained (the run reached its maximum size).
    r = _reader(agent, readahead_blocks=3, max_run_bytes=128 * 1024)
    r.read(0, 0, 4096)
    r.read(0, 65_536, 4096)  # sequential: next blocks are prefetched in the background
    deadline = time.time() + 5
    while time.time() < deadline and r.blocks_fetched < 5:
        time.sleep(0.05)
    assert r.blocks_fetched >= 4
    r.close()


def test_reader_fails_over_to_a_second_agent_address(agent):
    r = _reader(agent, urls=[_dead_url(), agent.url], readahead_blocks=0)
    assert r.read(0, 0, 32) == agent.payload[:32]
    assert r._urls[0] == agent.url
    r.close()


def test_reader_waits_through_a_short_outage(agent):
    health = []
    r = _reader(agent, readahead_blocks=0, on_health=health.append)
    agent.fail_next = 2
    assert r.read(0, 1000, 64) == agent.payload[1000:1064]
    assert any(h["state"] == "waiting" for h in health)
    r.close()


def test_reader_gives_up_after_the_retry_window(agent):
    from app.services.client_evidence.fusefs import EvidenceReadError

    r = _reader(agent, readahead_blocks=0, retry_seconds=1)
    agent.force_status = 503
    with pytest.raises(EvidenceReadError) as err:
        r.read(0, 0, 10)
    assert not err.value.fatal and "unreachable" in err.value.strerror
    r.close()


@pytest.mark.parametrize("status,needle", [(409, "changed on the client"), (401, "revoked"), (404, "revoked")])
def test_reader_stops_for_good_when_evidence_changes_or_share_is_revoked(agent, status, needle):
    from app.services.client_evidence.fusefs import EvidenceReadError

    r = _reader(agent, readahead_blocks=0)
    agent.force_status = status
    with pytest.raises(EvidenceReadError) as err:
        r.read(0, 0, 10)
    assert err.value.fatal and needle in err.value.strerror
    agent.force_status = None
    with pytest.raises(EvidenceReadError):  # stays failed: never mix old and new bytes
        r.read(0, 200_000, 10)
    r.close()


def test_reader_rejects_a_changed_etag(agent):
    from app.services.client_evidence.fusefs import EvidenceReadError

    r = _reader(agent, readahead_blocks=0)
    agent.etag_override = '"300000-1"'
    with pytest.raises(EvidenceReadError, match="no longer matches"):
        r.read(0, 0, 10)
    r.close()


def test_tree_is_built_from_the_frozen_manifest():
    from app.services.client_evidence.fusefs import build_tree

    index, children = build_tree(
        [{"path": "disk.E01"}, {"path": "a/b/c.zip"}, {"path": "a/x.txt"}], dirs=["empty", "a/b"],
    )
    assert index == {"/disk.E01": 0, "/a/b/c.zip": 1, "/a/x.txt": 2}
    assert children["/"] == ["a", "disk.E01", "empty"]
    assert children["/a"] == ["b", "x.txt"] and children["/a/b"] == ["c.zip"] and children["/empty"] == []


# ---------------------------------------------------------------------------
# Registry (Redis) and token sealing
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_redis(monkeypatch):
    fakeredis = pytest.importorskip("fakeredis")
    from app.services.client_evidence import registry

    server = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(registry, "_redis", lambda: server)
    monkeypatch.setenv("CLIENT_EVIDENCE_SECRET", "unit-test-secret")
    return server


def test_registry_save_load_delete_and_job_index(fake_redis):
    from app.services.client_evidence import registry

    rec = registry.ShareRecord(share_id=SHARE, job_id=JOB, token="secret-token" * 3, agent_url="http://10.0.0.5:9877",
                               base_urls=["http://10.0.0.6:9877"], hostname="WS-1", client_root="E:\\Case")
    registry.save_share(rec)
    loaded = registry.load_share(SHARE)
    assert loaded == rec and loaded.candidates() == ["http://10.0.0.5:9877", "http://10.0.0.6:9877"]
    assert "token" not in loaded.public_dict()
    assert registry.shares_for_job(JOB) == [SHARE] and registry.all_share_ids() == [SHARE]
    registry.delete_share(SHARE)
    assert registry.load_share(SHARE) is None and registry.shares_for_job(JOB) == []


def test_sealed_token_round_trips_and_rebuilds_a_record(fake_redis):
    from app.services.client_evidence import registry

    sealed = registry.seal_token("bearer-token-value-123456")
    assert "bearer-token" not in sealed
    rebuilt = registry.record_from_job_source(JOB, {
        "share_id": SHARE, "token_sealed": sealed, "agent_url": "http://10.0.0.5:9877", "hostname": "WS-1",
        "client_root": "E:\\Case", "file_count": 3, "total_bytes": 9, "manifest_sha256": "a" * 64,
    })
    assert rebuilt.token == "bearer-token-value-123456" and rebuilt.job_id == JOB


# ---------------------------------------------------------------------------
# Attaching a client folder to a job
# ---------------------------------------------------------------------------

class _FakeDB:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def flush(self):
        pass


@pytest.fixture
def attach_env(fake_redis, monkeypatch, agent):
    from app.services.client_evidence import job_source, mount

    state = {"status": "created", "ds": {"type_hint": "keep-me"}}
    logs: list[str] = []
    monkeypatch.setattr(job_source, "_load_ds", lambda db, job_id: (json.loads(json.dumps(state["ds"])), state["status"]))
    monkeypatch.setattr(job_source, "_save_ds", lambda db, job_id, ds: state.__setitem__("ds", ds))
    monkeypatch.setattr("app.services.disk_build_log.write_disk_log", lambda db, job_id, msg, **kw: logs.append(msg))
    mounted: list[str] = []
    monkeypatch.setattr(mount, "ensure_mounted", lambda sid, **kw: mounted.append(sid) or Path("/client-evidence") / sid)
    monkeypatch.setattr(mount, "unmount", lambda sid: None)
    # The fake agent listens on loopback; allow it explicitly for the test.
    monkeypatch.setenv("CLIENT_EVIDENCE_ALLOWED_NETWORKS", "127.0.0.0/8")
    port = int(agent.url.rsplit(":", 1)[1])
    return {"state": state, "logs": logs, "mounted": mounted, "port": port}


def _attach(agent, env, **overrides):
    from app.services.client_evidence.agent_client import manifest_digest
    from app.services.client_evidence.job_source import attach_client_source

    kwargs = dict(
        share_id=agent.share_id, token=agent.token, port=env["port"], addresses=["127.0.0.1"], hostname="",
        client_root="E:\\Case-0423", file_count=3, total_bytes=0, manifest_sha256=manifest_digest(agent.manifest_files()),
        source_type="disk", agent_url=None, request_ip="203.0.113.9", user_email="examiner@lab",
    )
    kwargs.update(overrides)
    return attach_client_source(_FakeDB(), JOB, **kwargs)


def test_attach_connects_mounts_and_records_the_source(agent, attach_env):
    from app.services.client_evidence import registry

    out = _attach(agent, attach_env)
    assert out["path"] == f"client-evidence://{SHARE}"
    assert out["display_path"] == "WS-EXAM-07: E:\\Case-0423" and out["file_count"] == 3
    assert attach_env["mounted"] == [SHARE]
    ds = attach_env["state"]["ds"]
    assert ds["type_hint"] == "keep-me" and ds["evidence_location"] == "client"
    cs = ds["client_source"]
    assert cs["share_id"] == SHARE and "token" not in cs and registry.open_token(cs["token_sealed"]) == agent.token
    assert ds["client_sources"][SHARE]["hostname"] == "WS-EXAM-07"
    assert "stays on the client computer" in attach_env["logs"][-1]
    assert registry.load_share(SHARE).agent_url == agent.url


def test_attach_refuses_running_jobs_changed_folders_and_count_mismatch(agent, attach_env):
    from app.services.client_evidence import ClientEvidenceError

    attach_env["state"]["status"] = "processing"
    with pytest.raises(ClientEvidenceError, match="Stop the running pipeline"):
        _attach(agent, attach_env)
    attach_env["state"]["status"] = "created"
    with pytest.raises(ClientEvidenceError, match="changed after it was selected"):
        _attach(agent, attach_env, manifest_sha256="f" * 64)
    with pytest.raises(ClientEvidenceError, match="file count differs"):
        _attach(agent, attach_env, file_count=7)
    with pytest.raises(ClientEvidenceError, match="CLIENT_EVIDENCE_ALLOWED_NETWORKS"):
        _attach(agent, attach_env, addresses=["8.8.8.8"])


def test_reselecting_replaces_the_old_share_and_forgets_its_folder(agent, attach_env, monkeypatch):
    from app.services.client_evidence import registry

    old = "ce" + "a" * 24
    registry.save_share(registry.ShareRecord(share_id=old, job_id=JOB, token="x" * 30, agent_url="http://127.0.0.1:1"))
    attach_env["state"]["ds"].update({
        "client_sources": {old: {"share_id": old}},
        "evidence_folder": f"client-evidence://{old}",
        "evidence_folders": [f"client-evidence://{old}", "D:\\Server\\Case"],
        "last_host_path": f"client-evidence://{old}",
    })
    _attach(agent, attach_env)
    ds = attach_env["state"]["ds"]
    assert registry.load_share(old) is None
    assert set(ds["client_sources"]) == {SHARE}
    assert ds["evidence_folders"] == ["D:\\Server\\Case"] and ds["evidence_folder"] == "D:\\Server\\Case"
    assert "last_host_path" not in ds


def test_second_directory_of_one_selection_is_added_not_replaced(agent, attach_env):
    from app.services.client_evidence import registry

    other = "ce" + "b" * 24
    registry.save_share(registry.ShareRecord(share_id=other, job_id=JOB, token="x" * 30, agent_url="http://127.0.0.1:1"))
    _attach(agent, attach_env, replace_existing=False)
    assert registry.load_share(other) is not None and set(registry.shares_for_job(JOB)) == {other, SHARE}


def test_release_revokes_on_the_agent_and_drops_the_record(agent, attach_env, monkeypatch):
    from app.services.client_evidence import agent_client, job_source, registry

    _attach(agent, attach_env)
    revoked = []
    monkeypatch.setattr(agent_client, "revoke_share", lambda url, sid, tok, **kw: revoked.append((url, sid)) or True)
    ds = attach_env["state"]["ds"]
    assert job_source.release_job_client_sources(JOB, ds) == 1
    assert revoked == [(agent.url, SHARE)] and registry.load_share(SHARE) is None
    assert ds["client_sources"] == {} and "client_source" not in ds


def test_reseed_rebuilds_redis_from_the_job_after_a_flush(agent, attach_env, fake_redis):
    from app.services.client_evidence import job_source, registry

    _attach(agent, attach_env)
    fake_redis.flushall()
    assert registry.load_share(SHARE) is None
    assert job_source.reseed_job_shares(_FakeDB(), JOB) == [SHARE]
    assert registry.load_share(SHARE).token == agent.token


# ---------------------------------------------------------------------------
# host_evidence integration: client paths go through the normal registration
# ---------------------------------------------------------------------------

def test_resolver_routes_client_paths_and_keeps_them_resolvable(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_EVIDENCE_MOUNT_ROOT", str(tmp_path / "ce"))
    from app.services import host_evidence
    from app.services.client_evidence import ClientEvidenceError, job_source

    folder = tmp_path / "ce" / SHARE
    folder.mkdir(parents=True)
    monkeypatch.setattr(job_source, "resolve_client_path", lambda raw: folder)
    assert host_evidence.resolve_host_path(f"client-evidence://{SHARE}", job_id=JOB) == folder
    assert host_evidence._is_absolute_host_path(f"client-evidence://{SHARE}")
    assert host_evidence.container_to_workstation_path(folder / "sub") == f"client-evidence://{SHARE}/sub"

    def boom(raw):
        raise ClientEvidenceError("Path not found on the client workstation share")

    monkeypatch.setattr(job_source, "resolve_client_path", boom)
    with pytest.raises(ValueError, match="client workstation share"):
        host_evidence.resolve_host_path(f"client-evidence://{SHARE}/missing", job_id=JOB)


class _RegisterDB:
    """Just enough SQL for host_evidence.register_segments."""

    def __init__(self, ds: dict):
        self.ds = ds
        self.evidence: list[dict] = []
        self.info: dict = {}

    def commit(self): pass
    def rollback(self): pass
    def flush(self): pass

    def fetchone(self, db, sql, params=None):
        s = " ".join(sql.split())
        if s.startswith("SELECT disk_source FROM jobs"):
            return {"disk_source": json.loads(json.dumps(self.ds))}
        if s.startswith("SELECT type, disk_source FROM jobs"):
            return {"type": "host_disk", "disk_source": json.loads(json.dumps(self.ds))}
        if "FROM evidence_files WHERE job_id=:job_id AND host_path" in s:
            return next((e for e in self.evidence if e["host_path"] == params["host_path"]), None)
        if s.startswith("INSERT INTO evidence_files"):
            row = {"id": len(self.evidence) + 1, "job_id": params["job_id"], "relative_path": params["rel"],
                   "original_name": params["orig"], "host_path": params["host"], "storage_uri": params["uri"],
                   "sha256": params["sha256"], "status": "registered", "size_bytes": params["size"],
                   "source_kind": "host", "segment_part": params["part"], "segment_base": params["base"],
                   "created_at": "2026-10-26T12:00:00+00:00"}
            self.evidence.append(row)
            return row
        return None

    def fetchall(self, db, sql, params=None):
        if "FROM evidence_files" in sql:
            return [{"original_name": e["original_name"], "status": e["status"]} for e in self.evidence]
        return []

    def execute(self, db, sql, params=None):
        if "SET disk_source" in sql:
            self.ds = json.loads(params["ds"])


def test_register_segments_from_a_client_folder_records_client_residency(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_EVIDENCE_MOUNT_ROOT", str(tmp_path / "ce"))
    from app.services import host_evidence
    from app.services.client_evidence import job_source

    folder = tmp_path / "ce" / SHARE
    folder.mkdir(parents=True)
    (folder / "laptop.E01").write_bytes(os.urandom(4096))
    (folder / "laptop.E02").write_bytes(os.urandom(2048))
    (folder / "notes.txt").write_text("not evidence")

    fake = _RegisterDB({"client_source": {"share_id": SHARE, "hostname": "WS-EXAM-07"}, "intake": None})
    monkeypatch.setattr(job_source, "resolve_client_path", lambda raw: folder)
    monkeypatch.setattr(job_source, "reseed_for_path", lambda db, job_id, raw: None)
    monkeypatch.setattr("app.services.client_evidence.mount.ensure_mounted_for_paths", lambda paths: [])
    for name in ("fetchone", "fetchall", "execute"):
        monkeypatch.setattr(host_evidence, name, getattr(fake, name))
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *a, **k: None)
    monkeypatch.setattr("app.services.pipeline_orchestrator.patch_segment_registration_orchestration",
                        lambda *a, **k: None)
    monkeypatch.setattr("app.services.artifact_selection_catalog.persist_job_axiom_platform",
                        lambda db, job_id: "windows")

    result = host_evidence.register_segments(
        fake, JOB, path=f"client-evidence://{SHARE}", source_type="disk", skip_folder_list=True,
    )
    assert sorted(r["original_name"] for r in result["accepted"]) == ["laptop.E01", "laptop.E02"]
    # Workers open the FUSE path; nothing was copied anywhere.
    assert {e["host_path"] for e in fake.evidence} == {str(folder / "laptop.E01"), str(folder / "laptop.E02")}
    ds = fake.ds
    assert ds["intake"] == "client_remote"
    assert ds["source_residency"] == "client_workstation"
    assert ds["transport_mode"] == "remote_in_place" and ds["cleanup_policy"] == "never_delete_source"
    assert ds["transfer_required"] is False and ds["evidence_location"] == "client"
    assert ds["evidence_folder"] == f"client-evidence://{SHARE}"
    assert ds["client_source"]["hostname"] == "WS-EXAM-07"  # attach metadata survives registration
    # A browser-upload gate must never hold back a client-computer job.
    assert host_evidence.is_client_upload_pending(ds) is False


def test_server_path_registration_is_still_server_local(monkeypatch, tmp_path):
    from app.services import host_evidence

    folder = tmp_path / "server-drive" / "Case"
    folder.mkdir(parents=True)
    (folder / "pc.E01").write_bytes(b"x" * 100)
    fake = _RegisterDB({})
    monkeypatch.setattr(host_evidence, "resolve_host_path", lambda *a, **k: folder)
    for name in ("fetchone", "fetchall", "execute"):
        monkeypatch.setattr(host_evidence, name, getattr(fake, name))
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *a, **k: None)
    monkeypatch.setattr("app.services.pipeline_orchestrator.patch_segment_registration_orchestration",
                        lambda *a, **k: None)
    monkeypatch.setattr("app.services.artifact_selection_catalog.persist_job_axiom_platform",
                        lambda db, job_id: "windows")
    host_evidence.register_segments(fake, JOB, path=str(folder), source_type="disk", skip_folder_list=True)
    assert fake.ds["intake"] == "server_local" and fake.ds["evidence_location"] == "server"


# ---------------------------------------------------------------------------
# HTTP endpoint: error mapping and client address
# ---------------------------------------------------------------------------

@pytest.fixture
def api_client(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.routers import client_evidence as router_mod

    from app.deps import firm_db

    app = FastAPI()
    app.include_router(router_mod.router)
    user = type("U", (), {"email": "examiner@lab"})()
    for route in router_mod.router.routes:
        for dep in route.dependant.dependencies:
            app.dependency_overrides[dep.call] = lambda: user
    app.dependency_overrides[firm_db] = lambda: _FakeDB()
    monkeypatch.setattr("app.routers.jobs._ensure_job", lambda db, job_id: {"id": job_id})
    monkeypatch.setattr("app.routers.jobs._job_source_type", lambda db, job_id: "disk")
    return TestClient(app)


BODY = {"share_id": SHARE, "token": "t" * 43, "port": 9877, "addresses": ["10.20.30.41"], "hostname": "WS-1",
        "client_root": "E:\\Case", "file_count": 2, "total_bytes": 10, "manifest_sha256": "a" * 64}


def test_endpoint_passes_the_browser_address_and_maps_errors(api_client, monkeypatch):
    from app.services.client_evidence import ClientEvidenceError, job_source

    seen = {}

    def fake_attach(db, job_id, **kw):
        seen.update(kw)
        return {"ok": True, "path": f"client-evidence://{SHARE}"}

    monkeypatch.setattr(job_source, "attach_client_source", fake_attach)
    r = api_client.post(f"/api/jobs/{JOB}/evidence/client-source", json=BODY, headers={"X-Forwarded-For": "10.20.30.41, 172.18.0.2"})
    assert r.status_code == 200 and r.json()["path"] == f"client-evidence://{SHARE}"
    assert seen["request_ip"] == "10.20.30.41" and seen["replace_existing"] is True

    cases = [
        ("Stop the running pipeline before changing this job's evidence source", 409),
        ("The forensic server could not reach the Client Evidence Agent", 502),
        ("/dev/fuse is not available in this container", 503),
        ("The agent manifest does not match", 400),
    ]
    for message, status in cases:
        def failing(db, job_id, _m=message, **kw):
            raise ClientEvidenceError(_m)

        monkeypatch.setattr(job_source, "attach_client_source", failing)
        r = api_client.post(f"/api/jobs/{JOB}/evidence/client-source", json=BODY)
        assert r.status_code == status, message
        assert r.json()["detail"]["error"]["message"] == message


def test_endpoint_validates_share_identifiers(api_client):
    bad = {**BODY, "share_id": "../../etc"}
    assert api_client.post(f"/api/jobs/{JOB}/evidence/client-source", json=bad).status_code == 422
    short = {**BODY, "token": "short"}
    assert api_client.post(f"/api/jobs/{JOB}/evidence/client-source", json=short).status_code == 422


# ---------------------------------------------------------------------------
# Celery prerun hook
# ---------------------------------------------------------------------------

def test_prerun_hook_mounts_only_for_job_tasks(monkeypatch):
    from app.services.client_evidence import celery_hooks, mount

    calls = []
    monkeypatch.setattr(mount, "ensure_job_mounts", lambda job_id: calls.append(job_id))
    task = type("T", (), {"name": "app.tasks.build_extracted_disk_task"})()
    celery_hooks._on_task_prerun(task=task, args=("firm_a", JOB), kwargs={})
    celery_hooks._on_task_prerun(task=task, args=(), kwargs={"schema_name": "firm_a", "job_id": JOB})
    celery_hooks._on_task_prerun(task=type("T", (), {"name": "app.tasks.progress_agent_task"})(), args=(), kwargs={})
    celery_hooks._on_task_prerun(task=task, args=("firm_a", "not-a-uuid"), kwargs={})
    assert calls == [JOB, JOB]

    def explode(job_id):
        raise RuntimeError("redis down")

    monkeypatch.setattr(mount, "ensure_job_mounts", explode)
    celery_hooks._on_task_prerun(task=task, args=("firm_a", JOB), kwargs={})  # never blocks the task


# ---------------------------------------------------------------------------
# Shipped agent and deployment settings
# ---------------------------------------------------------------------------

AGENT_PS1 = ROOT / "scripts/client-evidence-agent/polaron-client-evidence-agent.ps1"
PUBLIC_DIR = ROOT / "frontend/public/downloads/client-evidence-agent"


def _embedded_csharp() -> str:
    text = AGENT_PS1.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    return text.split("$AgentSource = @'\n", 1)[1].split("\n'@", 1)[0]


def test_downloadable_agent_matches_the_canonical_script():
    for name in ("polaron-client-evidence-agent.ps1", "Install-PolaronClientEvidenceAgent.cmd"):
        assert (PUBLIC_DIR / name).read_bytes() == (AGENT_PS1.parent / name).read_bytes(), name
    raw = AGENT_PS1.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw  # Windows PowerShell 5.1 friendly
    cmd = (AGENT_PS1.parent / "Install-PolaronClientEvidenceAgent.cmd").read_text()
    assert "polaron-client-evidence-agent.ps1" in cmd and "-Install" in cmd


def test_agent_enforces_the_documented_security_rules():
    cs = _embedded_csharp()
    assert "public sealed class Agent" in cs
    assert 'Error("browser_forbidden"' in cs          # evidence bytes never go to a browser
    assert "!req.IsLocal || !HostIsLoopback(req)" in cs  # browsing/sharing only from this computer
    assert "origin_not_paired" in cs                  # only the paired Polaron console
    assert "Access-Control-Allow-Private-Network" in cs
    assert "evidence_modified" in cs                  # refuses changed files
    assert "FileShare.ReadWrite | FileShare.Delete" in cs and "FileAccess.Read" in cs
    assert ".Append(f.path).Append('\\t')" in cs       # same digest format as manifest_digest()
    # Outbound connection: only to the paired console that asked, token kept with DPAPI, TLS 1.2.
    assert "u.GetLeftPart(UriPartial.Authority).TrimEnd('/'), o, StringComparison.OrdinalIgnoreCase" in cs
    assert "DataProtectionScope.CurrentUser" in cs and "(SecurityProtocolType)3072" in cs
    assert "DefaultConnectionLimit" in cs and '"/ack/" + reqId' in cs
    # Wire encodings: all-zero marker and DEFLATE, decided by spread samples.
    assert "public static byte[] EncodeForWire(" in cs and "WorthCompressing(raw)" in cs
    assert '"X-Polaron-Encoding"' in cs and '"X-Relay-Encoding"' in cs
    ps1 = AGENT_PS1.read_text(encoding="utf-8-sig")
    assert "'System.Security'" in ps1 and "TrustServerThumbprint" in ps1


@pytest.mark.skipif(shutil.which("mcs") is None, reason="Mono C# compiler not installed")
def test_embedded_agent_compiles_as_csharp5(tmp_path):
    src = tmp_path / "Agent.cs"
    src.write_text(_embedded_csharp(), encoding="utf-8")
    proc = subprocess.run(
        ["mcs", "-langversion:5", "-target:library", "-nologo", "-r:System.Web.Extensions.dll", "-r:System.Core.dll",
         "-r:System.Security.dll",
         f"-out:{tmp_path / 'agent.dll'}", str(src)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_processing_container_can_mount_client_evidence():
    import yaml

    for compose, app_image in [("docker-compose.yml", "rag_new2-api"),
                               ("services/mobile-android/docker-compose.yml", "aetheris-mobile-android-app"),
                               ("services/mobile-ios/docker-compose.yml", "aetheris-mobile-ios-app")]:
        services = yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))["services"]
        for name, svc in services.items():
            if svc.get("image") != app_image or name == "worker-progress" and compose == "docker-compose.yml":
                continue
            assert "/dev/fuse:/dev/fuse" in (svc.get("devices") or []), f"{compose}:{name}"
            assert "SYS_ADMIN" in (svc.get("cap_add") or []), f"{compose}:{name}"
    dockerfile = (ROOT / "backend/Dockerfile").read_text()
    assert "fuse3 libfuse2t64" in dockerfile
    assert "fusepy==" in (ROOT / "backend/requirements.txt").read_text()


# ---------------------------------------------------------------------------
# Real FUSE mount (runs where /dev/fuse + libfuse + a Redis are available)
# ---------------------------------------------------------------------------

def _fuse_usable() -> bool:
    if not os.environ.get("CLIENT_EVIDENCE_TEST_REDIS_URL"):
        return False
    try:
        import fuse  # noqa: F401
    except (ImportError, OSError, EnvironmentError):
        return False
    return os.path.exists("/dev/fuse") and os.access("/dev/fuse", os.R_OK | os.W_OK)


@pytest.mark.skipif(not _fuse_usable(), reason="needs /dev/fuse, libfuse and CLIENT_EVIDENCE_TEST_REDIS_URL")
def test_fuse_mount_serves_identical_bytes_read_only(agent, monkeypatch, tmp_path):
    monkeypatch.setenv("REDIS_URL", os.environ["CLIENT_EVIDENCE_TEST_REDIS_URL"])
    monkeypatch.setenv("CLIENT_EVIDENCE_MOUNT_ROOT", str(tmp_path / "ce"))
    monkeypatch.setenv("CLIENT_EVIDENCE_SECRET", "unit-test-secret")
    monkeypatch.setenv("CLIENT_EVIDENCE_ALLOWED_NETWORKS", "127.0.0.0/8")
    from app.services.client_evidence import registry
    from app.services.client_evidence.agent_client import manifest_digest
    from app.services.client_evidence.mount import ensure_mounted, is_mounted, unmount

    registry.save_share(registry.ShareRecord(
        share_id=SHARE, job_id=JOB, token=agent.token, agent_url=agent.url,
        manifest_sha256=manifest_digest(agent.manifest_files()),
    ))
    try:
        mp = ensure_mounted(SHARE)
        assert is_mounted(mp)
        assert sorted(os.listdir(mp)) == ["05_Exports", "disk.E01", "sub"]
        assert os.listdir(mp / "05_Exports") == ["run-1"]
        assert (mp / "05_Exports" / "run-1" / "logical.zip").stat().st_size == 22
        assert (mp / "disk.E01").read_bytes() == agent.payload
        assert (mp / "sub" / "notes ü.txt").read_bytes() == "évidence".encode()
        with pytest.raises(OSError):
            (mp / "new.txt").write_text("x")
        with pytest.raises(OSError):
            os.unlink(mp / "disk.E01")
        assert ensure_mounted(SHARE) == mp  # idempotent
    finally:
        unmount(SHARE)
        registry.delete_share(SHARE)
    assert not is_mounted(tmp_path / "ce" / SHARE)


# ---------------------------------------------------------------------------
# Outbound connection ("relay"): the PC connects to the server
# ---------------------------------------------------------------------------

class OutboundAgent(threading.Thread):
    """Scripted stand-in for the agent's relay loop, talking to the real HTTP endpoints."""

    def __init__(self, base: str, share_id: str, token: str, files: list[tuple[str, bytes]],
                 lose_first: bool = False, delay_after_ack: float = 0.0):
        super().__init__(daemon=True)
        import httpx

        self.http = httpx.Client(base_url=base, timeout=60,
                                 headers={"Authorization": f"Bearer {token}", "X-Polaron-Share": share_id})
        self.files, self.share_id = files, share_id
        self.lose_first, self.delay_after_ack = lose_first, delay_after_ack
        self.stop = threading.Event()
        self.ranges: list[tuple[int, int, int]] = []

    def run(self):
        from app.services.client_evidence.agent_client import manifest_digest

        while not self.stop.is_set():
            try:
                resp = self.http.post("/api/client-agent/relay/poll", headers={"X-Polaron-Wait": "2"}, content=b"{}")
            except Exception:
                time.sleep(0.2)
                continue
            if resp.status_code != 200:
                time.sleep(0.2)
                continue
            msg = resp.json()
            if self.lose_first:
                self.lose_first = False  # like a poll whose connection died: never acknowledged, never answered
                continue
            rid = msg["req_id"]
            self.http.post(f"/api/client-agent/relay/ack/{rid}")
            time.sleep(self.delay_after_ack)
            headers, body = {"X-Relay-Status": "200"}, b""
            if msg["op"] == "manifest":
                files = [{"path": n, "size": len(d), "mtime_ms": FakeAgent.MTIME} for n, d in self.files]
                body = json.dumps({"ok": True, "share_id": self.share_id, "root": "D:\\Home", "hostname": "HOME-PC",
                                   "files": files, "dirs": [], "manifest_sha256": manifest_digest(files)}).encode()
            elif msg["op"] == "range":
                name, data = self.files[msg["index"]]
                self.ranges.append((msg["index"], msg["start"], msg["end"]))
                body = data[msg["start"]:msg["end"] + 1]
                headers = {"X-Relay-Status": "206", "X-Relay-ETag": f'"{len(data)}-{FakeAgent.MTIME}"'}
                if "zero" in msg.get("accept", "") and body and not any(body):
                    headers.update({"X-Relay-Encoding": "zero", "X-Relay-Raw-Length": str(len(body))})
                    body = b""
            self.http.post(f"/api/client-agent/relay/respond/{rid}", headers=headers, content=body)


def _redis_for_tests() -> str | None:
    url = os.environ.get("CLIENT_EVIDENCE_TEST_REDIS_URL")
    if not url:
        return None
    try:
        import redis

        redis.Redis.from_url(url, socket_connect_timeout=2).ping()
        return url
    except Exception:
        return None


@pytest.fixture
def relay_server(monkeypatch):
    url = _redis_for_tests()
    if not url:
        pytest.skip("needs CLIENT_EVIDENCE_TEST_REDIS_URL (a reachable Redis)")
    uvicorn = pytest.importorskip("uvicorn")
    from fastapi import FastAPI

    from app.routers import client_evidence as router_mod
    from app.services.client_evidence import relay

    monkeypatch.setenv("REDIS_URL", url)
    monkeypatch.setenv("CLIENT_EVIDENCE_SECRET", "unit-test-secret")
    monkeypatch.setattr(relay, "_sync_client", None)
    monkeypatch.setattr(relay, "_async_clients", {})
    import redis

    redis.Redis.from_url(url).flushdb()
    app = FastAPI()
    app.include_router(router_mod.agent_router)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def _relay_share(files):
    from app.services.client_evidence import registry, relay

    registry.save_share(registry.ShareRecord(share_id=SHARE, job_id=JOB, token="r" * 43, agent_url=relay.RELAY_URL))
    return [(n, d) for n, d in files]


def test_relay_serves_manifest_and_exact_bytes_through_the_server(relay_server):
    from app.services.client_evidence import agent_client, relay
    from app.services.client_evidence.fusefs import RemoteReader

    payload = os.urandom(150_000)
    files = _relay_share([("laptop.E01", payload)])
    agent = OutboundAgent(relay_server, SHARE, "r" * 43, files)
    agent.start()
    try:
        url, manifest = agent_client.choose_reachable([relay.RELAY_URL], share_id=SHARE, token="r" * 43, expected_digest=None)
        assert url == relay.RELAY_URL and manifest["hostname"] == "HOME-PC"
        assert relay.agent_online(SHARE)
        r = RemoteReader(share_id=SHARE, token="r" * 43, base_urls=[relay.RELAY_URL], files=manifest["files"],
                         block_size=64 * 1024, readahead_blocks=0)
        assert r.read(0, 0, len(payload)) == payload
        assert r.read(0, 70_000, 100) == payload[70_000:70_100]
        r.close()
    finally:
        agent.stop.set()


def test_relay_recovers_quickly_from_a_request_lost_on_a_dropped_connection(relay_server, monkeypatch):
    from app.services.client_evidence import relay
    from app.services.client_evidence.fusefs import RemoteReader

    monkeypatch.setenv("CLIENT_EVIDENCE_RELAY_ACK_SECONDS", "2")
    payload = os.urandom(70_000)
    files = _relay_share([("laptop.E01", payload)])
    agent = OutboundAgent(relay_server, SHARE, "r" * 43, files, lose_first=True)
    agent.start()
    try:
        r = RemoteReader(share_id=SHARE, token="r" * 43, base_urls=[relay.RELAY_URL],
                         files=[{"path": "laptop.E01", "size": len(payload), "mtime_ms": FakeAgent.MTIME}],
                         block_size=64 * 1024, readahead_blocks=0)
        t = time.time()
        assert r.read(0, 10, 50) == payload[10:60]
        assert time.time() - t < 10  # ack window 2 s + one retry; previously the full 120 s timeout
        r.close()
    finally:
        agent.stop.set()


def test_relay_keeps_waiting_for_an_acknowledged_slow_upload(relay_server, monkeypatch):
    from app.services.client_evidence import relay
    from app.services.client_evidence.fusefs import RemoteReader

    monkeypatch.setenv("CLIENT_EVIDENCE_RELAY_ACK_SECONDS", "2")
    payload = os.urandom(20_000)
    files = _relay_share([("laptop.E01", payload)])
    agent = OutboundAgent(relay_server, SHARE, "r" * 43, files, delay_after_ack=5)
    agent.start()
    try:
        r = RemoteReader(share_id=SHARE, token="r" * 43, base_urls=[relay.RELAY_URL],
                         files=[{"path": "laptop.E01", "size": len(payload), "mtime_ms": FakeAgent.MTIME}],
                         block_size=64 * 1024, readahead_blocks=0)
        assert r.read(0, 0, 100) == payload[:100]
        assert len(agent.ranges) == 1  # never re-sent while the agent was working on it
        r.close()
    finally:
        agent.stop.set()


def test_relay_endpoints_require_the_share_token(relay_server):
    import httpx

    _relay_share([])
    base = f"{relay_server}/api/client-agent/relay"
    assert httpx.post(f"{base}/poll").status_code == 401
    assert httpx.post(f"{base}/poll", headers={"X-Polaron-Share": SHARE, "Authorization": "Bearer " + "x" * 43}).status_code == 401
    other = "ce" + "9" * 24
    assert httpx.post(f"{base}/poll", headers={"X-Polaron-Share": other, "Authorization": "Bearer " + "r" * 43}).status_code == 404
    good = {"X-Polaron-Share": SHARE, "Authorization": "Bearer " + "r" * 43}
    assert httpx.post(f"{base}/respond/abc123", headers=good, content=b"x").status_code == 404  # nobody waits for it
    assert httpx.post(f"{base}/poll", headers={**good, "X-Polaron-Wait": "1"}).status_code == 204


def test_attach_falls_back_to_the_outbound_connection(relay_server, monkeypatch):
    from app.services.client_evidence import job_source, mount, registry, relay
    from app.services.client_evidence.agent_client import manifest_digest

    payload = os.urandom(5000)
    files = [("laptop.E01", payload)]
    state = {"ds": {}}
    monkeypatch.setattr(job_source, "_load_ds", lambda db, job_id: (json.loads(json.dumps(state["ds"])), "created"))
    monkeypatch.setattr(job_source, "_save_ds", lambda db, job_id, ds: state.__setitem__("ds", ds))
    monkeypatch.setattr("app.services.disk_build_log.write_disk_log", lambda *a, **k: None)
    monkeypatch.setattr(mount, "ensure_mounted", lambda sid, **kw: Path("/client-evidence") / sid)
    agent = OutboundAgent(relay_server, SHARE, "r" * 43, files)
    agent.start()
    try:
        digest = manifest_digest([{"path": "laptop.E01", "size": 5000, "mtime_ms": FakeAgent.MTIME}])
        out = job_source.attach_client_source(
            _FakeDB(), JOB, share_id=SHARE, token="r" * 43, port=9877, addresses=["203.0.113.50"], hostname="",
            client_root="D:\\Home", file_count=1, total_bytes=5000, manifest_sha256=digest, source_type="disk",
            agent_url=None, request_ip="198.51.100.7", relay_supported=True,
        )
        assert out["transport"] == "relay" and out["agent_url"] == relay.RELAY_URL
        assert registry.load_share(SHARE).agent_url == relay.RELAY_URL
        assert "outbound connection" in json.dumps(state["ds"]) or state["ds"]["client_source"]["agent_url"] == relay.RELAY_URL
    finally:
        agent.stop.set()


def test_attach_without_relay_support_still_reports_unreachable(relay_server, monkeypatch):
    from app.services.client_evidence import ClientEvidenceError, job_source, registry

    monkeypatch.setattr(job_source, "_load_ds", lambda db, job_id: ({}, "created"))
    with pytest.raises(ClientEvidenceError, match="connects out to the server"):
        job_source.attach_client_source(
            _FakeDB(), JOB, share_id=SHARE, token="r" * 43, port=9877, addresses=["203.0.113.50"], hostname="",
            client_root="D:\\Home", file_count=1, total_bytes=1, manifest_sha256="", source_type="disk",
            agent_url=None, request_ip="198.51.100.7", relay_supported=False,
        )
    assert registry.load_share(SHARE) is None



# ---------------------------------------------------------------------------
# Less upload: adaptive block runs, wire encodings, transfer counters
# ---------------------------------------------------------------------------

def test_scattered_reads_fetch_one_small_block_and_sequential_reads_grow(agent):
    r = _reader(agent, block_size=16 * 1024, max_run_bytes=128 * 1024, readahead_blocks=0, encoding="none")
    for off in (5_000, 200_000, 90_000, 150_000):           # scattered: MFT records, registry cells, LNK files
        r.read(0, off, 512)
    assert [e - s + 1 for s, e in agent.ranges] == [16 * 1024] * 4
    r.close()
    agent.ranges.clear()
    r = _reader(agent, block_size=16 * 1024, max_run_bytes=128 * 1024, readahead_blocks=0, encoding="none")
    for off in range(0, 16 * 1024 * 12, 16 * 1024):        # sequential read of one file (fresh cache)
        r.read(0, off, 16 * 1024)
    sizes = [e - s + 1 for s, e in agent.ranges]
    # The run doubles with every sequential read (cache hits included) up to the 128 KiB cap,
    # so 12 sequential block reads cost only a few requests.
    assert sizes[:3] == [16 * 1024, 32 * 1024, 128 * 1024] and max(sizes) == 128 * 1024
    assert len(sizes) <= 4
    r.close()


def test_zero_and_deflate_blocks_are_decoded_exactly_and_counted():
    zeros, text = bytes(200_000), (b"registry value invoice password " * 5000)[:150_000]
    fa = FakeAgent({"free.bin": zeros, "notes.txt": text})
    try:
        stats = []
        from app.services.client_evidence.fusefs import RemoteReader

        r = RemoteReader(share_id=SHARE, token=fa.token, base_urls=[fa.url], files=fa.manifest_files(),
                         block_size=64 * 1024, readahead_blocks=0, encoding="zero,deflate", on_stats=stats.append)
        assert r.read(0, 0, len(zeros)) == zeros and r.read(1, 0, len(text)) == text
        assert r.zero_bytes == len(zeros)
        assert r.wire_bytes < len(text) // 5          # zeros cost nothing, text compresses
        r.close()
        total = {k: sum(s[k] for s in stats) for k in ("logical_bytes", "wire_bytes", "zero_bytes", "requests")}
        assert total["logical_bytes"] == len(zeros) + len(text) and total["wire_bytes"] == r.wire_bytes
    finally:
        fa.close()


def test_a_corrupted_compressed_block_is_retried_never_trusted():
    text = (b"event log record " * 20000)[:200_000]
    fa = FakeAgent({"log.evtx": text})
    fa.corrupt_next = 1
    try:
        r = _reader(fa, readahead_blocks=0, encoding="deflate")
        assert r.read(0, 0, len(text)) == text
        assert fa.corrupt_next == 0  # the bad block was received, rejected and fetched again
        r.close()
    finally:
        fa.close()


def test_old_agents_without_encodings_still_work(agent):
    r = _reader(agent, readahead_blocks=0, encoding="zero,deflate")
    agent_payload = agent.payload  # random bytes: an encoding-aware agent sends them as-is too
    assert r.read(0, 0, 100_000) == agent_payload[:100_000]
    assert r.wire_bytes == r.bytes_fetched
    r.close()


def test_transfer_counters_accumulate_across_containers(fake_redis):
    from app.services.client_evidence import registry

    registry.add_transfer_stats(SHARE, {"logical_bytes": 1000, "wire_bytes": 400, "zero_bytes": 100, "requests": 2})
    registry.add_transfer_stats(SHARE, {"logical_bytes": 500, "wire_bytes": 500, "requests": 1})
    assert registry.read_transfer_stats(SHARE) == {"logical_bytes": 1500, "wire_bytes": 900, "zero_bytes": 100, "requests": 3}
    registry.save_share(registry.ShareRecord(share_id=SHARE, job_id=JOB, token="x" * 30, agent_url="http://10.0.0.5:9877"))
    registry.delete_share(SHARE)
    assert registry.read_transfer_stats(SHARE)["logical_bytes"] == 0


def test_relay_carries_zero_blocks_without_sending_them(relay_server):
    from app.services.client_evidence import relay
    from app.services.client_evidence.fusefs import RemoteReader

    zeros = bytes(130_000)
    files = _relay_share([("free.bin", zeros)])
    agent = OutboundAgent(relay_server, SHARE, "r" * 43, files)
    agent.start()
    try:
        r = RemoteReader(share_id=SHARE, token="r" * 43, base_urls=[relay.RELAY_URL],
                         files=[{"path": "free.bin", "size": len(zeros), "mtime_ms": FakeAgent.MTIME}],
                         block_size=64 * 1024, readahead_blocks=0, encoding="auto")
        assert r.read(0, 0, len(zeros)) == zeros
        assert r.wire_bytes == 0 and r.zero_bytes == len(zeros)
        r.close()
    finally:
        agent.stop.set()
