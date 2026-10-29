"""V1.9.1: self-scan must not silently switch off (field jobs 320903ac, 64b549f1).

The laptop's live ``.lan-fingerprint`` had no ``host_ips`` key: a pre-1.8.0
writer loop was still running and racing the current writer. The agent then
scanned 192.168.0.163 through its own firewall (149 of 154 ports "no answer")
and emitted no self_target_check event, so nobody could see why.
"""
from __future__ import annotations

import json
import os
import time

import pytest

from agent import main, self_target
from tests.test_self_target_v180 import ALIAS, HOST, _completed, _env, _loop  # noqa: F401  (shared harness + isolation)
from agent.service_policy import policy_ports

LEGACY = {"subnet": "192.168.0.0/24", "gateway": "192.168.0.1", "source": "host",
          "updated_at": "2026-10-15T04:55:00Z"}  # exactly the shape found on the laptop
CURRENT = dict(LEGACY, host_ips=[HOST], writer_version="1.9.1")


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    for key in ("SCANNER_HOST_IPS", "SELF_SCAN_MODE", "SELF_SCAN_FINGERPRINT_WAIT_SEC",
                "SELF_SCAN_FINGERPRINT_MAX_AGE_SEC"):
        monkeypatch.delenv(key, raising=False)
    self_target.reset_cache()
    yield
    self_target.reset_cache()


def _write(path, payload, *, age=0.0):
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    if age:
        old = time.time() - age
        os.utime(path, (old, old))


def _use(monkeypatch, path):
    monkeypatch.setattr(self_target, "_fingerprint_paths", lambda: [path])


def test_legacy_writer_file_is_named_not_silently_ignored(tmp_path, monkeypatch):
    fp = tmp_path / ".lan-fingerprint"
    _write(fp, LEGACY)
    _use(monkeypatch, fp)
    info = self_target.scanner_host_ips(wait_sec=0)
    assert info["ips"] == set() and info["legacy_writer"] is True
    assert "pre-1.8.0 Write-LanFingerprint" in info["reason"]
    plan = self_target.plan_self_targets([HOST])
    assert plan["aliases"] == {} and plan["undetermined"] is True and plan["legacy_writer"] is True


def test_race_with_current_writer_is_won_by_rereading(tmp_path, monkeypatch):
    """Old loop wrote last; the current loop rewrites within 10 s and is then used."""
    fp = tmp_path / ".lan-fingerprint"
    _write(fp, LEGACY)
    _use(monkeypatch, fp)
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)
        _write(fp, CURRENT)  # the current writer's next 10 s tick

    monkeypatch.setattr(self_target.time, "sleep", fake_sleep)
    info = self_target.scanner_host_ips(wait_sec=25)
    assert info["ips"] == {HOST} and info["reason"] == "fresh host fingerprint"
    assert len(sleeps) == 1


def test_a_read_that_lands_mid_write_is_retried(tmp_path, monkeypatch):
    fp = tmp_path / ".lan-fingerprint"
    _write(fp, '{"gateway":"192.168.0.1","host_')  # truncated: writer was rewriting in place
    _use(monkeypatch, fp)
    monkeypatch.setattr(self_target.time, "sleep", lambda sec: _write(fp, CURRENT))
    assert self_target.scanner_host_ips(wait_sec=10)["ips"] == {HOST}


def test_negative_cache_keeps_a_254_ip_job_from_waiting_on_every_chunk(tmp_path, monkeypatch):
    fp = tmp_path / ".lan-fingerprint"
    _write(fp, LEGACY)
    _use(monkeypatch, fp)
    clock = {"t": 1000.0}
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)
        clock["t"] += sec

    monkeypatch.setattr(self_target.time, "sleep", fake_sleep)
    monkeypatch.setattr(self_target.time, "monotonic", lambda: clock["t"])
    first = self_target.scanner_host_ips(wait_sec=6)
    waited = len(sleeps)
    assert waited >= 3 and "still after 6 s" in first["reason"]
    second = self_target.scanner_host_ips(wait_sec=6)
    assert len(sleeps) == waited and second["legacy_writer"] is True  # cached, no new wait


def test_stale_file_is_still_never_trusted_or_waited_on(tmp_path, monkeypatch):
    fp = tmp_path / ".lan-fingerprint"
    _write(fp, CURRENT, age=3600)
    _use(monkeypatch, fp)
    monkeypatch.setattr(self_target.time, "sleep", lambda sec: pytest.fail("must not wait on a stale file"))
    info = self_target.scanner_host_ips()
    assert info["ips"] == set() and "not trusted" in info["reason"]


def test_job_records_why_the_network_path_was_used(monkeypatch, caplog):
    """64b549f1 had no self_target_check event at all; now the reason is in the IP log."""
    tcp, _ = policy_ports()

    def probe(hosts, **kw):
        return {h: {"open": [135, 139, 445], "closed": [], "filtered": [p for p in tcp if p not in (135, 139, 445)]}
                for h in hosts}

    legacy = {"ips": set(), "source": "file:.lan-fingerprint", "legacy_writer": True,
              "reason": "fingerprint has no host_ips key: a pre-1.8.0 Write-LanFingerprint loop is still running"}
    real_plan = self_target.plan_self_targets

    def plan(targets):
        monkeypatch.delenv("SCANNER_HOST_IPS", raising=False)  # the harness sets it; the field laptop did not
        monkeypatch.setattr(self_target, "scanner_host_ips", lambda **kw: dict(legacy))
        return real_plan(targets)

    monkeypatch.setattr(self_target, "plan_self_targets", plan)
    main._LEGACY_WRITER_WARNED["at"] = 0.0
    caplog.set_level("WARNING", logger="scanner_agent")
    _uploaded, events, started = _loop(monkeypatch, [HOST], _completed, probe=probe)
    checks = [kw for h, e, kw in events if e == "self_target_check"]
    assert checks and checks[0]["undetermined"] is True and checks[0]["legacy_writer"] is True
    assert "pre-1.8.0" in checks[0]["reason"]
    assert started[0]["scan_addresses"] is None  # honest: network path, but now explained
    assert "SELF-SCAN DISABLED" in caplog.text
