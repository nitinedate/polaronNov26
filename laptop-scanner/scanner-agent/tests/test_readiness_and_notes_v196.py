"""V1.9.6 — field job 8d4e431e (agent 1.9.5, 192.168.0.163).

* The dispatcher calls ready() on every pass (3 s). Once V1.9.4 made the probe fast,
  gvmd was probed every ~4 s and "Base config ... not present" was logged every ~4 s.
* The timed-out-check note said "the next scans give it 60 s" although this scan had
  already run the check with the 60 s limit.
"""
from __future__ import annotations

import logging

import pytest
from lxml import etree

from agent import gmp_local, scan_performance as perf
from agent.scan_performance import NvtHangRegistry

OID = "1.3.6.1.4.1.25623.1.0.902269"
NAME = "Microsoft Windows SMB Server NTLM Multiple Vulnerabilities (971468)"


def _err(seconds: int) -> dict:
    return {"host": "192.168.0.163", "port": "general/tcp", "nvt_oid": OID, "nvt_name": NAME,
            "description": f"NVT timed out after {seconds} seconds."}


@pytest.fixture(autouse=True)
def _registry(monkeypatch, tmp_path):
    for key in ("NVT_HANG_MIN_EVENTS", "NVT_HANG_CAP_SEC", "NVT_HANG_WINDOW_DAYS", "READINESS_RECHECK_SEC"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- readiness is cached while ready ------------------------------------------------------------
def _scanner(monkeypatch, results):
    scanner = gmp_local.LocalOpenVAS.__new__(gmp_local.LocalOpenVAS)
    calls = []

    def probe():
        calls.append(1)
        return results[min(len(calls), len(results)) - 1]

    monkeypatch.setattr(scanner, "_probe_ready", probe)
    return scanner, calls


def test_a_ready_result_is_reused_instead_of_probing_gvmd_every_pass(monkeypatch):
    scanner, calls = _scanner(monkeypatch, [True])
    assert all(scanner.ready() for _ in range(20))
    assert len(calls) == 1


def test_not_ready_is_rechecked_on_every_pass(monkeypatch):
    scanner, calls = _scanner(monkeypatch, [False, False, True])
    assert [scanner.ready() for _ in range(4)] == [False, False, True, True]
    assert len(calls) == 3


def test_recheck_interval_is_configurable_and_can_be_invalidated(monkeypatch):
    monkeypatch.setenv("READINESS_RECHECK_SEC", "0")
    scanner, calls = _scanner(monkeypatch, [True])
    scanner.ready(); scanner.ready()
    assert len(calls) == 2
    monkeypatch.setenv("READINESS_RECHECK_SEC", "60")
    scanner.ready(); scanner.ready()
    assert len(calls) == 3
    scanner.invalidate_readiness()
    scanner.ready()
    assert len(calls) == 4


def test_base_config_fallback_is_logged_once_per_hour(monkeypatch, caplog):
    class G:
        def get_scan_configs(self, **kw):
            return etree.fromstring(
                b'<r><config id="aeth-1"><name>Aetheris Full and fast</name></config></r>')

    monkeypatch.setattr(gmp_local, "_BASE_CONFIG_NOTE_AT", 0.0)
    caplog.set_level(logging.INFO, logger="scanner_agent.gmp")
    for _ in range(10):
        assert gmp_local._find_config_id(G(), "Full and fast") == "aeth-1"
    assert sum("Base config 'Full and fast' not present" in r.getMessage() for r in caplog.records) == 1


# --- the timed-out check note --------------------------------------------------------------------
def test_note_says_already_limited_when_this_scan_used_the_limit():
    reg = perf.hang_registry()
    reg.record([_err(320)], host="192.168.0.163", job_id="j1")
    reg.record([_err(320)], host="192.168.0.163", job_id="j2")
    reg.record([_err(60)], host="192.168.0.163", job_id="j3")
    note = perf.timed_out_check_notes([_err(60)], "192.168.0.163", self_scan_via="192.168.65.254")[0]
    assert f"Check {NAME} ({OID}) on general/tcp did not finish" in note and "after 60 s" in note
    assert "already limits it to 60 s, so it no longer holds the scan up" in note
    assert "next scan" not in note
    assert "timed out in 3 scans in the last 30 days" in note
    assert "scanner laptop, scanned through the Docker loopback (192.168.65.254)" in note


def test_note_without_self_scan_does_not_mention_the_loopback():
    note = perf.timed_out_check_notes([_err(320)], "10.0.0.5")
    assert note == []  # error belongs to another host
    note = perf.timed_out_check_notes([dict(_err(320), host="10.0.0.5")], "10.0.0.5")[0]
    assert "loopback" not in note and "timed out in" not in note  # first occurrence: no history line
