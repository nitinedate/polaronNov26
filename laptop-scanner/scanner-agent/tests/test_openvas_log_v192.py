"""V1.9.2: "per-check logging is off" at 98 % was a blind spot, not a setting.

Field job 3c4f45e0 (192.168.1.8), like 320903ac and c8416cd6, reported
"OpenVAS per-check logging is off (set log_whole_attack)" with no log line for
the host at all. openvas_log.conf was at DEBUG (128), and during the SSL/TLS
cipher checks libgvm wrote >8 MB of "Key ... already contained integer" lines
in about a second, so the old 8 MB tail never reached a "Launching" line.
"""
from __future__ import annotations

import logging

import pytest

from agent import openvas_log
from agent.openvas_log import describe, host_activity
from agent.scan_performance import stall_decision

HOST = "192.168.1.8"
SSL = "1.3.6.1.4.1.25623.1.0.900234"
OTHER = "1.3.6.1.4.1.25623.1.0.10736"


def _msg(ts: str, text: str) -> str:
    return f"sd   main:MESSAGE:2026-10-15 {ts} utc:4711: {text}\n"


def _debug_flood(host: str, n: int) -> str:
    # Real field format (job 320903ac): ~190 bytes each, all in the same second.
    line = (f"libgvm util:  DEBUG:2026-10-15 07h41.20 utc:5571:f30e3613-7003-497a-9ea1-62d12e9521d3: "
            f"Key 'ssl_tls/ciphers/sni/{host}/nonweak_ciphers' already contained integer '1'\n")
    return line * n


@pytest.fixture(autouse=True)
def _log(tmp_path, monkeypatch):
    path = tmp_path / "openvas.log"
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(path))
    monkeypatch.delenv("OPENVAS_LOG_BACKFILL_MB", raising=False)
    openvas_log.reset()
    yield path
    openvas_log.reset()


def _field_log() -> str:
    return (_msg("07h36.00", f"Vulnerability scan s1 started for host: {HOST}")
            + _msg("07h36.05", f"Launching gb_ssl_ciphers.nasl ({SSL}) against {HOST} [9001]")
            + _msg("07h36.06", f"Launching gb_dcerpc.nasl ({OTHER}) against {HOST} [9002]")
            + _msg("07h36.30", f"gb_dcerpc.nasl ({OTHER}) [9002] finished its job in 24.000 seconds")
            + _debug_flood(HOST, 60_000))  # ~11 MB, more than the old 8 MB window


def test_debug_flood_no_longer_hides_the_running_check(_log):
    _log.write_text(_field_log())
    assert _log.stat().st_size > 8_000_000
    act = host_activity(HOST)
    assert act["whole_attack_logging"] is True and act["host_started_seen"] is True
    assert [r["oid"] for r in act["running"]] == [SSL]
    assert act["running"][0]["running_sec"] == 315  # 07h36.05 -> flood at 07h41.20, not 07h36.30
    assert "gb_ssl_ciphers.nasl" in describe(act) and "logging is off" not in describe(act)
    assert act["debug_share"] > 0.99 and act["lines"]  # DEBUG lines are counted, never kept
    assert not any("DEBUG" in line for line in act["lines"])
    assert stall_decision(act, "auto") == "wait"  # a named check is running


def test_incremental_reads_only_new_bytes_and_tracks_finish(_log):
    _log.write_text(_field_log())
    first = host_activity(HOST)
    read_before = openvas_log._STATE["lines_read"]
    with _log.open("a") as fh:
        fh.write(_msg("07h47.30", f"gb_ssl_ciphers.nasl ({SSL}) [9001] finished its job in 685.000 seconds"))
    second = host_activity(HOST)
    assert first["running"] and second["running"] == []
    assert openvas_log._STATE["lines_read"] - read_before == 1
    assert second["slow_finished"][0] == {"oid": SSL, "name": "gb_ssl_ciphers.nasl", "seconds": 685.0}


def test_nothing_running_is_not_proof_without_the_hosts_start(_log, monkeypatch):
    """A check launched before the window must not make a busy host look idle."""
    monkeypatch.setenv("OPENVAS_LOG_BACKFILL_MB", "1")
    _log.write_text(_msg("07h36.00", f"Vulnerability scan s1 started for host: {HOST}")
                    + _msg("07h36.05", f"Launching gb_ssl_ciphers.nasl ({SSL}) against {HOST} [9001]")
                    + _debug_flood(HOST, 12_000)  # ~2.3 MB: pushes the launch out of a 1 MB window
                    + _msg("07h40.00", f"Launching gb_dcerpc.nasl ({OTHER}) against {HOST} [9002]")
                    + _msg("07h40.20", f"gb_dcerpc.nasl ({OTHER}) [9002] finished its job in 20.000 seconds"))
    act = host_activity(HOST)
    assert act["whole_attack_logging"] is True and act["running"] == []
    assert act["host_started_seen"] is False
    assert stall_decision(act, "auto") == "wait"  # V1.6.8 would have answered "stop"
    text = describe(act)
    assert text.startswith("Cannot see this host's running checks") and "OPENVAS_LOG_LEVEL=127" in text


def test_logging_really_off_is_named_as_such(_log):
    _log.write_text(_msg("07h36.00", f"Vulnerability scan s1 started for host: {HOST}")
                    + _msg("07h36.10", f"nasl_ssh: connect to {HOST} port 22 refused"))
    act = host_activity(HOST)
    assert act["host_started_seen"] is True and act["whole_attack_logging"] is False
    assert "per-check logging is off" in describe(act) and "OPENVAS_LOG_WHOLE_ATTACK=yes" in describe(act)
    assert stall_decision(act, "auto") == "wait"


def test_rewritten_or_rotated_log_is_read_from_scratch(_log):
    _log.write_text(_field_log())
    assert host_activity(HOST)["running"]
    _log.write_text(_msg("08h00.00", "Vulnerability scan s2 started for host: 10.0.0.9") * 400)
    assert host_activity(HOST)["running"] == []  # old state is not carried over
    assert host_activity("10.0.0.9")["host_started_seen"] is True


def test_launch_in_the_same_second_keeps_its_start_time(_log):
    _log.write_text(_msg("07h36.00", f"Vulnerability scan s1 started for host: {HOST}")
                    + _msg("07h36.00", f"Launching gb_ssl_ciphers.nasl ({SSL}) against {HOST} [9001]")
                    + _msg("07h38.00", "still working"))
    assert host_activity(HOST)["running"][0]["running_sec"] == 120


def test_oid_digits_are_not_mistaken_for_ip_addresses(_log):
    _log.write_text(_msg("07h36.00", f"gb_x.nasl ({OTHER}) reported something"))
    host_activity(HOST)
    assert "1.3.6.1" not in openvas_log._STATE["context"]
    assert "6.1.4.1" not in openvas_log._STATE["context"]


# --- the job loop: self-scan alias and log level of the 98 % notice ------------------------------
def test_self_scan_reads_the_log_under_the_loopback_alias(monkeypatch, caplog):
    from tests.test_self_target_v180 import ALIAS, HOST as LAPTOP, _completed, _loop
    from agent.service_policy import policy_ports

    tcp, _ = policy_ports()
    asked: list[str] = []

    def fake_activity(address, **kw):
        asked.append(address)
        return {"available": True, "whole_attack_logging": True, "host_started_seen": True,
                "running": [{"oid": SSL, "name": "gb_ssl_ciphers.nasl", "pid": 9001, "running_sec": 400}],
                "host_finished": False, "lines": [], "nvt_oids": [SSL], "slow_finished": []}

    monkeypatch.setattr(openvas_log, "host_activity", fake_activity)
    polls = {"n": 0}

    def poll(host):
        polls["n"] += 1
        if polls["n"] < 25:
            return {"status": "running", "gmp_status": "running", "progress": 98,
                    "vulnerabilities": [], "evidence": {}}
        return _completed(host)

    def probe(hosts, **kw):
        return {h: ({"open": [135, 445], "closed": [], "filtered": []} if h == ALIAS
                    else {"open": [], "closed": [], "filtered": list(tcp)}) for h in hosts}

    caplog.set_level(logging.INFO, logger="scanner_agent")
    _uploaded, events, started = _loop(monkeypatch, [LAPTOP], poll, probe=probe)
    assert started[0]["scan_addresses"] == {LAPTOP: ALIAS}
    assert asked and set(asked) == {ALIAS}  # never the firewalled LAN address
    tails = [kw for h, e, kw in events if e == "tail_activity"]
    assert tails and tails[0]["log_host"] == ALIAS
    notice = [r for r in caplog.records if "at 98% for" in r.getMessage()]
    assert notice and all(r.levelno == logging.INFO for r in notice)  # normal tail, not a warning
