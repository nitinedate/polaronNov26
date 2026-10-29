"""V1.9.5 — field job d1c55fbe (192.168.0.163, agent 1.9.3).

* openvas.log had no check-launch lines although 1.9.3 set log_whole_attack=yes on
  the scan config: gvmd sends scan-config scanner prefs as "1"/"0", ospd turns them
  back into yes/no only for its own boolean params, OpenVAS needs the exact "yes".
  So the value read as "off" and overrode openvas.conf.
* The job was "completed with warnings" because one check (…902269) timed out; the UI
  only said "plugin errors or timeouts".
"""
from __future__ import annotations

import copy

import pytest
from lxml import etree

from agent import gmp_local, main, openvas_log, scan_performance as perf
from agent.scan_performance import NvtHangRegistry
from tests.test_speed_v167 import _done, _loop

OID = "1.3.6.1.4.1.25623.1.0.902269"
FIELD_ERROR = {"host": "192.168.0.163", "port": "445/tcp", "nvt_oid": OID, "nvt_name": "Some SMB check",
               "severity": "-3.0", "description": "NVT timed out after 320 seconds."}


@pytest.fixture(autouse=True)
def _registry(monkeypatch, tmp_path):
    for key in ("NVT_HANG_MIN_EVENTS", "NVT_HANG_CAP_SEC", "NVT_HANG_WINDOW_DAYS", "NVT_HANG_CAPS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- scan-config scanner prefs that OpenVAS can only read as "off" ------------------------------
class _CloneGmp:
    def __init__(self):
        self.calls: list[tuple[str, str | None]] = []

    def get_scan_configs(self, **kw):
        return etree.fromstring(b"<r/>")

    def clone_scan_config(self, cid):
        return {"id": "clone-1"}

    def modify_scan_config_set_name(self, cid, name):
        self.name = name

    def modify_scan_config_set_scanner_preference(self, cid, name, value=None):
        self.calls.append((name, value))

    def modify_scan_config_set_nvt_preference(self, *a, **kw):
        pass

    def modify_scan_config_set_comment(self, cid, *, comment=None):
        pass

    def delete_scan_config(self, cid, ultimate=False):
        pass


def test_log_whole_attack_is_removed_from_new_profile_configs_never_set():
    g = _CloneGmp()
    cid, status = gmp_local._ensure_profile_config(
        g, "base", {"plugins_timeout": "320", "log_whole_attack": "yes"}, {}, None)
    assert cid == "clone-1"
    # removal (no value) comes first; a value for it is never written
    assert g.calls[0] == ("log_whole_attack", None)
    assert ("log_whole_attack", "yes") not in g.calls
    assert ("plugins_timeout", "320") in g.calls
    assert status["removed_scanner_prefs"] == ["log_whole_attack"]
    assert "log_whole_attack" not in status["scanner_preferences"]


def test_profile_configs_made_before_the_fix_are_not_reused():
    """The config name includes the cleanup marker, so a 1.9.3 clone never matches."""
    g1, g2 = _CloneGmp(), _CloneGmp()
    gmp_local._ensure_profile_config(g1, "base", {"plugins_timeout": "320"}, {}, None)
    saved = gmp_local._OPENVAS_CONF_ONLY_PREFS
    try:
        gmp_local._OPENVAS_CONF_ONLY_PREFS = ()
        gmp_local._ensure_profile_config(g2, "base", {"plugins_timeout": "320"}, {}, None)
    finally:
        gmp_local._OPENVAS_CONF_ONLY_PREFS = saved
    assert g1.name != g2.name


# --- naming the check behind "completed with warnings" ------------------------------------------
def test_timed_out_check_is_named_with_port_and_what_happens_next():
    notes = perf.timed_out_check_notes([FIELD_ERROR], "192.168.0.163")
    assert len(notes) == 1
    note = notes[0]
    assert f"Some SMB check ({OID})" in note and "on 445/tcp" in note and "after 320 s" in note
    assert "findings are valid" in note and "'with warnings'" in note
    assert "If it times out 2 times in 30 days, the agent limits it to 60 s" in note


def test_note_says_it_will_be_capped_once_it_repeats():
    reg = perf.hang_registry()
    reg.record([FIELD_ERROR], host="192.168.0.163", job_id="j1")
    reg.record([FIELD_ERROR], host="192.168.0.163", job_id="j2")
    note = perf.timed_out_check_notes([FIELD_ERROR], "192.168.0.163")[0]
    # it ran 320 s this time, so the limit applies from the next scan
    assert "From the next scan the agent limits it to 60 s" in note
    assert "timed out in 2 scans in the last 30 days" in note


def test_other_hosts_and_non_timeout_errors_get_no_note():
    other = dict(FIELD_ERROR, host="10.0.0.9")
    not_timeout = dict(FIELD_ERROR, description="Could not resolve hostname")
    assert perf.timed_out_check_notes([other, not_timeout], "192.168.0.163") == []


def test_discovery_checks_are_named_but_never_promised_a_cap():
    nmap = dict(FIELD_ERROR, nvt_oid="1.3.6.1.4.1.25623.1.0.14259", nvt_name="Nmap (NASL wrapper)")
    note = perf.timed_out_check_notes([nmap], "192.168.0.163")[0]
    assert "discovery check" in note and "never shortens" in note


def test_the_note_reaches_the_uploaded_host_coverage(monkeypatch):
    host = "192.168.0.163"

    def poll(h, n, stopped):
        done = copy.deepcopy(_done(h))
        done["evidence"]["plugin_error_details"] = [FIELD_ERROR]
        done["evidence"]["plugin_error_count"] = 1
        return done

    uploaded, _, _, _ = _loop(monkeypatch, [host], poll)
    notes = uploaded[-1]["host_coverage"][host].get("notes") or []
    assert any(OID in n and "445/tcp" in n for n in notes)


# --- logging setup, read from openvas.log ------------------------------------------------------
def test_setup_warnings_name_the_fix_for_debug_level_and_missing_launches():
    warnings = openvas_log.setup_warnings({"available": True, "lines_read": 50000, "debug_share": 0.99,
                                           "hosts_started": 3, "whole_attack_logging": False})
    assert len(warnings) == 3
    assert "99% DEBUG" in warnings[0] and "OPENVAS_LOG_LEVEL=127" in warnings[0]
    assert "no check launches" in warnings[1] and "OPENVAS_LOG_WHOLE_ATTACK=yes" in warnings[1]
    assert all("--force-recreate configure-openvas" in w for w in warnings[:2])
    assert "scans already in openvas.log" in warnings[2]


def test_setup_warnings_quiet_when_logging_is_right():
    assert openvas_log.setup_warnings({"available": True, "lines_read": 50000, "debug_share": 0.01,
                                       "hosts_started": 3, "whole_attack_logging": True}) == []
    assert openvas_log.setup_warnings({"available": False}) == []
    # too little log read to judge the DEBUG share
    assert openvas_log.setup_warnings({"available": True, "lines_read": 20, "debug_share": 1.0,
                                       "hosts_started": 0, "whole_attack_logging": False}) == []


def test_tail_message_gives_the_command_that_actually_reruns_configure_openvas():
    msg = openvas_log.describe({"available": True, "host_started_seen": True, "whole_attack_logging": False,
                                "debug_share": 1.0, "running": []})
    assert "docker compose up -d --force-recreate configure-openvas" in msg
    assert "OPENVAS_LOG_LEVEL=127" in msg  # the DEBUG share is reported too
    assert "up -d configure-openvas)" not in msg
