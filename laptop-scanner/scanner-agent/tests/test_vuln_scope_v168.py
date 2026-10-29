"""V1.6.8: vulnerability-only checks, OpenVAS log evidence, no time limits."""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from lxml import etree

from agent import gmp_local, scan_performance as perf
from agent.openvas_log import describe, host_activity
from agent.scan_performance import NvtHangRegistry, resolve_check_scope, stall_decision
from agent.service_policy import validate_request

HOST = "192.168.0.163"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("SCAN_CHECK_SCOPE", "SCAN_STALL_ACTION", "SCAN_PERFORMANCE", "GVM_MIN_NVT_COUNT",
                "PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_IP_DEADLINE_SEC"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "openvas.log"))
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- settings ---------------------------------------------------------------------
def test_check_scope_default_and_precedence(monkeypatch):
    assert resolve_check_scope(None) == "vulnerability"
    monkeypatch.setenv("SCAN_CHECK_SCOPE", "all")
    assert resolve_check_scope(None) == "all"
    assert resolve_check_scope({"check_scope": "vulnerability"}) == "vulnerability"
    assert validate_request({"check_scope": "all"})["check_scope"] == "all"
    with pytest.raises(ValueError):
        validate_request({"check_scope": "info"})


# --- OpenVAS log ----------------------------------------------------------------------
LOG = """\
sd main:MESSAGE:2026-10-14 04h40.00 utc:9: Vulnerability scan s1 started for host: 192.168.0.163
sd main:MESSAGE:2026-10-14 04h40.10 utc:9: Launching gb_smb_a.nasl (1.3.6.1.4.1.25623.1.0.100001) against 192.168.0.163 [201]
sd main:MESSAGE:2026-10-14 04h40.11 utc:9: Launching gb_other.nasl (1.3.6.1.4.1.25623.1.0.100009) against 192.168.0.164 [301]
sd main:MESSAGE:2026-10-14 04h40.12 utc:9: Launching gb_smb_b.nasl (1.3.6.1.4.1.25623.1.0.100002) against 192.168.0.163 [202]
sd main:MESSAGE:2026-10-14 04h41.42 utc:9: gb_smb_a.nasl (1.3.6.1.4.1.25623.1.0.100001) [201] finished its job in 92.100 seconds
sd main:MESSAGE:2026-10-14 04h41.43 utc:9: gb_other.nasl (1.3.6.1.4.1.25623.1.0.100009) [301] finished its job in 1.000 seconds
sd main:MESSAGE:2026-10-14 04h42.00 utc:9: Launching gb_smb_c.nasl (1.3.6.1.4.1.25623.1.0.100003) against 192.168.0.163 [203]
sd main:MESSAGE:2026-10-14 04h45.32 utc:9: 1.3.6.1.4.1.25623.1.0.100003 (pid 203) is slow to finish - killing it
sd main:MESSAGE:2026-10-14 04h55.12 utc:9: still alive
"""


def test_log_reconstructs_running_slow_and_killed_checks(tmp_path):
    (tmp_path / "openvas.log").write_text(LOG)
    act = host_activity(HOST)
    assert act["available"] and act["whole_attack_logging"]
    assert [r["oid"] for r in act["running"]] == ["1.3.6.1.4.1.25623.1.0.100002"]
    assert act["running"][0]["running_sec"] == 900  # 04h40.12 -> last stamp 04h55.12
    assert act["slow_finished"] == [{"oid": "1.3.6.1.4.1.25623.1.0.100001", "name": "gb_smb_a.nasl",
                                     "seconds": 92.1}]
    assert act["killed"][0]["oid"] == "1.3.6.1.4.1.25623.1.0.100003"
    assert act["host_finished"] is False
    assert "gb_smb_b.nasl" in describe(act) and "for 900s" in describe(act)


def test_other_hosts_finish_lines_do_not_clear_this_host(tmp_path):
    (tmp_path / "openvas.log").write_text(LOG)
    other = host_activity("192.168.0.164")
    assert other["running"] == [] and other["slow_finished"] == []


def test_host_finished_means_greenbone_is_processing(tmp_path):
    (tmp_path / "openvas.log").write_text(
        LOG + "sd main:MESSAGE:2026-10-14 04h56.00 utc:9: Vulnerability scan s1 finished for host "
              "192.168.0.163 in 960.12 seconds\n")
    act = host_activity(HOST)
    assert act["host_finished"] is True and act["running"] == []
    assert "Greenbone is still processing" in describe(act)


# --- stall decision ----------------------------------------------------------------------
@pytest.mark.parametrize("activity,expected", [
    ({"available": False}, "wait"),
    ({"available": True, "whole_attack_logging": False}, "wait"),
    ({"available": True, "whole_attack_logging": True, "running": [{"oid": "x"}]}, "wait"),
    ({"available": True, "whole_attack_logging": True, "host_finished": True}, "wait"),
    ({"available": True, "whole_attack_logging": True, "running": [], "host_finished": False,
      "host_started_seen": True}, "stop"),
    # V1.9.2: without the host's start line in the log, "nothing running" is not proof.
    ({"available": True, "whole_attack_logging": True, "running": [], "host_finished": False}, "wait"),
])
def test_stall_decision_is_evidence_based(activity, expected):
    assert stall_decision(activity, "auto") == expected


def test_stall_action_overrides():
    assert stall_decision({"available": False}, "stop") == "stop"
    assert stall_decision({"available": True, "whole_attack_logging": True}, "off") == "wait"


# --- vulnerability-only config ---------------------------------------------------------------
FAMILIES = ["Port scanners", "Service detection", "Settings", "Product detection", "General", "Windows",
            "Brute force attacks", "Policy", "Ubuntu Local Security Checks", "Web application abuses"]
SEVERE = {  # family -> NVTs with severity > 0
    "Product detection": [],
    "General": ["g-vuln-1", "g-vuln-2"],
    "Windows": ["w-1", "w-2", "w-3"],
    "Web application abuses": ["web-1"],
}
ESSENTIAL_FAMILY = {"1.3.6.1.4.1.25623.1.0.900239": "General", "1.3.6.1.4.1.25623.1.0.103997": "General",
                    "1.3.6.1.4.1.25623.1.0.105937": "Product detection"}


class ScopeGmp:
    def __init__(self, existing=None, new_count=40000, fail_on=None):
        self.existing = existing or []
        self.new_count = new_count
        self.fail_on = fail_on
        self.info_filters: list[str] = []
        self.family_rows = None
        self.nvt_selection: dict[str, list[str]] = {}
        self.scanner_prefs: dict[str, str] = {}
        self.names: list[str] = []

    def get_feeds(self):
        return etree.fromstring(b"<r><feed><type>NVT</type><version>202610140600</version></feed></r>")

    def get_scan_configs(self, **kw):
        rows = "".join(f'<config id="{cid}"><name>{n}</name><comment>{c}</comment></config>'
                       for cid, n, c in self.existing)
        return etree.fromstring(f"<r>{rows}</r>".encode())

    def get_scan_config(self, cid):
        fams = "".join(f"<family><name>{f}</name></family>" for f in FAMILIES)
        count = self.new_count if cid.startswith("vs-") else 90000
        return etree.fromstring(
            f"<r><config id='{cid}'><nvt_count>{count}</nvt_count><families>{fams}</families></config></r>".encode())

    def get_info(self, oid, info_type):
        fam = ESSENTIAL_FAMILY.get(oid)
        if not fam:
            raise RuntimeError("not found")
        return etree.fromstring(f"<r><info id='{oid}'><nvt oid='{oid}'><family>{fam}</family></nvt></info></r>".encode())

    def get_info_list(self, info_type, filter_string=None, details=None):
        assert info_type.value == "NVT" and details is False
        self.info_filters.append(filter_string)
        if self.fail_on and self.fail_on in filter_string:
            raise RuntimeError("socket closed")
        fam = filter_string.split('family="', 1)[1].split('"', 1)[0]
        infos = "".join(f"<info id='{oid}'><nvt oid='{oid}'/></info>" for oid in SEVERE.get(fam, []))
        return etree.fromstring(f"<r>{infos}</r>".encode())

    def clone_scan_config(self, cid):
        return {"id": f"vs-{cid}"}

    def modify_scan_config_set_name(self, cid, name):
        self.names.append(name)

    def modify_scan_config_set_family_selection(self, cid, families, auto_add_new_families=True):
        self.family_rows = families

    def modify_scan_config_set_nvt_selection(self, cid, family, oids):
        self.nvt_selection[family] = list(oids)

    def modify_scan_config_set_scanner_preference(self, cid, name, value=None):
        self.scanner_prefs[name] = value

    def modify_scan_config_set_comment(self, cid, *, comment=None):  # keyword-only, like python-gvm
        self.comment = comment

    def delete_scan_config(self, cid, ultimate=False):
        pass


def test_vulnerability_scope_keeps_every_non_excluded_family_whole():
    """V1.9.1: no OID enumeration, so gvmd's 1000-row cap cannot truncate anything."""
    g = ScopeGmp()
    cid, status = gmp_local._ensure_check_scope_config(g, "base-1")
    assert cid == "vs-base-1" and g.names[0].startswith("Aetheris vuln-scope v2 ")
    rows = {name: (growing, whole) for name, growing, whole in g.family_rows}
    for fam in FAMILIES:
        if fam in ("Brute force attacks", "Policy"):
            assert fam not in rows  # Nessus default: no brute force / compliance
        else:
            assert rows[fam] == (True, True), fam  # whole and growing
    assert g.info_filters == [] and g.nvt_selection == {}
    assert g.scanner_prefs["auto_enable_dependencies"] == "yes"
    assert status["scope"] == "vulnerability" and status["excluded_families"] == ["Brute force attacks", "Policy"]


def test_severity_scope_selects_severity_checks_and_keeps_discovery():
    """Opt-in V1.6.8 behaviour, now with detection kept whole."""
    g = ScopeGmp()
    cid, status = gmp_local._ensure_check_scope_config(g, "base-1", mode="severity")
    assert cid == "vs-base-1" and g.names[0].startswith("Aetheris severity-scope v2 ")
    rows = {name: (growing, whole) for name, growing, whole in g.family_rows}
    for fam in ("Port scanners", "Service detection", "Settings", "Product detection",
                "Ubuntu Local Security Checks"):
        assert rows[fam] == (True, True)
    assert "Brute force attacks" not in rows and "Policy" not in rows
    assert g.nvt_selection["Windows"] == ["w-1", "w-2", "w-3"]
    assert g.nvt_selection["General"] == ["g-vuln-1", "g-vuln-2", "1.3.6.1.4.1.25623.1.0.900239",
                                          "1.3.6.1.4.1.25623.1.0.103997"]
    assert all("severity>0" in f and "rows=" in f and "first=" in f for f in g.info_filters)
    assert status["nvt_count"] == 40000 and status["excluded_families"] == ["Brute force attacks", "Policy"]


def test_vulnerability_scope_reuses_config_for_same_feed():
    first = ScopeGmp()
    gmp_local._ensure_check_scope_config(first, "base-1")
    g = ScopeGmp(existing=[("vs-old", first.names[0], '{"nvt_count": 40000}')])
    cid, status = gmp_local._ensure_check_scope_config(g, "base-1")
    assert cid == "vs-old" and status["config"].startswith("reused") and g.info_filters == []


def test_vulnerability_scope_falls_back_to_all_checks_on_any_problem(monkeypatch):
    cid, status = gmp_local._ensure_check_scope_config(ScopeGmp(fail_on="Windows"), "base-1", mode="severity")
    assert cid == "base-1" and status["config"].startswith("not applied")
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "50000")
    cid, status = gmp_local._ensure_check_scope_config(ScopeGmp(new_count=40000), "base-1")
    assert cid == "base-1" and "below GVM_MIN_NVT_COUNT" in status["config"]


def _start(monkeypatch, policy):
    g = ScopeGmp()
    created = {}
    g.create_target = lambda **kw: created.setdefault("target", kw) and {"id": "t"}
    g.create_task = lambda **kw: created.setdefault("task", kw) and {"id": "task-9"}
    g.start_task = lambda tid: etree.fromstring(b"<r/>")
    g.modify_scan_config_set_nvt_preference = lambda *a, **kw: None

    @contextmanager
    def sess(**kw):
        yield g

    monkeypatch.setattr(gmp_local, "_session", sess)
    monkeypatch.setattr(gmp_local, "_ensure_portscan_config", lambda gmp, base: f"cfg-{base}")
    monkeypatch.setattr(gmp_local, "_assert_feed_quality", lambda gmp, cid: {})
    monkeypatch.setattr(gmp_local, "_find_scanner_id", lambda gmp: "s")
    from agent import control_plane

    monkeypatch.setattr(control_plane, "port_range_without_control_plane", lambda rng, hosts: rng)  # no DNS
    scanner = gmp_local.LocalOpenVAS()
    tid = scanner.start_scan(name="t", targets=[HOST], scan_policy=policy)
    return created, scanner.policy_snapshots[tid], g


def test_basic_network_runs_vulnerability_checks_only_by_default(monkeypatch):
    created, snap, g = _start(monkeypatch, {"template": "basic_network"})
    assert snap["check_scope"] == "vulnerability"
    assert snap["check_scope_status"]["config"].startswith("created")
    assert g.nvt_selection == {}  # V1.9.1: whole families, no truncatable OID lists
    assert all(growing and whole for _f, growing, whole in g.family_rows)
    assert created["task"]["config_id"].startswith("vs-")  # profile clone of the vuln-scope config
    assert snap["check_selection"]["available"] is True


def test_all_checks_discovery_and_family_templates_are_not_filtered(monkeypatch):
    for policy in ({"template": "basic_network", "check_scope": "all"},
                   {"template": "host_discovery"}, {"template": "web_app_tests"}):
        _, snap, g = _start(monkeypatch, policy)
        assert "check_scope_status" not in snap and g.nvt_selection == {}, policy
