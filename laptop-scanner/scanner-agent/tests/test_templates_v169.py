"""V1.6.9: Ping-Only Discovery, Credential Validation, Advanced Dynamic Scan, Policy Compliance."""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from lxml import etree

from agent import gmp_local, scan_performance as perf
from agent.scan_coverage import coverage_from_report
from agent.scan_performance import NvtHangRegistry
from agent.service_policy import credential_gap, validate_request
from tests.test_speed_v167 import _loop
from tests.test_vuln_scope_v168 import ScopeGmp

SMB_REF = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("SCAN_CHECK_SCOPE", "SCAN_PERFORMANCE", "GVM_MIN_NVT_COUNT", "PORT_PROFILE", "UDP_PROFILE",
                "UDP_PORT_RANGE", "SCAN_IP_DEADLINE_SEC", "SCAN_STALL_ACTION"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "openvas.log"))
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


# --- policy contract ------------------------------------------------------------------
def test_dynamic_filter_is_structured_and_safe():
    assert "nvt_filter" not in validate_request({"nvt_filter": {}})  # empty = no filter
    ok = validate_request({"template": "advanced_dynamic", "nvt_filter": {"min_severity": "9", "name_contains": "SMB"}})
    assert ok["nvt_filter"] == {"min_severity": 9.0, "name_contains": "SMB"}
    for bad in ({"min_severity": 11}, {"min_severity": 0}, {"name_contains": 'x" rows=-1'},
                {"sort": "name"}):
        with pytest.raises(ValueError):
            validate_request({"nvt_filter": bad})


def test_new_templates_and_credential_requirements():
    assert validate_request({"template": "ping_discovery"})["scan_purpose"] == "ping_discovery"
    assert credential_gap(validate_request({"template": "credential_validation"}))
    assert credential_gap(validate_request({"template": "policy_compliance"}))
    assert credential_gap(validate_request({"template": "credential_validation",
                                            "gmp_credential_refs": {"smb": SMB_REF}})) is None


def test_severity_filter_uses_gvmd_operators():
    assert gmp_local._severity_filter(None) == "severity>0"
    assert gmp_local._severity_filter({"min_severity": 7.0}) == "severity>6.9"
    assert gmp_local._severity_filter({"min_severity": 0.1, "name_contains": "SMB"}) == 'severity>0.0 name~"SMB"'


# --- Advanced Dynamic builder -----------------------------------------------------------
def test_dynamic_filter_selects_matching_checks_without_the_10k_floor(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = ScopeGmp(new_count=300)  # a narrow filter legitimately yields few checks
    cid, status = gmp_local._ensure_check_scope_config(g, "base-1", {"min_severity": 7.0})
    assert cid == "vs-base-1" and g.names[0].startswith("Aetheris dynamic ")
    assert all("severity>6.9" in f for f in g.info_filters)
    assert status["scope"] == "dynamic" and status["filter"] == {"min_severity": 7.0}


def test_explicit_family_list_is_honoured_even_for_normally_excluded_families():
    g = ScopeGmp()
    gmp_local._ensure_check_scope_config(g, "base-1", {"families": ["Windows", "Brute force attacks"]})
    filtered = {f.split('family="', 1)[1].split('"', 1)[0] for f in g.info_filters}
    assert filtered == {"Windows", "Brute force attacks"}
    rows = {name for name, _g, _a in g.family_rows}
    assert "Ubuntu Local Security Checks" not in rows  # not requested
    assert {"Port scanners", "Service detection"} <= rows  # discovery always kept


class NoMatchGmp(ScopeGmp):
    def get_info_list(self, info_type, filter_string=None, details=None):
        self.info_filters.append(filter_string)
        return etree.fromstring(b"<r/>")


def test_dynamic_filter_never_silently_falls_back_to_all_checks():
    with pytest.raises(ValueError, match="matched no checks"):
        gmp_local._ensure_check_scope_config(NoMatchGmp(), "base-1", {"name_contains": "zzz"})
    with pytest.raises(ValueError, match="could not be applied"):
        gmp_local._ensure_check_scope_config(ScopeGmp(fail_on="Windows"), "base-1", {"min_severity": 4.0})


# --- family scoping ------------------------------------------------------------------------
class FamGmp(ScopeGmp):
    def __init__(self, present):
        super().__init__()
        self.present = present

    def get_scan_config(self, cid):
        fams = "".join(f"<family><name>{f}</name></family>" for f in self.present)
        return etree.fromstring(f"<r><config><families>{fams}</families></config></r>".encode())


def test_missing_compliance_families_are_reported_or_refused():
    base = ["Port scanners", "Service detection", "Settings", "General", "Credentials", "Product detection"]
    _, status = gmp_local._ensure_family_config(FamGmp(base + ["Policy"]), "c", ["Policy", "Compliance"], require=True)
    assert "not in this feed: Compliance" in status
    with pytest.raises(ValueError, match="none of the required check families"):
        gmp_local._ensure_family_config(FamGmp(base), "c", ["Policy", "Compliance"], require=True)


# --- login results ---------------------------------------------------------------------------
def test_auth_host_details_become_login_status():
    report = etree.fromstring(b"""<report><host><ip>10.0.0.5</ip>
      <detail><name>Auth-SMB-Failure</name><value>x</value></detail>
      <detail><name>Auth-SMB-Success</name><value>x</value></detail>
      <detail><name>Auth-SSH-Failure</name><value>x</value></detail>
    </host></report>""")
    cov = coverage_from_report(report, host="10.0.0.5")
    assert cov["auth_status"] == {"smb": "success", "ssh": "failure"}


# --- ping-only discovery ---------------------------------------------------------------------------
def test_ping_purpose_judges_by_aliveness():
    ev = {"assessed_hosts": ["10.0.0.1"], "host_coverage": {
        "10.0.0.1": {"verdict": "degraded_no_ports"}, "10.0.0.2": {"verdict": "degraded_no_ports"}}}
    gmp_local._apply_scan_purpose(ev, "ping_discovery")
    assert ev["host_coverage"]["10.0.0.1"]["verdict"] == "discovery_alive"
    assert ev["host_coverage"]["10.0.0.2"]["verdict"] == "discovery_not_alive"
    ev2 = {"assessed_hosts": [], "host_coverage": {"h": {"verdict": "observed_unverified"}}}
    gmp_local._apply_scan_purpose(ev2, None)
    assert ev2["host_coverage"]["h"] == {"verdict": "observed_unverified", "scan_purpose": "vulnerability"}


def test_not_alive_host_is_skipped_and_the_job_still_completes(monkeypatch):
    def poll(host, n, stopped):
        alive = host.endswith(".1")
        return {"status": "completed", "gmp_status": "done", "progress": 100, "vulnerabilities": [],
                "evidence": {"report_id": f"rep-{host}", "task_status": "done",
                             "assessed_hosts": [host] if alive else [], "hosts_assessed": int(alive),
                             "assessment_complete": alive, "scan_start": "s", "scan_end": "e",
                             "host_coverage": {host: {"verdict": "discovery_alive" if alive else "discovery_not_alive",
                                                      "scan_purpose": "ping_discovery"}}}}
    uploaded, events, _, _ = _loop(monkeypatch, ["10.0.9.1", "10.0.9.2"], poll)
    final = uploaded[-1]
    skipped = final.get("skipped_hosts") or []
    assert [s["host"] for s in skipped] == ["10.0.9.2"] and skipped[0]["reason"] == "not_alive"
    assert any(e == "not_alive" for _, e, _ in events)
    assert final["status"] == "completed"


# --- start_scan wiring --------------------------------------------------------------------------------
def _start(monkeypatch, policy, gmp=None):
    g = gmp or ScopeGmp()
    created = {}
    g.create_target = lambda **kw: created.setdefault("target", kw) and {"id": "t"}
    g.create_task = lambda **kw: created.setdefault("task", kw) and {"id": "task-9"}
    g.start_task = lambda tid: etree.fromstring(b"<r/>")
    g.modify_scan_config_set_nvt_preference = lambda *a, **kw: None
    g.get_credential = lambda cid: etree.fromstring(f'<r><credential id="{cid}"/></r>'.encode())
    seen = {}

    @contextmanager
    def sess(**kw):
        yield g

    from agent import control_plane

    monkeypatch.setattr(control_plane, "port_range_without_control_plane", lambda rng, hosts: rng)
    monkeypatch.setattr(gmp_local, "_session", sess)
    monkeypatch.setattr(gmp_local, "_ensure_portscan_config", lambda gmp, base: seen.setdefault("base", base) and f"cfg-{base}")
    monkeypatch.setattr(gmp_local, "_assert_feed_quality", lambda gmp, cid: (seen.setdefault("quality", cid), {})[1])
    monkeypatch.setattr(gmp_local, "_find_scanner_id", lambda gmp: "s")
    scanner = gmp_local.LocalOpenVAS()
    tid = scanner.start_scan(name="t", targets=["10.0.0.5"], scan_policy=policy)
    return created, scanner.policy_snapshots[tid], g, seen


def test_ping_discovery_uses_the_host_discovery_config(monkeypatch):
    created, snap, _, seen = _start(monkeypatch, {"template": "ping_discovery"})
    assert seen["base"] == "Host Discovery" and snap["scan_purpose"] == "ping_discovery"
    assert created["target"]["alive_test"] == "ICMP, TCP-ACK Service & ARP Ping"


def test_advanced_dynamic_builds_a_filtered_config_and_skips_the_floor(monkeypatch):
    _, snap, g, seen = _start(monkeypatch, {"template": "advanced_dynamic",
                                            "nvt_filter": {"min_severity": 9.0}})
    assert snap["check_scope_status"]["scope"] == "dynamic"
    assert all("severity>8.9" in f for f in g.info_filters)
    assert seen["quality"] is None  # a narrow dynamic config is not held to the 10k floor


def test_policy_compliance_refused_when_feed_lacks_the_families(monkeypatch):
    base = ["Port scanners", "Service detection", "Settings", "General", "Credentials", "Product detection"]
    with pytest.raises(ValueError, match="none of the required check families"):
        _start(monkeypatch, {"template": "policy_compliance", "gmp_credential_refs": {"smb": SMB_REF}},
               gmp=FamGmp(base))
