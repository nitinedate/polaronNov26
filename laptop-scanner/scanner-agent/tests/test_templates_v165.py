"""V1.6.5 Nessus-equivalent scan templates and their effect on the Greenbone task."""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from lxml import etree

from agent import gmp_local as mod
from agent.service_policy import (
    credential_gap, effective_policy, mark_cve_watchlist, port_numbers, scan_templates, validate_request,
)

SMB_REF = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_TCP_CUSTOM_PORTS",
                "SCAN_UDP_CUSTOM_PORTS", "SERVICE_EXTRA_TCP_PORTS", "SERVICE_EXTRA_UDP_PORTS",
                "GVM_OPTIMIZE_TEST"):
        monkeypatch.delenv(key, raising=False)


def _tcp(spec: str) -> set[int]:
    return {p for tok in spec.split(",") if tok.startswith("T:") for p in port_numbers(tok[2:])}


def test_every_shipped_template_validates_and_has_nessus_reference():
    doc = scan_templates()
    assert len(doc["templates"]) >= 10
    for template in doc["templates"]:
        req = validate_request({"template": template["key"]})
        assert req["template"] == template["key"]
        assert template.get("reference") or template.get("nessus_reference")
        assert template["vendor"] in {"polaron", "nessus", "nexpose", "aetheris"}
        if template["vendor"] == "polaron":
            # V1.10.2: Polaron default package = Nessus Basic Network Scan ports + report ports.
            assert template["key"] == "polaron" and template.get("default") is True
            assert template["nessus_template"] == "Basic Network Scan" and template["nexpose_template"] is None
        elif template["category"] == "threat":
            # V1.6.9: not in the Nessus 10.11 scanner list, so never labelled as a Nessus template.
            assert template["nessus_template"] is None and template["name"].startswith("Threat check:")
        elif template["vendor"] == "nexpose":
            # V1.8.0: Rapid7 Nexpose/InsightVM built-in template; never labelled as Nessus.
            assert template["nexpose_template"] and template["nessus_template"] is None
        elif template["vendor"] == "aetheris":
            # V1.9.0: Aetheris-defined templates (PDF service matrix / Fund Fox
            # reference, TLS-SWEET32 focus) have no Nessus or Nexpose equivalent,
            # so they carry neither label and must name themselves "Aetheris ·".
            assert template["nessus_template"] is None and template["nexpose_template"] is None
            assert template["name"].startswith("Aetheris \u00b7")
        else:
            assert template["nessus_template"]
        effective_policy({"template": template["key"]})


def test_unknown_template_and_bad_settings_are_rejected():
    with pytest.raises(ValueError):
        validate_request({"template": "nope"})
    with pytest.raises(ValueError):
        validate_request({"scan_config": "Everything"})
    with pytest.raises(ValueError):
        validate_request({"alive_test": "ping harder"})
    with pytest.raises(ValueError):
        validate_request({"cve_watchlist": ["not-a-cve"]})
    with pytest.raises(ValueError):
        validate_request({"nvt_families": ["<script>"]})
    with pytest.raises(ValueError):
        validate_request({"port_profile": "focused"})


def test_explicit_settings_override_template_defaults():
    req = validate_request({"template": "basic_network", "udp_profile": "off", "optimize_test": "no"})
    assert req["udp_profile"] == "off" and req["optimize_test"] == "no"
    assert req["scan_config"] == "Full and fast"


def test_credentialed_template_requires_a_matching_reference():
    req = validate_request({"template": "credentialed_patch_audit"})
    assert "SMB or SSH" in credential_gap(req)
    ok = validate_request({"template": "credentialed_patch_audit", "gmp_credential_refs": {"smb": SMB_REF}})
    assert credential_gap(ok) is None


def test_focused_template_scans_only_its_ports():
    p = mod._effective_scan_policy({"template": "threat_ms17_010"}, "nexus", "priority")
    assert p["port_range"] == "T:139,T:445"
    assert p["udp_port_count"] == 0
    assert p["cve_watchlist"][0] == "CVE-2017-0143"


def test_nessus_static_floor_is_1_to_1024_plus_catalog():
    p = mod._effective_scan_policy(None, "nessus", "priority")
    tcp = _tcp(p["port_range"])
    assert set(range(1, 1025)) <= tcp
    assert {3389, 5985, 8443, 27017} <= tcp
    assert p["port_list_name"] == "All IANA assigned TCP"


def _scanner(monkeypatch, fake):
    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setattr(mod, "_session", fake_session)
    return mod.LocalOpenVAS()


def test_nessus_profile_widens_with_greenbone_iana_list(monkeypatch):
    monkeypatch.setattr(mod, "_named_port_list_tcp", lambda gmp, name: {5040, 5357, 7680, 80})
    scanner = _scanner(monkeypatch, object())
    rng = scanner.resolve_port_range(["192.0.2.1"], None, {"template": "basic_network", "port_profile": "nessus"})
    assert {5040, 5357, 7680, 22, 445} <= _tcp(rng)
    assert "U:161" in rng
    assert "widened" in scanner._port_list_status


def test_nessus_profile_falls_back_when_port_list_missing(monkeypatch):
    def boom(gmp, name):
        raise LookupError("missing")

    monkeypatch.setattr(mod, "_named_port_list_tcp", boom)
    scanner = _scanner(monkeypatch, object())
    rng = scanner.resolve_port_range(["192.0.2.1"], None, {"port_profile": "nessus"})
    assert set(range(1, 1025)) <= _tcp(rng)
    assert 5040 not in _tcp(rng)
    assert scanner._port_list_status.startswith("fallback")


def test_supplied_range_respects_template_udp_off(monkeypatch):
    scanner = _scanner(monkeypatch, object())
    rng = scanner.resolve_port_range(["192.0.2.1"], "T:80,T:443", {"template": "web_app_tests"})
    assert "U:" not in rng


def test_named_port_list_parser():
    xml = etree.fromstring(b"""<get_port_lists_response><port_list id="x"><name>All IANA assigned TCP</name>
      <port_ranges><port_range><start>1</start><end>3</end><type>tcp</type></port_range>
      <port_range><start>53</start><end>53</end><type>udp</type></port_range>
      <port_range><start>3389</start><end>3389</end><type>tcp</type></port_range></port_ranges>
      </port_list></get_port_lists_response>""")

    class G:
        def get_port_lists(self, **kwargs):
            return xml

    assert mod._named_port_list_tcp(G(), "All IANA assigned TCP") == {1, 2, 3, 3389}


class FakeGmp:
    def __init__(self, reject_families: bool = False):
        self.reject_families = reject_families
        self.targets: list[dict] = []
        self.tasks: list[dict] = []
        self.family_calls: list = []

    def get_credential(self, cid):
        return etree.fromstring(f'<r><credential id="{cid}"/></r>'.encode())

    def get_scan_configs(self, **kwargs):
        return etree.fromstring(b"<r/>")

    def clone_scan_config(self, cid):
        return {"id": f"clone-of-{cid}"}

    def modify_scan_config_set_name(self, cid, name):
        pass

    def modify_scan_config_set_scanner_preference(self, cid, name, value=None):
        pass

    def modify_scan_config_set_family_selection(self, cid, families, **kwargs):
        self.family_calls.append(families)
        if self.reject_families:
            raise RuntimeError("Failed to modify family selection")

    def create_target(self, **kwargs):
        self.targets.append(kwargs)
        return {"id": "target-1"}

    def create_task(self, **kwargs):
        self.tasks.append(kwargs)
        return {"id": "task-1"}

    def start_task(self, task_id):
        return etree.fromstring(b"<r><report_id>rep-1</report_id></r>")

    def get_feeds(self):
        return etree.fromstring(b"<r/>")


def _launch(monkeypatch, policy, fake=None):
    fake = fake or FakeGmp()
    seen = {}
    monkeypatch.setattr(mod, "_ensure_portscan_config", lambda gmp, base: seen.setdefault("base", base) and f"cfg-{base}")
    monkeypatch.setattr(mod, "_assert_feed_quality", lambda gmp, cid: (seen.setdefault("quality", cid), {})[1])
    monkeypatch.setattr(mod, "_find_scanner_id", lambda gmp: "scanner-1")
    monkeypatch.setattr(mod, "_named_port_list_tcp", lambda gmp, name: {5357})
    scanner = _scanner(monkeypatch, fake)
    task_id = scanner.start_scan(name="t", targets=["192.0.2.1"], scan_policy=policy)
    return scanner, fake, seen, scanner.policy_snapshots[task_id]


def test_template_drives_config_alive_test_and_optimize(monkeypatch):
    _, fake, seen, snap = _launch(monkeypatch, {"template": "host_discovery"})
    assert seen["base"] == "Discovery"
    assert seen["quality"] is None  # Discovery config is small by design; feed floor still checked
    assert fake.targets[0]["alive_test"] == "ICMP, TCP-ACK Service & ARP Ping"
    assert fake.tasks[0]["preferences"]["optimize_test"] == "yes"
    assert snap["template"] == "host_discovery" and snap["scan_config_name"] == "Discovery"


def test_basic_network_records_port_list_status(monkeypatch):
    _, fake, seen, snap = _launch(monkeypatch, {"template": "basic_network", "port_profile": "nessus"})
    assert seen["quality"] == "clone-of-cfg-Full and fast"  # profile clone still passes the NVT floor
    assert 5357 in _tcp(fake.targets[0]["port_range"])
    assert snap["port_list_status"].startswith("widened")


def test_credentialed_audit_without_reference_never_creates_a_task(monkeypatch):
    fake = FakeGmp()
    with pytest.raises(ValueError, match="credential reference"):
        _launch(monkeypatch, {"template": "credentialed_patch_audit"}, fake)
    assert fake.targets == [] and fake.tasks == []


def test_credentialed_audit_binds_smb_reference(monkeypatch):
    _, fake, _, snap = _launch(
        monkeypatch, {"template": "credentialed_patch_audit", "gmp_credential_refs": {"smb": SMB_REF}})
    assert fake.targets[0]["smb_credential_id"] == SMB_REF
    assert snap["credential_status"]["smb"].startswith("bound")


def test_family_scope_applied_or_falls_back_to_full_config(monkeypatch):
    _, fake, _, snap = _launch(monkeypatch, {"template": "web_app_tests"})
    names = {f for f, _g, _a in fake.family_calls[0]}
    assert {"Web Servers", "Port scanners", "Service detection"} <= names
    assert snap["family_scope_status"].startswith("scoped")
    assert fake.tasks[0]["config_id"].startswith("clone-of-")

    _, fake2, seen2, snap2 = _launch(monkeypatch, {"template": "web_app_tests"}, FakeGmp(reject_families=True))
    assert snap2["family_scope_status"].startswith("not applied")
    assert fake2.tasks[0]["config_id"] == "clone-of-cfg-Full and fast"
    assert seen2["quality"] == "clone-of-cfg-Full and fast"


def test_cve_watchlist_marks_hits_and_never_claims_absence():
    rows = [{"host": "h", "result_id": "r1", "cves": ["CVE-2017-0144"], "plugin_name": "MS17-010", "cvss": 8.1,
             "severity": "high"},
            {"host": "h", "result_id": "r2", "cves": [], "plugin_name": "other"}]
    hit = mark_cve_watchlist(rows, ["cve-2017-0144", "CVE-2017-0143"])
    assert hit["status"] == "hit" and hit["hit_count"] == 1
    assert rows[0]["watchlist_cves"] == ["CVE-2017-0144"]
    miss = mark_cve_watchlist(rows[1:], ["CVE-2020-1472"])
    assert miss["status"] == "no_hit_in_scanned_scope"
    assert "not proof" in miss["note"]
    assert mark_cve_watchlist(rows, []) is None
