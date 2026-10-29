"""V1.8.0: scanning the scanner laptop itself, hotspot fingerprint, notes vs warnings."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager

import pytest

from agent import gmp_local as mod
from agent import main, port_discovery, self_target
from agent.coverage_reconcile import reconcile_host_observations
from agent.lan_fingerprint import is_docker_nat_fingerprint
from agent.scan_performance import NvtHangRegistry
from agent import scan_performance as perf
from agent.service_policy import policy_ports

HOST = "172.20.10.2"  # field job e158c5dc: the scanner laptop on an iPhone hotspot
ALIAS = "192.168.65.254"  # Docker Desktop host.docker.internal


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_TCP_CUSTOM_PORTS", "SCAN_UDP_CUSTOM_PORTS",
                "SERVICE_EXTRA_TCP_PORTS", "SERVICE_EXTRA_UDP_PORTS", "SCAN_PERFORMANCE", "SCAN_CHECK_SCOPE",
                "SCAN_IP_DEADLINE_SEC", "PORT_DISCOVERY_RANGE", "SELF_SCAN_MODE", "SELF_SCAN_ADDRESS",
                "SCANNER_HOST_IPS", "SELF_SCAN_FINGERPRINT_MAX_AGE_SEC"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SELF_SCAN_ALIAS_STORE", str(tmp_path / "aliases.json"))
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(tmp_path / "openvas.log"))
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))
    monkeypatch.setattr(self_target, "_fingerprint_paths", lambda: [tmp_path / "missing.json"])


def _fingerprint(tmp_path, monkeypatch, payload, *, age=0.0):
    path = tmp_path / ".lan-fingerprint"
    path.write_text(json.dumps(payload), encoding="utf-8")
    if age:
        old = time.time() - age
        os.utime(path, (old, old))
    monkeypatch.setattr(self_target, "_fingerprint_paths", lambda: [path])
    return path


# --- where the laptop's own addresses come from ------------------------------------------------
def test_fresh_fingerprint_lists_the_laptop_addresses(tmp_path, monkeypatch):
    _fingerprint(tmp_path, monkeypatch, {"gateway": "172.20.10.1", "source": "host",
                                         "host_ips": [HOST, "127.0.0.1", "169.254.3.4"]})
    info = self_target.scanner_host_ips()
    assert info["ips"] == {HOST}  # loopback and link-local are never "the laptop"


def test_stale_fingerprint_is_never_trusted(tmp_path, monkeypatch):
    # A client device can later receive the laptop's old address; never confuse them.
    _fingerprint(tmp_path, monkeypatch, {"host_ips": [HOST]}, age=3600)
    info = self_target.scanner_host_ips()
    assert info["ips"] == set() and "not trusted" in info["reason"]


def test_powershell_single_string_and_env_override(tmp_path, monkeypatch):
    _fingerprint(tmp_path, monkeypatch, {"host_ips": HOST})
    assert self_target.scanner_host_ips()["ips"] == {HOST}
    monkeypatch.setenv("SCANNER_HOST_IPS", "10.9.8.7, bogus")
    assert self_target.scanner_host_ips()["ips"] == {"10.9.8.7"}


def test_only_the_laptop_address_is_rerouted(monkeypatch):
    monkeypatch.setenv("SCANNER_HOST_IPS", HOST)
    monkeypatch.setattr(self_target, "loopback_address", lambda: ALIAS)
    plan = self_target.plan_self_targets([HOST, "172.20.10.3"])
    assert plan["aliases"] == {HOST: ALIAS}
    monkeypatch.setenv("SELF_SCAN_MODE", "off")
    assert self_target.plan_self_targets([HOST])["aliases"] == {}


def test_unresolvable_loopback_keeps_the_network_path(monkeypatch):
    monkeypatch.setenv("SCANNER_HOST_IPS", HOST)
    monkeypatch.setattr(self_target, "loopback_address", lambda: None)
    plan = self_target.plan_self_targets([HOST])
    assert plan["aliases"] == {} and "does not resolve" in plan["reason"]


def test_accept_all_proxy_and_exact_remap():
    tcp, _ = policy_ports()
    assert self_target.looks_like_accept_all({"open": tcp, "closed": [], "filtered": []})
    assert not self_target.looks_like_accept_all({"open": [135, 445], "closed": tcp[2:], "filtered": []})
    out = self_target.remap({ALIAS: {"host": ALIAS, "text": f"seen on {ALIAS}"}, "hosts": [ALIAS]}, {ALIAS: HOST})
    assert out == {HOST: {"host": HOST, "text": f"seen on {ALIAS}"}, "hosts": [HOST]}  # free text untouched


# --- the Greenbone task ------------------------------------------------------------------------
class FakeGmp:
    def __init__(self):
        self.targets, self.tasks = [], []

    def get_scan_configs(self, **kw):
        from lxml import etree
        return etree.fromstring(b"<r/>")

    def create_target(self, **kw):
        self.targets.append(kw)
        return {"id": "target-1"}

    def create_task(self, **kw):
        self.tasks.append(kw)
        return {"id": "task-self"}

    def start_task(self, task_id):
        from lxml import etree
        return etree.fromstring(b"<r><report_id>rep-1</report_id></r>")

    def get_feeds(self):
        from lxml import etree
        return etree.fromstring(b"<r/>")


def _scanner(monkeypatch, fake):
    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setattr(mod, "_session", fake_session)
    monkeypatch.setattr(mod, "_ensure_portscan_config", lambda gmp, base: "cfg")
    monkeypatch.setattr(mod, "_ensure_profile_config", lambda gmp, cid, prefs, caps, timing: (cid, {}))
    monkeypatch.setattr(mod, "_assert_feed_quality", lambda gmp, cid: {})
    monkeypatch.setattr(mod, "_find_scanner_id", lambda gmp: "scanner-1")
    return mod.LocalOpenVAS()


def test_task_targets_the_loopback_but_snapshot_keeps_the_authorized_ip(monkeypatch):
    fake = FakeGmp()
    scanner = _scanner(monkeypatch, fake)
    tid = scanner.start_scan(name="t", targets=[HOST], scan_addresses={HOST: ALIAS})
    assert fake.targets[0]["hosts"] == [ALIAS]
    snap = scanner.policy_snapshots[tid]
    assert snap["targets"] == [HOST] and snap["scan_addresses"] == {HOST: ALIAS} and snap["self_scan"] is True
    # Survives an agent restart: a new client reads the persisted mapping.
    fresh = mod.LocalOpenVAS()
    monkeypatch.setattr(fresh, "_get_task_hosts_raw", lambda t: [ALIAS])
    assert fresh.get_task_hosts(tid) == [HOST]


def test_poll_reports_everything_under_the_authorized_ip(monkeypatch):
    fake = FakeGmp()
    scanner = _scanner(monkeypatch, fake)
    tid = scanner.start_scan(name="t", targets=[HOST], scan_addresses={HOST: ALIAS})
    monkeypatch.setattr(mod, "_task_status", lambda gmp, t: ("done", 100.0, None))
    seen = {}

    def fake_payload(gmp, task_id, *, expected_targets, **kw):
        seen["expected"] = expected_targets
        vulns = [{"host": ALIAS, "result_id": "m1", "severity": "medium", "cvss": 5.0, "port": 135,
                  "plugin_name": "DCE/RPC and MSRPC Services Enumeration Reporting"}]
        ev = {"report_id": "rep-1", "assessment_complete": True, "assessed_hosts": [ALIAS],
              "host_coverage": {ALIAS: {"verdict": "observed_unverified", "open_tcp_ports": [135, 445]}}}
        return vulns, ev

    monkeypatch.setattr(mod, "_report_payload", fake_payload)
    res = scanner.poll(tid, expected_targets=[HOST])
    assert seen["expected"] == [ALIAS]
    assert res["vulnerabilities"][0]["host"] == HOST and res["vulnerabilities"][0]["severity"] == "medium"
    cov = res["evidence"]["host_coverage"][HOST]
    assert res["evidence"]["assessed_hosts"] == [HOST]
    assert cov["self_scan"]["scanned_via"] == ALIAS and cov["self_scan"]["view"] == "local"


# --- the job loop --------------------------------------------------------------------------------
def _loop(monkeypatch, hosts, poll_fn, *, probe):
    from agent import reachability

    uploaded, events, started = [], [], []

    class Api:
        def patch_job(self, job_id, payload):
            return {"id": job_id}

        def upload_results(self, job_id, payload):
            uploaded.append(payload)
            return {"status": "completed"}

    class Scanner:
        port_profile = "nexus"

        def start_scan(self, *, name, targets, scan_addresses=None, **kw):
            started.append({"targets": targets, "scan_addresses": scan_addresses})
            return f"task-{targets[0]}"

        def get_task_hosts(self, task_id):
            return [task_id.split("task-", 1)[1]]

        def poll(self, task_id, **kw):
            return poll_fn(task_id.split("task-", 1)[1])

        def stop(self, task_id):
            return True

    clock = {"t": 5000.0}

    def mono():
        clock["t"] += 30.0
        return clock["t"]

    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    monkeypatch.setattr(main.time, "monotonic", mono)
    monkeypatch.setattr(main, "should_watch_lan", lambda *a, **kw: False)
    monkeypatch.setattr(main, "probe_laptop_capacity", lambda **kw: {
        "chunk_size": 1, "ip_workers": 4, "configured_ceiling": 4, "hot": False, "admission_paused": False})
    monkeypatch.setattr(main, "emit_ip_event", lambda job, host, event, **kw: events.append((host, event, kw)))
    monkeypatch.setattr(main, "emit_service_results", lambda *a, **kw: None)
    monkeypatch.setattr(reachability, "partition_targets", lambda targets, **kw: {
        "reachable": list(targets), "unreachable": [], "skipped_hosts": []})
    monkeypatch.setattr(port_discovery, "probe_tcp_port_states", probe)
    for key, value in {"SKIP_UNREACHABLE_TARGETS": "false", "SCAN_DEGRADED_RETRY": "0",
                       "PORT_DISCOVERY_ENABLED": "true", "PORT_PROFILE": "nexus",
                       "SCANNER_HOST_IPS": HOST}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(self_target, "loopback_address", lambda: ALIAS)
    main._run_job_body({"api": Api(), "openvas": Scanner(), "poll": 0, "max_scan_runtime_sec": 0,
                        "progress_report_interval": 0, "high_progress_warn_sec": 300,
                        "high_progress_stall_sec": 0},
                       {"id": "00000000-0000-0000-0000-0000000000b8", "targets": [{"target": h} for h in hosts]})
    return uploaded, events, started


def _completed(host):
    return {"status": "completed", "gmp_status": "done", "progress": 100,
            "vulnerabilities": [{"host": host, "result_id": "m1", "severity": "medium", "port": 135,
                                 "protocol": "tcp", "plugin_name": "DCE/RPC enumeration", "cvss": 5.0}],
            "evidence": {"report_id": "r", "task_status": "done", "assessed_hosts": [host], "hosts_assessed": 1,
                         "assessment_complete": True, "scan_start": "s", "scan_end": "e",
                         "host_coverage": {host: {"verdict": "observed_unverified", "network_scan_complete": True,
                                                  "open_tcp_ports": [135, 445], "port_scanner_errors": [],
                                                  "warnings": []}}}}


def test_screenshot_job_now_scans_the_laptop_through_the_loopback(monkeypatch):
    tcp, _ = policy_ports()
    rest = [p for p in tcp if p not in (135, 445)]

    def probe(hosts, **kw):
        out = {}
        for h in hosts:
            if h == ALIAS:  # local view: SMB and RPC are listening
                out[h] = {"open": [135, 445], "closed": rest, "filtered": []}
            else:  # network view: Public-profile firewall drops everything
                out[h] = {"open": [], "closed": [], "filtered": list(tcp)}
        return out

    uploaded, events, started = _loop(monkeypatch, [HOST], _completed, probe=probe)
    assert started[0]["targets"] == [HOST] and started[0]["scan_addresses"] == {HOST: ALIAS}
    cov = uploaded[-1]["host_coverage"][HOST]
    assert cov["verdict"] == "observed_unverified"  # not "no exposed services"
    assert cov["self_scan"]["scanned_via"] == ALIAS
    assert cov["self_scan"]["network_exposure"]["filtered_count"] == len(tcp)
    assert any("firewall currently hides" in n for n in cov["notes"])
    assert cov["port_state_counts"]["open"] == 2
    assert [e for h, e, kw in events if e == "self_target"]


def test_accept_all_loopback_falls_back_to_the_network_path(monkeypatch):
    tcp, _ = policy_ports()

    def probe(hosts, **kw):
        return {h: ({"open": list(tcp), "closed": [], "filtered": []} if h == ALIAS
                    else {"open": [], "closed": [], "filtered": list(tcp)}) for h in hosts}

    def degraded(host):
        res = _completed(host)
        res["vulnerabilities"] = []
        res["evidence"]["host_coverage"][host] = {"verdict": "degraded_no_ports", "open_tcp_ports": [],
                                                  "port_scanner_errors": [], "warnings": []}
        return res

    uploaded, events, started = _loop(monkeypatch, [HOST], degraded, probe=probe)
    assert started[0]["scan_addresses"] is None
    assert [e for h, e, kw in events if e == "self_target_unreliable"]
    cov = uploaded[-1]["host_coverage"][HOST]
    assert cov["verdict"] == "no_exposed_services" and "self_scan" not in cov


# --- notes vs warnings, hotspot fingerprint --------------------------------------------------------------
def test_firewalled_host_gets_a_note_not_a_warning():
    tcp, _ = policy_ports()
    details = {"evidence": {"host_coverage": {HOST: {"verdict": "degraded_no_ports", "open_tcp_ports": [],
                                                     "port_scanner_errors": [], "warnings": []}}}}
    cov = reconcile_host_observations(details, HOST, [], {"open": [], "closed": [], "filtered": tcp})[
        "evidence"]["host_coverage"][HOST]
    assert cov["verdict"] == "no_exposed_services"
    assert cov["warnings"] == [] and any("firewall" in n for n in cov["notes"])


def test_iphone_hotspot_is_a_real_lan_not_docker_nat():
    assert is_docker_nat_fingerprint({"gateway": "172.20.10.1", "source": "host"}) is False
    assert is_docker_nat_fingerprint({"gateway": "172.17.0.1", "source": "proc"}) is True
    assert is_docker_nat_fingerprint({"gateway": "192.168.65.1", "source": "host"}) is True
