"""V1.10.2 agent: name the cause when targets answered nothing."""

from agent.reachability_diagnosis import CONTROL_ADDRESS, diagnose_silent_hosts, icmp_echo

LAN = {"subnet": "192.168.0.0/24", "gateway": "192.168.0.254"}
SILENT = [f"192.168.0.{n}" for n in (162, 183, 194, 201, 209, 212, 228, 234, 241, 246)]


def _evidence(extra=None):
    cov = {h: {"verdict": "no_exposed_services", "host_responded": False,
               "port_state_counts": {"filtered": 262, "closed": 0},
               "notes": ["None of the 262 TCP ports in this policy's port list answered"]} for h in SILENT}
    cov["192.168.0.254"] = {"verdict": "observed_unverified", "open_tcp_ports": [22, 80, 443]}
    cov.update(extra or {})
    return {"host_coverage": cov}


def test_only_gateway_answered_and_no_ping_is_client_isolation():
    ev = _evidence()
    summary = diagnose_silent_hosts(ev, LAN, ping=lambda h: "no_reply")
    assert summary["gateway_only"] is True and summary["silent_hosts"] == sorted(SILENT)
    for h in SILENT:
        cov = ev["host_coverage"][h]
        assert cov["silent_cause"] == "client_isolation_suspected" and cov["assessed"] is False
        assert cov["notes"][0].startswith("Not assessed: no answer to ping or to any of 262")
    assert "silent_cause" not in ev["host_coverage"]["192.168.0.254"]


def test_ping_reply_means_host_firewall():
    ev = _evidence()
    diagnose_silent_hosts(ev, LAN, ping=lambda h: "no_reply" if h == CONTROL_ADDRESS else "reply")
    assert {ev["host_coverage"][h]["silent_cause"] for h in SILENT} == {"host_firewall"}


def test_no_guess_when_ping_unavailable_or_other_hosts_answered():
    ev = _evidence()
    diagnose_silent_hosts(ev, LAN, ping=lambda h: "unavailable")
    assert {ev["host_coverage"][h]["silent_cause"] for h in SILENT} == {None}
    ev = _evidence({"192.168.0.50": {"verdict": "observed_unverified", "open_tcp_ports": [445]}})
    diagnose_silent_hosts(ev, LAN, ping=lambda h: "no_reply")
    assert {ev["host_coverage"][h]["silent_cause"] for h in SILENT} == {"no_answer"}


def test_rerun_does_not_duplicate_notes_and_up_hosts_untouched():
    ev = _evidence({"192.168.0.60": {"verdict": "no_exposed_services", "host_responded": True}})
    diagnose_silent_hosts(ev, LAN, ping=lambda h: "no_reply")
    diagnose_silent_hosts(ev, LAN, ping=lambda h: "no_reply")
    assert sum(n.startswith("Not assessed:") for n in ev["host_coverage"][SILENT[0]]["notes"]) == 1
    assert "silent_cause" not in ev["host_coverage"]["192.168.0.60"]
    assert diagnose_silent_hosts({"host_coverage": {}}, LAN) is None


def test_icmp_echo_never_raises():
    # Some sandboxes/virtual NICs answer every echo (this build environment does): any state is
    # acceptable here; the control ping in diagnose_silent_hosts handles that case.
    assert icmp_echo(CONTROL_ADDRESS, timeout=0.2) in {"reply", "no_reply", "unavailable"}
    assert icmp_echo("not-an-ip") == "unavailable"


def test_network_that_answers_every_ping_is_not_trusted():
    ev = _evidence()
    summary = diagnose_silent_hosts(ev, LAN, ping=lambda h: "reply")  # control answers too
    assert summary["ping_unreliable"] is True and summary["ping_control"] == "reply"
    for h in SILENT:
        cov = ev["host_coverage"][h]
        assert cov["silent_cause"] is None and cov["icmp_echo"] == "unavailable"
        assert "answers ping for any address" in cov["notes"][0]


def test_probe_uses_the_job_policy_port_list(monkeypatch):
    import agent.port_discovery as pd
    from agent.service_policy import effective_policy

    seen = {}
    monkeypatch.setattr(pd, "probe_tcp_port_states",
                        lambda hosts, port_range=None, timeout=None: seen.setdefault("r", port_range) and {h: {"open": [], "closed": [], "filtered": []} for h in hosts})
    tcp = ",".join(t for t in effective_policy({"template": "polaron"})["port_range"].split(",") if t.startswith("T:"))
    pd.discovery_plan(["192.168.0.162"], port_range=tcp)
    assert seen["r"] == tcp and len(pd.parse_tcp_ports(tcp)) == 262
    import inspect, agent.main as m
    assert "discovery_plan(chunk, port_range=_job_probe_range) if _job_probe_range" in inspect.getsource(m)
