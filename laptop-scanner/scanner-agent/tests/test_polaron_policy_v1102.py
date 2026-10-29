"""V1.10.2 agent: Polaron policy expands to Basic Network Scan ports + Polaron report ports."""

import json
from pathlib import Path

EVIDENCE = json.loads((Path(__file__).parent / "polaron_report_ports.json").read_text())


def test_agent_expands_polaron_template():
    from agent.service_policy import effective_policy, validate_request

    req = validate_request({"template": "polaron"})
    assert req["template"] == "polaron" and req["template_name"] == "Polaron policy"
    pol = effective_policy({"template": "polaron"})
    assert (pol["tcp_port_count"], pol["udp_port_count"]) == (262, 35)
    tcp = {p["port"] for p in EVIDENCE["ports"] if p["protocol"] == "tcp"}
    udp = {p["port"] for p in EVIDENCE["ports"] if p["protocol"] == "udp"}
    assert tcp <= set(req["custom_tcp_ports"]) and udp <= set(req["custom_udp_ports"])
    for port in (445, 3389, 62128, 9998, 8099, 26769, 1433, 57674):
        assert f"T:{port}" in pol["port_range"].split(",") or any(
            "-" in t and t.startswith("T:") and int(t[2:].split("-")[0]) <= port <= int(t.split("-")[1])
            for t in pol["port_range"].split(",")
        )


def test_agent_default_template_and_build():
    from agent import AGENT_BUILD
    from agent.service_policy import default_template_key

    assert default_template_key() == "polaron"
    assert AGENT_BUILD.endswith("v63.0")


def test_agent_runs_inlined_request_without_template_key():
    """Central sends expanded settings without the key to agents older than v62.0."""
    from agent.service_policy import effective_policy, validate_request

    full = validate_request({"template": "polaron"})
    inlined = {k: v for k, v in full.items() if k not in ("template", "template_name")}
    assert effective_policy(inlined)["port_range"] == effective_policy(full)["port_range"]
