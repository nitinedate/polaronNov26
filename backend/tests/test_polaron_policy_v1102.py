"""V1.10.2: Polaron policy = Nessus Basic Network Scan ports + Polaron report ports, default selected."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = json.loads((Path(__file__).parent / "fixtures" / "polaron_report_ports.json").read_text())
REPORT_TCP = sorted(p["port"] for p in EVIDENCE["ports"] if p["protocol"] == "tcp")
REPORT_UDP = sorted(p["port"] for p in EVIDENCE["ports"] if p["protocol"] == "udp")


def test_evidence_fixture_matches_the_eight_reports():
    assert len(EVIDENCE["files"]) == 8
    assert EVIDENCE["rows_total"] == 6659 == EVIDENCE["rows_with_port"] + EVIDENCE["rows_port_0"]
    assert sum(p["findings"] for p in EVIDENCE["ports"]) == EVIDENCE["rows_with_port"]
    assert (len(REPORT_TCP), len(REPORT_UDP)) == (138, 7)


def test_template_is_the_single_default_and_seeded():
    from app.services.scanner_service_policy import default_template_key, scan_templates, template_by_key

    t = template_by_key("polaron")
    assert t["name"] == "Polaron policy" and t["vendor"] == "polaron"
    assert t["default"] is True and t["seed_as_builtin"] is True
    assert t["nessus_template"] == "Basic Network Scan"
    assert [x["key"] for x in scan_templates()["templates"] if x.get("default")] == ["polaron"]
    assert default_template_key() == "polaron"
    assert scan_templates()["catalog_version"] == "aetheris-templates-1.4"


def test_scope_is_basic_network_plus_every_report_port():
    from app.services.scanner_service_policy import effective_policy, port_numbers

    basic = effective_policy({"template": "basic_network"})
    pol = effective_policy({"template": "polaron"})

    def ports(spec: str, prefix: str) -> set[int]:
        return set(port_numbers([t[2:] for t in spec.split(",") if t.startswith(prefix)]))

    b_tcp, b_udp = ports(basic["port_range"], "T:"), ports(basic["port_range"], "U:")
    p_tcp, p_udp = ports(pol["port_range"], "T:"), ports(pol["port_range"], "U:")
    assert p_tcp == b_tcp | set(REPORT_TCP)
    assert p_udp == b_udp | set(REPORT_UDP)
    assert (pol["tcp_port_count"], pol["udp_port_count"]) == (262, 35)
    # Same engine settings as Basic Network Scan.
    for key in ("port_profile", "udp_profile", "scan_config", "alive_test", "safe_checks", "optimize_test"):
        assert pol.get(key) == basic.get(key), key


def test_report_ports_pinned_even_if_a_service_is_disabled():
    from app.services.scanner_service_policy import effective_policy, service_port_policy

    every = [s["key"] for s in service_port_policy()["services"]]
    pol = effective_policy({"template": "polaron", "disabled_services": every})
    assert pol["tcp_port_count"] == len(REPORT_TCP) and pol["udp_port_count"] == len(REPORT_UDP)


def test_dynamic_port_classes_match_the_template_note():
    from app.services.scanner_service_policy import template_by_key

    dyn = [p for p in EVIDENCE["ports"] if p["class"] in {"windows_dynamic_rpc", "sql_server_dynamic"}]
    assert len(dyn) == 18
    assert "18 report ports are Windows dynamic RPC or SQL Server" in template_by_key("polaron")["deviations"]


def test_catalogue_and_policy_module_copies_identical():
    pairs = [
        ("backend/app/services/scan_templates.json", "laptop-scanner/scanner-agent/agent/scan_templates.json"),
        ("backend/app/services/scanner_service_policy.py", "laptop-scanner/scanner-agent/agent/service_policy.py"),
    ]
    for a, b in pairs:
        assert (ROOT / a).read_bytes() == (ROOT / b).read_bytes(), a


def test_builtin_seeding_names_the_policy():
    from app.services.builtin_scan_policies import VENDOR_LABEL, builtin_name, seedable_templates

    t = next(x for x in seedable_templates() if x["key"] == "polaron")
    assert builtin_name(t) == "Polaron policy"
    assert VENDOR_LABEL["polaron"] == "Polaron"


@pytest.mark.parametrize("version,keeps_key", [
    ("1.10.2+v62.0", True),
    ("1.11.0+v63.1", True),
    ("1.10.1+v61.0", False),   # field agent before this release
    ("1.5.9", False),          # protocol version only: build unknown
    (None, False),
])
def test_old_agents_get_expanded_settings_without_the_key(version, keeps_key):
    from app.services.scanner_agent_jobs import agent_compatible_policy_request
    from app.services.scanner_service_policy import validate_request

    req = validate_request({"template": "polaron"})
    out = agent_compatible_policy_request(req, version)
    assert ("template" in out) is keeps_key
    for key in ("port_profile", "udp_profile", "custom_tcp_ports", "custom_udp_ports", "scan_config"):
        assert out[key] == req[key]


def test_templates_without_min_build_are_untouched():
    from app.services.scanner_agent_jobs import agent_compatible_policy_request
    from app.services.scanner_service_policy import validate_request

    req = validate_request({"template": "nx_full_audit"})
    assert agent_compatible_policy_request(req, None) == req


def test_inlined_request_runs_identically_on_an_agent_without_the_template(monkeypatch):
    """Simulate the v61 agent: its catalogue has no 'polaron' key."""
    import app.services.scanner_service_policy as sp
    from app.services.scanner_agent_jobs import agent_compatible_policy_request

    full = sp.validate_request({"template": "polaron"})
    expected = sp.effective_policy(full)
    inlined = agent_compatible_policy_request(full, "1.10.1+v61.0")   # central knows the template
    old_doc = dict(sp.scan_templates())
    old_doc["templates"] = [t for t in old_doc["templates"] if t["key"] != "polaron"]
    monkeypatch.setattr(sp, "scan_templates", lambda: old_doc)

    with pytest.raises(ValueError, match="Unknown scan template"):
        sp.effective_policy(full)            # what the old agent did with the key
    eff = sp.effective_policy(inlined)       # what it does now
    assert eff["port_range"] == expected["port_range"]
    assert (eff["tcp_port_count"], eff["udp_port_count"]) == (262, 35)


def test_frontend_preselects_the_server_default():
    jobs = (ROOT / "frontend/src/pages/vuln/ScanJobsPage.tsx").read_text(encoding="utf-8")
    pols = (ROOT / "frontend/src/pages/vuln/ScanPoliciesPage.tsx").read_text(encoding="utf-8")
    assert 'const DEFAULT_TEMPLATE_KEY = "polaron";' in jobs
    assert "tpls.find((t) => t.is_default)?.key" in jobs
    assert 'POLICY_GROUP_ORDER = ["polaron",' in jobs
    assert "templates.find((t) => t.is_default)" in pols
    router = (ROOT / "backend/app/routers/vuln.py").read_text(encoding="utf-8")
    assert '"is_default": template["key"] == default_key' in router
