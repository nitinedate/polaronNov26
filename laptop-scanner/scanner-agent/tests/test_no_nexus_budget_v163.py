"""Regression against the old 600s per-IP forced-stop path."""
import inspect
from pathlib import Path
from agent import main
from agent import AGENT_BUILD


def test_legacy_budget_branch_removed():
    source = inspect.getsource(main)
    assert "_nexus_budget_complete" not in source
    assert "degraded_time_budget" not in source
    assert '"nexus_budget"' not in source
    assert 'ip_budget_sec > 0' not in source
    assert "LEGACY_IP_BUDGET_IGNORED" in source


def test_v167_time_limit_is_explicit_not_a_hidden_completion():
    """V1.6.7 reintroduces a per-IP limit on request, but explicitly: its own
    variable (SCAN_IP_DEADLINE_SEC, not the ignored SCAN_IP_BUDGET_SEC), a
    'time_limit' event, and time_limited/stopped_at_progress evidence."""
    source = inspect.getsource(main)
    # V1.9.3: the per-IP limit is read through ip_runtime_limit() (SCAN_IP_DEADLINE_SEC,
    # else MAX_SCAN_RUNTIME_SEC applied per IP).
    assert "ip_runtime_limit()" in source and '"time_limit"' in source
    assert '"time_limited": True' in source and '"stopped_at_progress"' in source


def test_legacy_budget_600_no_longer_interrupts(monkeypatch):
    monkeypatch.setenv("SCAN_IP_BUDGET_SEC", "600")
    monkeypatch.setenv("MAX_SCAN_RUNTIME_SEC", "0")
    # _cfg is only for top-level configuration requiring credentials; the
    # obsolete setting has no scan lifecycle branches and default job ceiling is 0.
    assert '600' not in inspect.getsource(main._cfg)
    assert AGENT_BUILD.startswith("1.10.3-")  # V1.10.2: Polaron policy build


def test_full_profile_ports_and_service_audit_still_enabled():
    from agent.audit_scan_policy import audit
    report = audit(profile="full", udp="priority")
    assert report["service_families"] == 52
    assert report["requested_tcp_ports"] == 65535
    assert report["families_with_port_hints_in_scope"] == 52
    assert report["actual_greenbone_execution_verified"] is False


def test_legacy_performance_scripts_do_not_reduce_scope():
    root = Path(__file__).resolve().parents[2]
    for filename in ("Apply-Vuln-Throughput-v1.3.5.ps1", "scripts/Apply-Vuln-Performance-Profile.ps1"):
        script = (root / filename).read_text(encoding="utf-8")
        assert "'PORT_PROFILE' = 'full'" in script
        assert "'GVM_OPTIMIZE_TEST' = 'no'" in script
        assert "'SCAN_IP_BUDGET_SEC' = '0'" in script
