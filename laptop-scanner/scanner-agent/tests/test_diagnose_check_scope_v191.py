"""V1.9.1 field diagnostic: it must name the truncated config the field tasks used."""
from __future__ import annotations

import json

from lxml import etree

from agent import diagnose_check_scope as diag
from agent import gmp_local
from tests.test_check_scope_v191 import BASE, DCE_REPORT, RealGvmd


class DiagGvmd(RealGvmd):
    def __init__(self):
        super().__init__()
        self.tasks: list[tuple[str, str, str]] = []

    def get_user_setting(self, setting_id):
        value = {diag.MAX_ROWS_SETTING: "1000", diag.FEED_IMPORT_OWNER_SETTING: "admin-uuid"}.get(setting_id, "")
        return etree.fromstring(f"<r><setting><value>{value}</value></setting></r>".encode())

    def get_scan_config_nvts(self, *, details=None, config_id=None, family=None, **_kw):
        nvts = "".join(f'<nvt oid="{oid}"/>' for oid in sorted(self._selected(config_id, family)))
        return etree.fromstring(f"<r>{nvts}</r>".encode())

    def get_tasks(self, *, filter_string=None, **_kw):
        rows = "".join(f'<task id="{tid}"><name>{name}</name><status>Done</status>'
                       f'<config id="{cid}"><name>{self.configs[cid]["name"]}</name></config></task>'
                       for tid, name, cid in self.tasks if cid in self.configs)
        return etree.fromstring(f"<r>{rows}</r>".encode())


def _legacy(g: DiagGvmd) -> str:
    sel = {f: ("whole", True) for f in g.feed if f.endswith(("Local Security Checks", "scanners", "Settings",
                                                             "Service detection"))}
    sel["Windows"] = ("static", set(g._ids("Windows")[:1000]))  # what gvmd's row cap left
    sel["General"] = ("static", set(g._ids("General")[:1000]))
    return g.add_config("Aetheris vuln-scope 7bb0ab6de1-d78f6a78", sel, in_use=True)


def test_diagnostic_names_the_truncated_config_the_field_task_used(monkeypatch):
    monkeypatch.setattr(diag, "_fingerprint", lambda: {"available": False})
    g = DiagGvmd()
    legacy = _legacy(g)
    g.tasks.append(("t-64b549f1", "edge-64b549f1-c0", legacy))
    out = diag.diagnose(g)
    row = next(c for c in out["configs"] if c["id"] == legacy)
    assert row["capped_families"] == ["General", "Windows"]
    assert row["sentinels"][DCE_REPORT] is False
    assert any(v.startswith("TRUNCATED") for v in out["verdicts"])
    assert any(v.startswith("MISSING CHECK") and "DCE/RPC" in v for v in out["verdicts"])
    assert out["max_rows_per_page"] == "1000"


def test_diagnostic_is_clean_after_the_fix(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(diag, "_fingerprint", lambda: {"available": True, "age_sec": 5, "keys": ["host_ips"],
                                                      "host_ips": ["192.168.0.163"], "legacy_writer": False})
    g = DiagGvmd()
    g.configs[BASE]["name"] = "Full and fast"  # stock config present
    g.configs[BASE]["id_alias"] = True
    cid, _ = gmp_local._ensure_check_scope_config(g, BASE)
    g.tasks.append(("t-new", "edge-new-c0", cid))
    out = diag.diagnose(g)
    row = next(c for c in out["configs"] if c["id"] == cid)
    assert row["capped_families"] == [] and row["sentinels"][DCE_REPORT] is True
    assert not any(v.startswith(("TRUNCATED", "MISSING CHECK", "SELF-SCAN")) for v in out["verdicts"])


def test_diagnostic_flags_the_legacy_fingerprint_writer(tmp_path, monkeypatch):
    fp = tmp_path / ".lan-fingerprint"
    fp.write_text(json.dumps({"subnet": "192.168.1.0/24", "gateway": "192.168.1.1", "source": "host"}))
    from agent import lan_fingerprint

    monkeypatch.setattr(lan_fingerprint, "FINGERPRINT_PATHS", (fp,))
    out = diag.diagnose(DiagGvmd(), check_sentinels=False)
    assert out["fingerprint"]["legacy_writer"] is True
    assert any(v.startswith("SELF-SCAN OFF") for v in out["verdicts"])


def test_diagnostic_flags_debug_level_openvas_log(tmp_path, monkeypatch):
    """V1.9.2: names the DEBUG flood that hid running checks (field job 3c4f45e0)."""
    from agent import openvas_log
    from tests.test_openvas_log_v192 import _debug_flood, _msg

    log = tmp_path / "openvas.log"
    log.write_text(_msg("07h36.00", "Vulnerability scan s1 started for host: 192.168.1.8")
                   + _msg("07h36.05", "Launching a.nasl (1.3.6.1.4.1.25623.1.0.900234) against 192.168.1.8 [9]")
                   + _debug_flood("192.168.1.8", 5000))
    monkeypatch.setenv("OPENVAS_LOG_FILE", str(log))
    monkeypatch.setattr(diag, "_fingerprint", lambda: {"available": False})
    openvas_log.reset()
    out = diag.diagnose(DiagGvmd(), check_sentinels=False)
    openvas_log.reset()
    assert out["openvas_log"]["whole_attack_logging"] is True
    assert any(v.startswith("OPENVAS DEBUG LOGGING") for v in out["verdicts"])
    assert not any(v.startswith("OPENVAS PER-CHECK LOGGING OFF") for v in out["verdicts"])
