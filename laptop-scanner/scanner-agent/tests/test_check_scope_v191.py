"""V1.9.1 regression: Info-only scans on 192.168.0.163 (jobs 1598a7c8, dffcee8e, 64b549f1).

V1.6.4 on the same laptop reported 2 Medium + 1 Low (field job d26e3145). From
V1.6.8 every scan was Info-only. The V1.6.8 scope builder asked gvmd for each
family's severity>0 checks with ``rows=-1``; gvmd caps every GET at
"Max Rows Per Page" (default 1000), so big families were truncated, and the
truncated config was reused forever because its verification comment was never
stored (``comment`` is keyword-only in python-gvm).

``RealGvmd`` below behaves like gvmd where it matters: the 1000-row cap, a
keyword-only comment, sorted pages, per-family nvt_count/max_nvt_count.
"""
from __future__ import annotations

import json
import re

import pytest
from lxml import etree

from agent import gmp_local

DCE_REPORT = "1.3.6.1.4.1.25623.1.0.10736"   # DCE/RPC and MSRPC Services Enumeration Reporting, 5.0
TCP_TS = "1.3.6.1.4.1.25623.1.0.80091"       # TCP Timestamps Information Disclosure, 2.6
ES_DETECT = "1.3.6.1.4.1.25623.1.0.105031"   # Elasticsearch Detection (HTTP), log
MAX_ROWS = 1000


def _feed() -> dict[str, list[tuple[str, str, float]]]:
    fams: dict[str, list[tuple[str, str, float]]] = {}
    # 1500 "Adobe ..." checks sort before "DCE/RPC ...", so a single capped
    # request (first 1000 by name) never reaches the DCE/RPC reporting check.
    fams["Windows"] = [(f"1.3.6.1.4.1.25623.1.1.{i}", f"Adobe Reader Windows advisory {i:05d}", 7.5)
                       for i in range(1500)]
    fams["Windows"] += [(DCE_REPORT, "DCE/RPC and MSRPC Services Enumeration Reporting", 5.0)]
    fams["Windows"] += [(f"1.3.6.1.4.1.25623.1.2.{i}", f"Microsoft Windows remote check {i:04d}", 9.8)
                        for i in range(372)]
    fams["Windows"] += [("1.3.6.1.4.1.25623.1.0.108044", "DCE/RPC and MSRPC Services Enumeration", 0.0)]
    fams["General"] = [(f"1.3.6.1.4.1.25623.1.3.{i}", f"Google Chrome advisory {i:05d}", 8.8) for i in range(2400)]
    fams["General"] += [(TCP_TS, "TCP Timestamps Information Disclosure", 2.6),
                        ("1.3.6.1.4.1.25623.1.0.51662", "Traceroute", 0.0)]
    fams["Product detection"] = [(ES_DETECT, "Elasticsearch Detection (HTTP)", 0.0),
                                 ("1.3.6.1.4.1.25623.1.0.105937", "OS Detection Consolidation and Reporting", 0.0)]
    fams["Service detection"] = [("1.3.6.1.4.1.25623.1.0.10330", "Services", 0.0)]
    fams["Port scanners"] = [("1.3.6.1.4.1.25623.1.0.14259", "Nmap (NASL wrapper)", 0.0)]
    fams["Settings"] = [("1.3.6.1.4.1.25623.1.0.12288", "Global variable settings", 0.0)]
    fams["Brute force attacks"] = [("1.3.6.1.4.1.25623.1.4.1", "Default credentials", 7.5)]
    fams["Denial of Service"] = [("1.3.6.1.4.1.25623.1.4.2", "Some DoS", 7.5)]
    fams["Windows Local Security Checks"] = [(f"1.3.6.1.4.1.25623.1.5.{i}", f"KB{i}", 8.1) for i in range(9000)]
    return fams


class RealGvmd:
    def __init__(self, drop_on_page2: bool = False):
        self.feed = _feed()
        self.drop_on_page2 = drop_on_page2
        self.info_filters: list[str] = []
        self.deleted: list[str] = []
        self._n = 0
        # config_id -> {"name", "comment", "in_use", "sel": {fam: ("whole", growing) | ("static", set)}}
        self.configs: dict[str, dict] = {
            "base1234-0000": {"name": "Aetheris Full and fast", "comment": "", "in_use": True,
                              "sel": {f: ("whole", True) for f in self.feed}},
        }

    # ---- helpers
    def _ids(self, fam):
        return [oid for oid, _n, _s in self.feed[fam]]

    def _selected(self, cid, fam):
        kind, val = self.configs[cid]["sel"].get(fam, (None, None))
        if kind == "whole":
            return set(self._ids(fam))
        return set(val or ())

    def add_config(self, name, sel, comment="", in_use=False):
        self._n += 1
        cid = f"cfg-{self._n}"
        self.configs[cid] = {"name": name, "comment": comment, "in_use": in_use, "sel": sel}
        return cid

    # ---- GMP surface used by the agent
    def get_feeds(self):
        return etree.fromstring(b"<r><feed><type>NVT</type><version>202610150000</version></feed>"
                                b"<feed><type>SCAP</type><version>202610150100</version></feed></r>")

    def get_scan_configs(self, filter_string=None, **_kw):
        rows = []
        for cid, c in self.configs.items():
            rows.append(f'<config id="{cid}"><name>{c["name"]}</name>'
                        f'<comment>{etree.Element("x").text or ""}{_esc(c["comment"])}</comment>'
                        f'<in_use>{1 if c["in_use"] else 0}</in_use></config>')
        return etree.fromstring(f"<r>{''.join(rows)}</r>".encode())

    def get_scan_config(self, cid, tasks=None):
        # Like gvmd (and GSA's "0 of N"): every feed family is listed, selected or not.
        fams, total = [], 0
        for fam in self.feed:
            sel = self._selected(cid, fam)
            kind, grow = self.configs[cid]["sel"].get(fam, (None, False))
            growing = 1 if kind == "whole" and grow else 0
            total += len(sel)
            fams.append(f"<family><name>{fam}</name><nvt_count>{len(sel)}</nvt_count>"
                        f"<max_nvt_count>{len(self.feed[fam])}</max_nvt_count><growing>{growing}</growing></family>")
        return etree.fromstring(
            f"<r><config id='{cid}'><nvt_count>{total}<growing>0</growing></nvt_count>"
            f"<families>{''.join(fams)}</families></config></r>".encode())

    def get_info(self, oid, info_type):
        for fam, rows in self.feed.items():
            if any(o == oid for o, _n, _s in rows):
                return etree.fromstring(f"<r><info id='{oid}'><nvt oid='{oid}'><family>{fam}</family></nvt></info></r>"
                                        .encode())
        raise RuntimeError("not found")

    def get_info_list(self, info_type, filter_string=None, details=None, **_kw):
        self.info_filters.append(filter_string)
        fam = re.search(r'family="([^"]+)"', filter_string).group(1)
        m = re.search(r"severity>([0-9.]+)", filter_string)
        floor = float(m.group(1)) if m else -1.0
        first = int((re.search(r"first=(-?\d+)", filter_string) or [None, "1"])[1])
        rows = int((re.search(r"rows=(-?\d+)", filter_string) or [None, "-1"])[1])
        if rows < 0 or rows > MAX_ROWS:  # gvmd "Max Rows Per Page": rows=-1 becomes 1000
            rows = MAX_ROWS
        matches = sorted((r for r in self.feed.get(fam, []) if r[2] > floor), key=lambda r: r[1])
        page = matches[first - 1:first - 1 + rows]
        if self.drop_on_page2 and first > 1 and page:
            page = page[1:]  # a page that loses a row: must be detected, never used
        infos = "".join(f"<info id='{oid}'><name>{name}</name></info>" for oid, name, _s in page)
        return etree.fromstring(f"<r>{infos}<info_count><filtered>{len(matches)}</filtered>"
                                f"<page>{len(page)}</page></info_count></r>".encode())

    def clone_scan_config(self, cid):
        new = self.add_config(f"Clone of {self.configs[cid]['name']}",
                              {k: (v[0], v[1] if v[0] == "whole" else set(v[1])) for k, v in
                               self.configs[cid]["sel"].items()})
        return {"id": new}

    def modify_scan_config_set_name(self, cid, name):
        self.configs[cid]["name"] = name

    def modify_scan_config_set_comment(self, cid, *, comment=None):  # keyword-only, as in python-gvm
        self.configs[cid]["comment"] = comment or ""

    def modify_scan_config_set_family_selection(self, cid, families, *, auto_add_new_families=True):
        sel = {}
        for fam, growing, all_nvts in families:
            sel[fam] = ("whole", True) if growing and all_nvts else ("static", set(self._ids(fam)) if all_nvts else set())
        self.configs[cid]["sel"] = sel

    def modify_scan_config_set_nvt_selection(self, cid, family, nvt_oids):
        self.configs[cid]["sel"][family] = ("static", set(nvt_oids))

    def modify_scan_config_set_scanner_preference(self, cid, name, *, value=None):
        pass

    def modify_scan_config_set_nvt_preference(self, cid, name, nvt_oid, value=None):
        pass

    def delete_scan_config(self, cid, *, ultimate=False):
        if self.configs[cid]["in_use"]:
            raise RuntimeError("Config is in use")
        self.deleted.append(self.configs[cid]["name"])
        del self.configs[cid]


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


BASE = "base1234-0000"


# --- the field mechanism ------------------------------------------------------------
def test_gvmd_row_cap_is_what_hid_the_medium_finding():
    """One V1.6.8-style request per family returns 1000 rows; 10736 sits at row 1501."""
    g = RealGvmd()
    resp = g.get_info_list(gmp_local._nvt_info_type(), filter_string='family="Windows" severity>0 rows=-1',
                           details=False)
    oids = gmp_local._info_oids(resp)
    assert len(oids) == 1000 and DCE_REPORT not in oids
    assert gmp_local._filtered_total(resp) == 1873  # gvmd says how many it did not send


# --- default scope: whole families ---------------------------------------------------
def test_vulnerability_scope_runs_the_checks_the_field_scans_lost(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    cid, status = gmp_local._ensure_check_scope_config(g, BASE)
    assert cid != BASE and status["config"].startswith("created Aetheris vuln-scope v2 ")
    assert DCE_REPORT in g._selected(cid, "Windows")
    assert TCP_TS in g._selected(cid, "General")
    assert ES_DETECT in g._selected(cid, "Product detection")
    assert g._selected(cid, "Brute force attacks") == set() and g._selected(cid, "Denial of Service") == set()
    assert g.info_filters == []  # nothing enumerated, nothing to truncate
    assert status["verification"]["ok"] and status["verification"]["partial_families"] == {}
    saved = json.loads(g.configs[cid]["comment"])  # the comment is really stored now
    assert saved["scope"] == "vulnerability" and saved["version"] == "v2"


def test_reuse_is_verified_and_logged_with_real_counts(monkeypatch, caplog):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    first, _ = gmp_local._ensure_check_scope_config(g, BASE)
    caplog.set_level("INFO", logger="scanner_agent.gmp")
    again, status = gmp_local._ensure_check_scope_config(g, BASE)
    assert again == first and status["config"].startswith("reused")
    assert status["verification"]["ok"]
    assert "reused" in caplog.text and "None checks" not in caplog.text


def test_a_stored_config_that_lost_checks_is_rebuilt_not_reused(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    first, _ = gmp_local._ensure_check_scope_config(g, BASE)
    g.configs[first]["sel"]["Windows"] = ("static", set(g._ids("Windows")[:1000]))  # truncated in place
    second, status = gmp_local._ensure_check_scope_config(g, BASE)
    assert second != first and status["config"].startswith("created")
    assert DCE_REPORT in g._selected(second, "Windows")


def test_legacy_v168_snapshot_is_retired_and_never_reused(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    legacy_sel = {f: ("whole", True) for f in g.feed if f.endswith(("Local Security Checks", "detection",
                                                                     "scanners", "Settings"))}
    legacy_sel["Windows"] = ("static", set(g._ids("Windows")[:1000]))
    legacy = g.add_config("Aetheris vuln-scope 7bb0ab6de1-base1234", legacy_sel, comment="")
    cid, status = gmp_local._ensure_check_scope_config(g, BASE)
    assert cid != legacy and legacy not in g.configs
    assert "Aetheris vuln-scope 7bb0ab6de1-base1234" in g.deleted
    assert DCE_REPORT in g._selected(cid, "Windows")


# --- opt-in severity scope: paged and verified ------------------------------------------
def test_severity_scope_pages_past_the_gvmd_row_cap(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    cid, status = gmp_local._ensure_check_scope_config(g, BASE, mode="severity")
    windows = g._selected(cid, "Windows")
    assert len(windows) == 1873 and DCE_REPORT in windows  # every severity>0 check, none dropped
    assert TCP_TS in g._selected(cid, "General")
    assert ES_DETECT in g._selected(cid, "Product detection")  # detection kept whole
    assert any("first=501" in f for f in g.info_filters)
    assert all("rows=500" in f for f in g.info_filters)
    assert status["verification"]["ok"]
    assert json.loads(g.configs[cid]["comment"])["static_counts"]["Windows"] == 1873


def test_an_incomplete_page_never_becomes_a_scan_config(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd(drop_on_page2=True)
    cid, status = gmp_local._ensure_check_scope_config(g, BASE, mode="severity")
    assert cid == BASE and "incomplete NVT list" in status["config"]  # falls back to all checks
    with pytest.raises(ValueError, match="incomplete NVT list"):
        gmp_local._ensure_check_scope_config(RealGvmd(drop_on_page2=True), BASE, {"min_severity": 4.0})


def test_dynamic_filter_is_paged_too():
    g = RealGvmd()
    cid, status = gmp_local._ensure_check_scope_config(g, BASE, {"min_severity": 7.0})
    assert status["scope"] == "dynamic"
    windows = g._selected(cid, "Windows")
    assert len(windows) == 1872 and DCE_REPORT not in windows  # 5.0 < 7.0, correctly excluded


# --- evidence ------------------------------------------------------------------------------
def test_effective_selection_reports_partial_families():
    g = RealGvmd()
    broken = g.add_config("x", {"Windows": ("static", set(g._ids("Windows")[:1000])),
                                "General": ("whole", True)})
    sel = gmp_local.effective_selection(g, broken)
    assert sel["available"] and sel["partial_families"] == {"Windows": "1000/1874"}


def test_excluded_families_are_not_reported_as_partial(monkeypatch):
    """gvmd lists unselected families as 0/N; that is excluded, not truncated."""
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    g = RealGvmd()
    cid, status = gmp_local._ensure_check_scope_config(g, BASE)
    sel = gmp_local.effective_selection(g, cid)
    assert sel["partial_families"] == {}
    assert sorted(sel["families_unselected"]) == ["Brute force attacks", "Denial of Service"]
    assert status["verification"]["partial_families"] == {}


def test_profile_config_comment_is_stored_so_reuse_reports_real_settings():
    g = RealGvmd()
    prefs = {"plugins_timeout": "320", "optimize_test": "yes"}
    cid, _ = gmp_local._ensure_profile_config(g, BASE, prefs, {}, None)
    assert json.loads(g.configs[cid]["comment"])["scanner_preferences"] == prefs
    again, status = gmp_local._ensure_profile_config(g, BASE, prefs, {}, None)
    assert again == cid and status["scanner_preferences"] == prefs  # was None in the field log
