"""V1.9.0 - PDF-scoped scan templates: TLS/SSL & SWEET32 focus and Fund Fox reference audit.

These templates are defined from the Aetheris scanner implementation guide (v2.0,
52-service matrix, section 9 TLS/SSL and SWEET32) and the Fund Fox gap report
(eight finding types). They have no Nessus or Nexpose equivalent, so they are
Aetheris-vendor templates and carry neither vendor label.
"""
from __future__ import annotations

import pytest

from agent.service_policy import (
    credential_gap,
    effective_policy,
    port_numbers,
    scan_templates,
    validate_request,
)

TLS_FOCUS = "aetheris_tls_sweet32"
PDF_REF = "aetheris_pdf_reference_audit"

# Every TLS/STARTTLS-bearing port the SWEET32 / SSLv2-3 / weak-cipher checks apply
# to, beyond 443: mail, LDAP(S), database TLS, broker TLS, WinRM HTTPS, FTPS, DoT.
TLS_SENTINEL_PORTS = (443, 8443, 25, 465, 587, 110, 995, 143, 993, 389, 636,
                      3268, 3269, 1433, 3306, 5432, 27017, 5671, 5986, 990, 853, 631)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "SCAN_TCP_CUSTOM_PORTS",
                "SCAN_UDP_CUSTOM_PORTS", "SERVICE_EXTRA_TCP_PORTS", "SERVICE_EXTRA_UDP_PORTS"):
        monkeypatch.delenv(key, raising=False)


def _tcp(spec: str) -> set[int]:
    return {p for tok in spec.split(",") if tok.startswith("T:") for p in port_numbers(tok[2:])}


def _udp(spec: str) -> set[int]:
    return {p for tok in spec.split(",") if tok.startswith("U:") for p in port_numbers(tok[2:])}


def test_both_templates_are_registered_and_aetheris_vendor():
    by_key = {t["key"]: t for t in scan_templates()["templates"]}
    assert TLS_FOCUS in by_key and PDF_REF in by_key
    for key in (TLS_FOCUS, PDF_REF):
        t = by_key[key]
        assert t["vendor"] == "aetheris"
        assert t["category"] == "vulnerability"
        assert t["nessus_template"] is None and t["nexpose_template"] is None
        assert t["name"].startswith("Aetheris \u00b7")
        assert t["seed_as_builtin"] is True
        # Unauthenticated-safe: launchable without a credential reference.
        assert credential_gap(validate_request({"template": key})) is None


def test_tls_focus_pins_ssl_tls_family_across_every_tls_port():
    req = validate_request({"template": TLS_FOCUS})
    # The SSL and TLS family is what carries the SWEET32 / SSLv2-3 / weak-cipher
    # checks; SSH is included for the OpenSSH/Dropbear report findings.
    assert set(req["nvt_families"]) == {"SSL and TLS", "SSH"}

    policy = effective_policy({"template": TLS_FOCUS})
    tcp = _tcp(policy["port_range"])
    # TLS is not restricted to 443: every TLS/STARTTLS-bearing port is in scope.
    missing = [p for p in TLS_SENTINEL_PORTS if p not in tcp]
    assert not missing, f"TLS-bearing ports missing from focus scope: {missing}"
    # UDP is off for the focused TLS audit.
    assert policy["udp_profile"] == "off"
    assert _udp(policy["port_range"]) == set()


def test_tls_focus_watchlist_flags_sweet32_and_legacy_ssl():
    req = validate_request({"template": TLS_FOCUS})
    watch = set(req["cve_watchlist"])
    assert "CVE-2016-2183" in watch  # SWEET32 (64-bit block / 3DES)
    assert "CVE-2016-0800" in watch  # DROWN (SSLv2)
    assert "CVE-2014-3566" in watch  # POODLE (SSLv3)


def test_pdf_reference_audit_covers_the_eight_fund_fox_families():
    req = validate_request({"template": PDF_REF})
    families = set(req["nvt_families"])
    # SSLv2/3 + SWEET32 -> SSL and TLS; OpenSSH/Dropbear -> SSH; SMB shares -> Windows.
    assert {"SSL and TLS", "SSH", "Windows"} <= families

    policy = effective_policy({"template": PDF_REF})
    tcp = _tcp(policy["port_range"])
    # The full service port policy (SMB 139/445, web, databases) plus TLS ports.
    assert {139, 445} <= tcp          # Windows SMB share-access finding
    assert {443, 636, 3306, 9200} <= tcp  # TLS on web, LDAPS, DB, Elasticsearch
    # UDP priority stays on for the comprehensive audit (SNMP/NTP/etc.).
    assert policy["udp_profile"] == "priority"
    assert policy["udp_port_count"] > 0

    watch = set(req["cve_watchlist"])
    assert "CVE-2016-2183" in watch   # SWEET32 is one named part of the audit
    assert len(watch) >= 10           # SSH/Dropbear/legacy-SSL families included


def test_explicit_settings_still_override_the_new_templates():
    # A policy may widen/narrow: e.g. turn UDP on for the TLS focus, or add ports.
    req = validate_request({"template": TLS_FOCUS, "udp_profile": "priority"})
    assert req["udp_profile"] == "priority"
    tcp = _tcp(effective_policy({"template": PDF_REF, "custom_tcp_ports": [4443]})["port_range"])
    assert 4443 in tcp
