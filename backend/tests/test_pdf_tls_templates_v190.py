"""V1.9.0 central - the PDF-scoped templates are exposed and become built-in policies."""
from __future__ import annotations

import os

TLS_FOCUS = "aetheris_tls_sweet32"
PDF_REF = "aetheris_pdf_reference_audit"


def test_new_templates_are_in_the_shared_catalog():
    from app.services.scanner_service_policy import scan_templates

    by_key = {t["key"]: t for t in scan_templates()["templates"]}
    for key in (TLS_FOCUS, PDF_REF):
        t = by_key[key]
        assert t["vendor"] == "aetheris"
        assert t["nessus_template"] is None and t["nexpose_template"] is None
        assert t["name"].startswith("Aetheris \u00b7")


def test_new_templates_seed_as_builtin_policies():
    from app.services.builtin_scan_policies import builtin_name, seedable_templates

    keys = {t["key"] for t in seedable_templates()}
    assert {TLS_FOCUS, PDF_REF} <= keys
    by_key = {t["key"]: t for t in seedable_templates()}
    assert builtin_name(by_key[TLS_FOCUS]) == "Aetheris \u00b7 TLS/SSL & SWEET32 focus"
    assert builtin_name(by_key[PDF_REF]) == "Aetheris \u00b7 PDF reference audit (Fund Fox)"


def test_template_endpoint_exposes_the_new_templates():
    from app.routers import vuln

    os.environ.setdefault("VULN_MODULE_ENABLED", "true")
    out = {t["key"]: t for t in vuln.list_policy_templates(current=None)}
    for key in (TLS_FOCUS, PDF_REF):
        assert key in out
        assert out[key]["vendor"] == "aetheris"
        assert out[key]["seed_as_builtin"] is True
        # Launchable without credentials (unauthenticated-safe).
        assert not out[key].get("requires_credentials")


def test_tls_focus_scope_targets_sweet32_across_tls_ports():
    from app.services.scanner_service_policy import effective_policy, port_numbers, validate_request

    req = validate_request({"template": TLS_FOCUS})
    assert set(req["nvt_families"]) == {"SSL and TLS", "SSH"}
    assert "CVE-2016-2183" in set(req["cve_watchlist"])  # SWEET32
    rng = effective_policy({"template": TLS_FOCUS})["port_range"]
    tcp = {p for tok in rng.split(",") if tok.startswith("T:") for p in port_numbers(tok[2:])}
    # TLS is not limited to 443: mail, LDAPS, database and broker TLS ports are in.
    assert {443, 636, 3306, 5671, 993} <= tcp
