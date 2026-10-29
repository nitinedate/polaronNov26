"""V1.9.0 - base scan-config resolution falls back to the Aetheris-renamed copy.

This Aetheris deployment re-imports the stock Greenbone "Full and fast" config
under the name "Aetheris Full and fast"; the stock name/ID may be absent. The
readiness check must then use the Aetheris copy instead of failing with
"Scan config not found: Full and fast".
"""
from __future__ import annotations

from lxml import etree

from agent import gmp_local as mod


def _gmp(configs):
    rows = "".join(f'<config id="{cid}"><name>{n}</name></config>' for n, cid in configs)

    class G:
        def get_scan_configs(self, **kwargs):
            return etree.fromstring(f"<r>{rows}</r>".encode())

    return G()


# Exactly the configs from the field log where the scan would not start.
LOG_CONFIGS = [
    ("Aetheris Full and fast", "aff-1"),
    ("Aetheris profile b2cd93560b", "p1"),
    ("Aetheris vuln-scope 7bb0ab6de1-d78f6a78", "v1"),
    ("Base", "base-1"),
]


def test_stock_full_and_fast_absent_falls_back_to_aetheris_copy():
    assert mod._find_config_id(_gmp(LOG_CONFIGS), "Full and fast") == "aff-1"


def test_stock_full_and_fast_present_is_still_preferred():
    configs = [("Full and fast", "stock-1"), ("Aetheris Full and fast", "aff-1"), ("Base", "b")]
    assert mod._find_config_id(_gmp(configs), "Full and fast") == "stock-1"


def test_stock_full_and_fast_by_canonical_id_still_resolves():
    configs = [("Full and fast", mod.FULL_AND_FAST_ID), ("Base", "b")]
    assert mod._find_config_id(_gmp(configs), "Full and fast") == mod.FULL_AND_FAST_ID


def test_explicit_aetheris_request_resolves_by_name():
    assert mod._find_config_id(_gmp(LOG_CONFIGS), "Aetheris Full and fast") == "aff-1"


def test_truly_missing_config_still_raises():
    import pytest

    with pytest.raises(RuntimeError) as exc:
        mod._find_config_id(_gmp([("Base", "b")]), "Full and fast")
    assert "Scan config not found" in str(exc.value)


def test_fallback_does_not_hijack_a_different_named_request():
    # A non-full-and-fast name that is genuinely absent must still raise, not be
    # silently replaced by the Aetheris base config.
    import pytest

    with pytest.raises(RuntimeError):
        mod._find_config_id(_gmp(LOG_CONFIGS), "Host Discovery")
