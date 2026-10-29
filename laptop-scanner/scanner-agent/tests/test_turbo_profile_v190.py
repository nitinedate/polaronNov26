"""V1.9.0 - turbo performance profile: high per-host NVT concurrency for one IP.

The only concurrency that speeds up a single IP is running more NVT checks at
once against that host. Turbo scales per-host check concurrency with CPU count
(coverage unchanged) and shortens the per-check tail so a stuck NVT can't pin
the host at 98%.
"""
from __future__ import annotations

import pytest

from agent import scan_performance as sp


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("SCAN_PERFORMANCE", "TURBO_MAX_CHECKS", "TURBO_CHECKS_PER_CPU",
                "TURBO_MAX_CHECKS_CAP", "TURBO_CHECKS_READ_TIMEOUT",
                "TURBO_PLUGINS_TIMEOUT", "TURBO_NMAP_TIMING", "NVT_HANG_CAPS"):
        monkeypatch.delenv(key, raising=False)


def test_turbo_is_a_recognised_profile():
    assert "turbo" in sp.PROFILES


def test_turbo_resolves_from_env_and_request(monkeypatch):
    monkeypatch.setenv("SCAN_PERFORMANCE", "turbo")
    assert sp.resolve_profile() == "turbo"
    # A per-policy request wins over the env.
    assert sp.resolve_profile({"performance": "standard"}) == "standard"


def test_turbo_scales_max_checks_with_cpu(monkeypatch):
    monkeypatch.setattr(sp, "_cpu_count", lambda: 8)
    monkeypatch.setenv("TURBO_CHECKS_PER_CPU", "4")
    monkeypatch.setenv("TURBO_MAX_CHECKS_CAP", "40")
    # 8 CPUs * 4 = 32 concurrent checks (vs Nessus-default 5).
    assert sp.turbo_max_checks() == 32
    assert sp.profile_settings("turbo")["max_checks"] == 32


def test_turbo_is_capped_and_floored(monkeypatch):
    monkeypatch.setattr(sp, "_cpu_count", lambda: 64)
    monkeypatch.setenv("TURBO_MAX_CHECKS_CAP", "40")
    assert sp.turbo_max_checks() == 40  # capped
    monkeypatch.setattr(sp, "_cpu_count", lambda: 1)
    assert sp.turbo_max_checks() == 10  # floor keeps a 1-core box usable


def test_turbo_absolute_override_wins(monkeypatch):
    monkeypatch.setattr(sp, "_cpu_count", lambda: 8)
    monkeypatch.setenv("TURBO_MAX_CHECKS", "24")
    assert sp.turbo_max_checks() == 24


def test_turbo_tightens_the_tail_vs_standard():
    turbo = sp.profile_settings("turbo")
    fast = sp.profile_settings("fast")
    standard = sp.profile_settings("standard")
    # Shorter per-check ceiling than fast (320) so a stuck NVT costs less.
    assert turbo["plugins_timeout"] == 180
    assert turbo["nmap_timing"] == "Aggressive"
    assert turbo["hang_caps"] is True
    # Turbo runs more checks at once than fast.
    assert turbo["max_checks"] >= fast["max_checks"]
    # Standard still means "keep the configured values" (no override).
    assert standard["max_checks"] is None and standard["plugins_timeout"] is None


def test_coverage_is_not_reduced_by_turbo():
    """Turbo changes concurrency/timeouts only - it must not drop families or ports."""
    s = sp.profile_settings("turbo")
    # No 'families' / 'ports' / 'scope' key exists in the perf settings at all.
    assert set(s.keys()) == {"checks_read_timeout", "max_checks", "nmap_timing",
                             "hang_caps", "plugins_timeout"}
