"""V1.9.0 - the known-slow SSL/TLS cipher NVTs are bounded on every scan.

On a full-port scan the SSL/TLS cipher enumeration can pin a host at ~98% for
the whole scan window (OpenVAS does not time it out by default). We apply a
static per-NVT timeout cap from the first run so the scan reaches "Done",
instead of relying on the hang registry to learn it after repeated failures.
"""
from __future__ import annotations

import inspect

import pytest

from agent import scan_performance as sp


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("SSL_CIPHER_STATIC_CAP", "SSL_CIPHER_CAP_SEC"):
        monkeypatch.delenv(key, raising=False)


def test_static_caps_bound_the_ssl_cipher_nvts():
    caps = sp.static_caps()
    # The SSL/TLS cipher-suite report NVT (the usual tail offender) is capped.
    assert "1.3.6.1.4.1.25623.1.0.900234" in caps
    assert all(30 <= v <= 600 for v in caps.values())
    assert len(caps) >= 3


def test_budget_is_overridable_and_disableable(monkeypatch):
    monkeypatch.setenv("SSL_CIPHER_CAP_SEC", "90")
    assert set(sp.static_caps().values()) == {90}
    monkeypatch.setenv("SSL_CIPHER_STATIC_CAP", "off")
    assert sp.static_caps() == {}


def test_caps_are_applied_in_start_scan_not_only_learned():
    # start_scan merges static_caps() with the learned hang caps, so the SSL
    # cipher check is bounded even in the standard profile / first run.
    src = inspect.getsource(__import__("agent.gmp_local", fromlist=["x"]))
    assert "static_caps" in src
    assert "hang_caps = dict(static_caps())" in src


def test_port_scanners_are_still_never_capped():
    # The static caps must only touch SSL NVTs, never the port scanner / service
    # detection NVTs that define coverage.
    caps = sp.static_caps()
    assert "1.3.6.1.4.1.25623.1.0.14259" not in caps   # Nmap
    assert "1.3.6.1.4.1.25623.1.0.10330" not in caps   # Services
