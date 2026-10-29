"""Secondary (mobile) stacks skip boot firm migrations so the api starts promptly.

The mobile-ios api failed its healthcheck because it re-ran idempotent firm DDL
against the shared PostgreSQL the forensic stack owns, blocking on that stack's
locks for ~4 minutes. Mobile stacks now skip these at boot; the owning stack
still applies them, and an explicit env flag overrides either way.
"""
import importlib

import pytest

import app.services.firm_migrations as fm


@pytest.mark.parametrize("service,expected", [
    ("forensic", False),      # DB owner: the only stack that applies migrations
    ("mobile-ios", True),
    ("mobile-android", True),
    ("mobile-extract", True),
    ("vuln", True),           # shares the forensic DB -> skip, same as the log case
])
def test_default_skip_by_service(monkeypatch, service, expected):
    monkeypatch.delenv("AETHERIS_SKIP_BOOT_MIGRATIONS", raising=False)
    monkeypatch.setenv("AETHERIS_SERVICE", service)
    assert fm.boot_migrations_disabled() is expected


def test_only_forensic_runs_every_other_stack_skips(monkeypatch):
    monkeypatch.delenv("AETHERIS_SKIP_BOOT_MIGRATIONS", raising=False)
    from app.service_identity import VALID_SERVICES, FORENSIC

    for service in VALID_SERVICES:
        monkeypatch.setenv("AETHERIS_SERVICE", service)
        assert fm.boot_migrations_disabled() is (service != FORENSIC), service


def test_env_flag_forces_skip_on_primary(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    monkeypatch.setenv("AETHERIS_SKIP_BOOT_MIGRATIONS", "1")
    assert fm.boot_migrations_disabled() is True


def test_env_flag_forces_run_on_secondary(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-ios")
    monkeypatch.setenv("AETHERIS_SKIP_BOOT_MIGRATIONS", "0")
    assert fm.boot_migrations_disabled() is False


def test_apply_all_firm_migrations_short_circuits_when_skipped(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-ios")
    monkeypatch.delenv("AETHERIS_SKIP_BOOT_MIGRATIONS", raising=False)

    called = {"n": 0}

    def _should_not_run(*a, **k):
        called["n"] += 1
        raise AssertionError("apply_firm_migrations must not run on a skipped stack")

    monkeypatch.setattr(fm, "apply_firm_migrations", _should_not_run)
    # Must return 0 without querying Firms or applying anything.
    assert fm.apply_all_firm_migrations(db=None) == 0
    assert called["n"] == 0


def test_unknown_env_value_falls_back_to_service_default(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-ios")
    monkeypatch.setenv("AETHERIS_SKIP_BOOT_MIGRATIONS", "maybe")
    assert fm.boot_migrations_disabled() is True
