"""V1.6.4 severity bands: all scoring paths must agree, including SQL."""
import pytest

from app.services.aetheris_severity import severity_from_cvss, aetheris_severity_sql, severity_thresholds
from app.services.multi_scanner_clients import _severity_label
from app.services.vuln_nessus_parity import _severity_from_cvss


@pytest.mark.parametrize("score,expected", [
    (0, "info"), (0.1, "low"), (3.99, "low"),
    (4, "medium"), (5.99, "medium"), (6, "high"),
    (7.99, "high"), (8, "critical"), (10, "critical"),
])
def test_all_python_score_classifiers(score, expected):
    assert severity_from_cvss(score) == expected
    assert _severity_label(score) == expected
    assert _severity_from_cvss(score) == expected


def test_dynamic_sql_bands_match_python():
    sql = aetheris_severity_sql("f")
    assert "f.cvss" in sql
    assert ">= 8" in sql and "'critical'" in sql
    assert ">= 6" in sql and "'high'" in sql
    assert ">= 4" in sql and "'medium'" in sql
    assert ">= 0.1" in sql and "'low'" in sql


def test_env_customization_is_respected_everywhere(monkeypatch):
    monkeypatch.setenv("VULN_SEVERITY_CRITICAL_MIN", "8.5")
    monkeypatch.setenv("VULN_SEVERITY_HIGH_MIN", "6.5")
    assert severity_from_cvss(8.2) == "high"
    assert ">= 8.5" in aetheris_severity_sql("f")
    assert ">= 6.5" in aetheris_severity_sql("f")


@pytest.mark.parametrize("values", [
    {"CRITICAL": "not-a-number"},
    {"HIGH": "Infinity"},
    {"CRITICAL": "5.0", "HIGH": "6.0"},
])
def test_invalid_env_fails_explicitly(monkeypatch, values):
    for k, v in values.items():
        monkeypatch.setenv(f"VULN_SEVERITY_{k}_MIN", v)
    with pytest.raises(ValueError):
        severity_thresholds()
