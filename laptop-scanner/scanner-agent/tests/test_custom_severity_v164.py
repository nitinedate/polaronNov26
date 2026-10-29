"""Laptop Greenbone parser, service logs, and local policy agree."""
import pytest

from agent.severity_policy import cvss_severity, severity_thresholds
from agent.gmp_local import _severity_from_cvss
from agent.service_audit import _severity


@pytest.mark.parametrize("score,expected", [(0, "Info"), (0.1, "Low"), (3.99, "Low"),
    (4, "Medium"), (5.99, "Medium"), (6, "High"), (7.99, "High"), (8, "Critical"), (10, "Critical")])
def test_consistent_laptop_labels(score, expected):
    assert cvss_severity(score).replace("None", "Info") == expected
    assert _severity_from_cvss(score) == expected.lower()
    assert _severity({"cvss": score, "severity": "low"}) == expected


def test_laptop_override_applies_to_report_and_logs(monkeypatch):
    monkeypatch.setenv("VULN_SEVERITY_CRITICAL_MIN", "8.5")
    assert _severity_from_cvss(8.2) == "high"
    assert _severity({"cvss": 8.2, "severity": "critical"}) == "High"


def test_invalid_bounds_fail(monkeypatch):
    monkeypatch.setenv("VULN_SEVERITY_HIGH_MIN", "9")
    with pytest.raises(ValueError):
        severity_thresholds()
