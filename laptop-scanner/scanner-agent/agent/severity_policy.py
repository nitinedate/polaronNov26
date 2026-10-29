"""Organization-specific CVSS severity labels for laptop scan findings.

Numeric CVSS scores are not altered; the labels below intentionally differ
from standard CVSS qualitative bands.
"""
from __future__ import annotations

import math
import os

DEFAULT_THRESHOLDS = {"CRITICAL": 8.0, "HIGH": 6.0, "MEDIUM": 4.0, "LOW": 0.1}


def severity_thresholds() -> dict[str, float]:
    bounds: dict[str, float] = {}
    for label, default in DEFAULT_THRESHOLDS.items():
        raw = os.environ.get(f"VULN_SEVERITY_{label}_MIN", str(default))
        try:
            number = float(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid {label} severity threshold: {raw!r}") from exc
        if not math.isfinite(number) or not 0 <= number <= 10:
            raise ValueError(f"Invalid {label} severity threshold: {raw!r}")
        bounds[label] = number
    if not (bounds["CRITICAL"] > bounds["HIGH"] > bounds["MEDIUM"] > bounds["LOW"] > 0):
        raise ValueError("Vulnerability severity thresholds must be strictly descending and positive")
    return bounds


def cvss_severity(score: float | None, *, informational: bool = False) -> str:
    if informational:
        return os.getenv("VULN_SEVERITY_INFORMATIONAL", "Info")
    if score is None:
        return os.getenv("VULN_SEVERITY_UNSCORED", "Unscored")
    if isinstance(score, bool):
        raise ValueError("CVSS score must be numeric")
    try:
        value = float(score)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("CVSS score must be numeric") from exc
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError("CVSS score must be between 0 and 10")
    for name, minimum in severity_thresholds().items():
        if value >= minimum:
            return name.title()
    return "None"
