"""CVSS severity with an explicit version basis and retained source signals."""
from __future__ import annotations

import math
import os
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_basis(value: str | None = None) -> str:
    raw = str(value or os.environ.get("VULN_SEVERITY_BASIS") or "cvss_v3").strip().lower()
    raw = raw.replace(".", "").replace(" ", "").replace("_", "")
    return "cvss_v2" if raw in {"cvssv2", "cvss2", "2", "cvssv20"} else "cvss_v4" if raw in {"cvssv4", "cvss4", "4", "cvssv40"} else "cvss_v3"


def valid_score(value: Any, maximum: float = 10.0) -> float | None:
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and 0 <= number <= maximum else None


def choose_cvss_score(row: dict[str, Any], basis: str | None = None) -> tuple[float, str, dict[str, float | None]]:
    aliases = {
        "cvss_v2": ("cvss_v2", "cvss2", "cvss_v2_base", "cvss2_base", "cvss2_base_score"),
        "cvss_v3": ("cvss_v3", "cvss3", "cvss_v3_base", "cvss3_base", "cvss3_base_score"),
        "cvss_v4": ("cvss_v4", "cvss4", "cvss_v4_base", "cvss4_base", "cvss4_base_score"),
    }
    candidates: dict[str, float | None] = {}
    for name, keys in aliases.items():
        values = [score for key in keys if (score := valid_score(row.get(key))) is not None]
        candidates[name] = max(values) if values else None
    for name in ("score", "cvss", "cvss_base", "greenbone_result_severity", "greenbone_nvt_cvss_base", "severity"):
        value = valid_score(row.get(name))
        if value is not None:
            candidates[name] = value
    signals = row.get("greenbone_score_signals")
    if isinstance(signals, dict):
        for name, raw in signals.items():
            value = valid_score(raw)
            if value is not None:
                candidates["greenbone." + str(name)] = value
    preferred = severity_basis(basis)
    for name in dict.fromkeys((preferred, "cvss_v3", "cvss_v2", "cvss_v4")):
        if candidates[name] is not None:
            return float(candidates[name]), name, candidates
    generic = {name: value for name, value in candidates.items() if value is not None}
    if generic:
        source = max(generic, key=lambda name: float(generic[name]))
        return float(generic[source]), source, candidates
    return 0.0, "unavailable", candidates


# Customer-defined assessment bands (not the standard CVSS qualitative bands).
# The numeric CVSS vector and its version remain unchanged for traceability.
DEFAULT_SEVERITY_THRESHOLDS = {"critical": 8.0, "high": 6.0, "medium": 4.0, "low": 0.1}


def severity_thresholds() -> dict[str, float]:
    result: dict[str, float] = {}
    for label, default in DEFAULT_SEVERITY_THRESHOLDS.items():
        raw = os.environ.get(f"VULN_SEVERITY_{label.upper()}_MIN", str(default))
        try:
            number = float(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid severity threshold for {label}: {raw!r}") from exc
        if not math.isfinite(number) or not 0 <= number <= 10:
            raise ValueError(f"Invalid severity threshold for {label}: {raw!r}")
        result[label] = number
    if not (result["critical"] > result["high"] > result["medium"] > result["low"] > 0):
        raise ValueError("Vulnerability severity thresholds must be strictly descending and positive")
    return result


def severity_from_cvss(cvss: float, basis: str | None = None) -> str:
    """Apply the configured organization bands, uniformly for CVSS v2/v3/v4.

    ``basis`` selects score provenance upstream; it does not change the
    organization-specific severity thresholds.
    """
    score = valid_score(cvss) or 0.0
    for label, minimum in severity_thresholds().items():
        if score >= minimum:
            return label
    return "info"


def apply_policy_floors(synopsis: str, severity: str) -> tuple[str, None]:
    """Compatibility API: descriptions never override technical severity."""
    return severity, None


def classify_severity(*, cvss: float = 0.0, synopsis: str = "", raw_severity: Any = None,
                      basis: str | None = None) -> tuple[str, None]:
    return severity_from_cvss(cvss, basis), None


def aetheris_severity_sql(alias: str = "f") -> str:
    """Exactly mirror Python thresholds when filtering/counting stored findings."""
    prefix = f"{alias}." if alias else ""
    bounds = severity_thresholds()
    # All values are validated floats, not untrusted SQL fragments.
    return f"""CASE
  WHEN COALESCE({prefix}cvss, 0) >= {bounds['critical']:g} THEN 'critical'
  WHEN COALESCE({prefix}cvss, 0) >= {bounds['high']:g} THEN 'high'
  WHEN COALESCE({prefix}cvss, 0) >= {bounds['medium']:g} THEN 'medium'
  WHEN COALESCE({prefix}cvss, 0) >= {bounds['low']:g} THEN 'low'
  ELSE 'info'
END"""
