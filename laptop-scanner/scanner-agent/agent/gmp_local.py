"""Local Greenbone GMP client for the Aetheris laptop scanner agent."""

from __future__ import annotations

import hashlib
import json
import threading
import logging
import math
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator
from urllib.parse import urlparse

from agent.severity_policy import cvss_severity
from agent.service_policy import (
    NESSUS_IANA_PORT_LIST,
    NESSUS_MODES,
    analyze_services,
    credential_gap,
    effective_policy,
    format_ports,
    mark_cve_watchlist,
    port_numbers,
)

log = logging.getLogger("scanner_agent.gmp")

# V1.9.3: serialises scan-config lookup/creation across concurrent IP starts.
_CONFIG_PREP_LOCK = threading.RLock()

# V1.9.5: OpenVAS settings that must NOT be carried on a scan config. gvmd sends
# every scan-config scanner preference to ospd with yes/no rewritten to "1"/"0"
# (gvmd manage_osp.c); ospd turns "1" back into "yes" only for its own boolean
# params (ospd_openvas/daemon.py OSPD_PARAMS), and these are not among them; OpenVAS
# treats only the exact string "yes" as true (gvm-libs prefs_get_bool). A value
# on the config therefore always reads as "off" and overrides openvas.conf.
# V1.9.3 set log_whole_attack=yes this way and so switched per-check logging OFF.
_OPENVAS_CONF_ONLY_PREFS = ("log_whole_attack",)

# V1.9.6: next time the "Base config not present" note may be logged again.
_BASE_CONFIG_NOTE_AT = 0.0

FULL_AND_FAST_ID = "daba56c8-73ec-11df-a475-002264764cea"
AETHERIS_SCAN_CONFIG = "Aetheris Full and fast"
NMAP_NVT_OID = "1.3.6.1.4.1.25623.1.0.14259"

# Legacy named TCP profiles remain available. The versioned service policy
# adds every explicit TCP service in the guide, including custom ports.
FAST_PORTS = (
    "T:21-23,T:25,T:53,T:80,T:81,T:88,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:631,T:993,T:995,T:1433,T:1521,T:1723,T:2049,"
    "T:3000,T:3306,T:3389,T:5432,T:5672,T:5900,T:5985,T:6379,T:6443,"
    "T:8080,T:8443,T:9000,T:9418,T:27017"
)

# Nessus-style vulnerability ports. Every IP uses this set when PORT_PROFILE=vuln.
# Dropped from the fast list because they produce informational results only
# (service banners, name lookups) and no vulnerability severity: 81, 88, 631,
# 1723, 3000, 5672, 9000, 9418. SSH, TLS, SMB, databases, RDP and the admin
# web ports stay, because those are where low/medium/high/critical findings are.
VULN_PORTS = (
    "T:21-23,T:25,T:53,T:80,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:993,T:995,T:1433,T:1521,T:2049,"
    "T:3306,T:3389,T:5432,T:5900,T:5985-5986,T:6379,T:6443,"
    "T:8080,T:8443,T:9200,T:27017"
)
# Kept for compatibility; the effective policy includes the guide UDP baseline.
VULN_UDP_PORTS = "U:161,U:623,U:11211"
_VULN_PROFILES = frozenset({"vuln", "nexus", "nessus"})

# High-value UDP services commonly relevant to infrastructure/IP assessment.
# GMP port_range requires each comma-separated range to carry T:/U: explicitly.
# Full UDP (1-65535) remains available through UDP_PROFILE=full, but is not the
# default because exhaustive UDP can dominate scan time on filtered networks.
PRIORITY_UDP_PORTS = (
    "U:53,U:67-69,U:88,U:111,U:123,U:137-138,U:161-162,U:389,U:500,U:514,U:520,U:623,U:902,U:1434,"
    "U:1701,U:1812-1813,U:1900,U:2049,U:3389,U:4500,U:4789,U:5004,U:5060,U:5353,U:11211"
)


def _normalize_udp_port_range(value: str) -> str:
    out: list[str] = []
    for raw in (value or "").split(","):
        token = raw.strip()
        if not token:
            continue
        if token.upper().startswith("U:"):
            token = token[2:].strip()
        if token:
            out.append(f"U:{token}")
    return ",".join(out)


def _udp_port_range(profile: str | None = None) -> str:
    raw = (profile if profile is not None else os.environ.get("UDP_PROFILE") or "priority").strip().lower()
    if raw in {"off", "none", "disabled", "false", "0"}:
        return ""
    if raw in {"full", "all", "1-65535"}:
        return "U:1-65535"
    custom = (os.environ.get("UDP_PORT_RANGE") or "").strip()
    if custom:
        return _normalize_udp_port_range(custom)
    return PRIORITY_UDP_PORTS


def _with_udp_range(tcp_range: str, udp_profile: str | None = None) -> str:
    base = (tcp_range or "").strip().rstrip(",")
    if not base:
        base = "T:1-65535"
    if any(part.strip().upper().startswith("U:") for part in base.split(",")):
        return base
    udp = _udp_port_range(udp_profile)
    return f"{base},{udp}" if udp else base


def _default_scan_port_range(port_profile: str, udp_profile: str | None = None) -> str:
    return _effective_scan_policy(None, port_profile, udp_profile)["port_range"]


def _effective_scan_policy(request: dict[str, Any] | None, port_profile: str,
                           udp_profile: str | None) -> dict[str, Any]:
    from agent.vuln_ports import port_document

    req = dict(request or {})
    from agent.service_policy import expand_template

    req = expand_template(req)
    mode = str(req.get("port_profile") or port_profile or os.environ.get("PORT_PROFILE") or "nexus").strip().lower()
    req["port_profile"] = mode
    port_profile = mode
    if mode in {"focused", "nexus", "catalog"}:
        # focused: exactly the listed ports. nexus/catalog (V1.7.0): exactly the
        # service port policy. No catalog/fast-list padding in either case.
        return effective_policy(req, port_profile=mode, udp_profile=udp_profile, catalog_tcp=[], catalog_udp=[])
    catalog = port_document()
    tcp = [port for item in catalog["tcp"] for port in port_numbers(item["ports"])]
    udp = port_numbers(PRIORITY_UDP_PORTS.replace("U:", ""))
    udp += [port for item in catalog["udp"] for port in port_numbers(item["ports"])]
    # Fast/Common add their historical common ports to the mandatory guide set.
    tcp += port_numbers(FAST_PORTS.replace("T:", ""))
    return effective_policy(req, port_profile=port_profile, udp_profile=udp_profile,
                            catalog_tcp=tcp, catalog_udp=udp)

def _report_filter_string(*, first: int | None = None, rows: int | None = None) -> str:
    """Fetch Greenbone results. Default is the full set (rows=-1)."""
    raw = (os.environ.get("GVM_REPORT_MIN_QOD") or "0").strip()
    try:
        min_qod = int(raw)
    except (TypeError, ValueError):
        min_qod = 0
    min_qod = max(0, min(100, min_qod))
    parts: list[str] = []
    if first is not None:
        parts.append(f"first={max(1, int(first))}")
    if rows is not None:
        parts.append(f"rows={int(rows)}")
    elif first is None:
        parts.append("rows=-1")
    parts.append(f"min_qod={min_qod}")
    return " ".join(parts)


def _gmp_connection_lost(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "remote closed",
            "connection reset",
            "broken pipe",
            "timed out",
            "timeout",
            "socket is closed",
            "not connected",
        )
    )


def _gmp_timeout() -> float:
    try:
        return max(30.0, float(os.environ.get("GVM_GMP_TIMEOUT") or 300))
    except (TypeError, ValueError):
        return 300.0


def _report_page_rows() -> int:
    try:
        return max(50, int(os.environ.get("GVM_REPORT_PAGE_ROWS") or 200))
    except (TypeError, ValueError):
        return 200


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_from_cvss(cvss: float) -> str:
    return cvss_severity(cvss).lower().replace("none", "info")


def _canonical_severity(threat: str | None, cvss: float) -> str:
    """Return Nessus-compatible CVSS severity only.

    Greenbone's legacy ``threat`` text is retained in the result payload for
    audit/debugging, but it must not change the technical severity shown by
    Polaron.  Nessus severity bands are driven by the numeric CVSS score.
    """
    del threat
    return _severity_from_cvss(cvss)


def _valid_cvss(value: Any) -> float | None:
    """Parse a valid 0..10 score without treating the string ``0.0`` as missing."""
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or score < 0.0 or score > 10.0:
        return None
    return score


def _best_cvss(nvt: Any, result: Any, tag_values: dict[str, str]) -> tuple[float, str, dict[str, float]]:
    """Choose the strongest numeric technical severity signal in a GMP result.

    Greenbone report variants are inconsistent: some put the usable score on
    ``result/severity`` while ``nvt/cvss_base`` is literally ``0.0``.  The old
    ``a or b`` parser considered the string ``0.0`` truthy and silently threw
    away the real result score.  Keep every parsed candidate for traceability
    and use the highest valid score, matching Nessus' highest-risk-factor
    presentation when multiple CVSS signals describe the same finding.
    """
    raw_candidates: list[tuple[str, Any]] = [
        ("result.severity", result.findtext("severity")),
        ("nvt.cvss_base", nvt.findtext("cvss_base")),
        ("nvt.cvss2_base", nvt.findtext("cvss2_base")),
        ("nvt.cvss_v2_base", nvt.findtext("cvss_v2_base")),
        ("nvt.cvss3_base", nvt.findtext("cvss3_base")),
        ("nvt.cvss_v3_base", nvt.findtext("cvss_v3_base")),
        ("nvt.cvss4_base", nvt.findtext("cvss4_base")),
        ("nvt.cvss_v4_base", nvt.findtext("cvss_v4_base")),
    ]
    for key in (
        "cvss_base", "cvss2_base", "cvss_v2_base",
        "cvss3_base", "cvss_v3_base", "cvss4_base", "cvss_v4_base"
    ):
        raw_candidates.append((f"tags.{key}", tag_values.get(key)))

    # Newer gvmd/NVT schemas can carry multiple CVSS generations under a
    # severities list. Preserve each score as an independent candidate so a
    # placeholder cvss_base=0.0 cannot hide an actual Critical result.
    try:
        for idx, value in enumerate(nvt.xpath(".//severities/severity/score/text()")):
            raw_candidates.append((f"nvt.severities[{idx}].score", value))
    except Exception:
        pass

    parsed: dict[str, float] = {}
    for source, value in raw_candidates:
        score = _valid_cvss(value)
        if score is not None:
            parsed[source] = score
    if not parsed:
        return 0.0, "none", {}

    # Prefer result.severity on a tie because it is the per-result score emitted
    # by gvmd; otherwise take the strongest valid technical score.
    max_score = max(parsed.values())
    tied = [name for name, score in parsed.items() if score == max_score]
    source = "result.severity" if "result.severity" in tied else tied[0]
    return max_score, source, parsed


def _versioned_cvss_scores(candidates: dict[str, float]) -> dict[str, float | None]:
    """Extract only explicitly versioned CVSS values for central normalization.

    ``cvss_base`` and Greenbone ``result/severity`` are deliberately left as
    generic scanner signals because their CVSS generation is not guaranteed by
    the GMP report shape. This prevents a legacy v2 score from being mislabeled
    as v3/v4 while still keeping the generic score available as a fallback.
    """
    names = {
        "cvss_v2": ("nvt.cvss2_base", "nvt.cvss_v2_base", "tags.cvss2_base", "tags.cvss_v2_base"),
        "cvss_v3": ("nvt.cvss3_base", "nvt.cvss_v3_base", "tags.cvss3_base", "tags.cvss_v3_base"),
        "cvss_v4": ("nvt.cvss4_base", "nvt.cvss_v4_base", "tags.cvss4_base", "tags.cvss_v4_base"),
    }
    out: dict[str, float | None] = {"cvss_v2": None, "cvss_v3": None, "cvss_v4": None}
    for version, sources in names.items():
        for source in sources:
            if source in candidates:
                out[version] = candidates[source]
                break
    return out


def _xml_result_nodes(report: Any) -> list[Any]:
    try:
        return list(report.xpath(".//results/result"))
    except Exception:
        return []


def _feed_count_from_xml(response: Any) -> int | None:
    """Best-effort total NVT count from GMP response metadata.

    Greenbone versions expose the count in slightly different shapes.  Returning
    None means "count unavailable", not zero.
    """
    if response is None or not hasattr(response, "xpath"):
        return None
    paths = (
        # Native <get_nvts> responses.
        ".//nvt_count/filtered/text()",
        ".//nvt_count/total/text()",
        ".//nvt_count/text()",
        ".//config/nvt_count/text()",
        # python-gvm may implement get_nvts() through GMP get_info unless
        # extended=True is requested.  gvmd 26.x then reports <info_count>
        # instead of <nvt_count>.  Treat both schemas equivalently.
        ".//info_count/filtered/text()",
        ".//info_count/total/text()",
        ".//info_count/text()",
    )
    values: list[int] = []
    for xpath in paths:
        try:
            for raw in response.xpath(xpath):
                try:
                    values.append(int(str(raw).strip()))
                except (TypeError, ValueError):
                    pass
        except Exception:
            pass
    return max(values) if values else None


def _minimum_nvt_count() -> int:
    try:
        return max(1, int(os.environ.get("GVM_MIN_NVT_COUNT") or 10000))
    except (TypeError, ValueError):
        return 10000


def _feed_health(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    """Return conservative Greenbone feed/config health evidence."""
    syncing = False
    versions: list[str] = []
    try:
        feeds = gmp.get_feeds()
        if hasattr(feeds, "xpath"):
            syncing = any(
                str(x or "").strip().lower() in {"1", "true", "yes"}
                for x in feeds.xpath(".//currently_syncing/text()")
            )
            versions = [str(v).strip() for v in feeds.xpath(".//feed/version/text()") if str(v).strip()]
    except Exception:
        log.debug("Unable to read Greenbone feed metadata", exc_info=True)

    nvt_count: int | None = None
    # V1.9.4: never request the full NVT list. python-gvm 27 sends
    # get_nvts(extended=True) as a bare <get_nvts/> - the filter is dropped -
    # so gvmd returned all ~185k checks on every readiness probe (each minute)
    # and every IP start: ~40 s each (field job d1c55fbe). The get_info form
    # keeps rows=1 and reports the total in <info_count>.
    try:
        resp = gmp.get_nvts(filter_string="rows=1 first=1")
        nvt_count = _feed_count_from_xml(resp)
        if nvt_count is None and hasattr(resp, "xpath") and resp.xpath(".//info | .//nvt"):
            nvt_count = -1  # present, total unknown
    except Exception:
        log.debug("Unable to read Greenbone NVT inventory", exc_info=True)
    if nvt_count is None or nvt_count == -1:
        # Cheap second source: one row per family (~60), each with its total.
        try:
            families = gmp.get_nvt_families()
            totals = [int(str(v).strip()) for v in families.xpath(".//family/max_nvt_count/text()")
                      if str(v).strip().isdigit()]
            if totals:
                nvt_count = sum(totals)
        except Exception:
            log.debug("Unable to read Greenbone NVT families", exc_info=True)

    config_nvt_count: int | None = None
    if config_id:
        getter = getattr(gmp, "get_scan_config", None)
        if callable(getter):
            try:
                config_nvt_count = _feed_count_from_xml(getter(config_id))
            except Exception:
                log.debug("Unable to read scan-config NVT count", exc_info=True)

    return {
        "syncing": syncing,
        "versions": versions,
        "nvt_count": nvt_count,
        "config_nvt_count": config_nvt_count,
    }


def _assert_feed_quality(gmp: Any, config_id: str | None = None) -> dict[str, Any]:
    health = _feed_health(gmp, config_id)
    if health["syncing"]:
        raise RuntimeError("Greenbone feed is still synchronizing; refusing to start a partial-quality scan")
    minimum = _minimum_nvt_count()
    for label in ("nvt_count", "config_nvt_count"):
        count = health.get(label)
        if isinstance(count, int) and count >= 0 and count < minimum:
            raise RuntimeError(
                f"Greenbone {label}={count} is below required minimum {minimum}; "
                "feed/config import is incomplete, so the scanner will not claim the job"
            )
    if health.get("nvt_count") is None:
        log.warning("Greenbone NVT total count is unavailable; continuing because feed sync is not active")
    return health



def _imports():
    from gvm.connections import TLSConnection, UnixSocketConnection

    try:
        from gvm.protocols.gmp import GMP
    except ImportError:
        from gvm.protocols.gmp import Gmp as GMP  # type: ignore

    try:
        from gvm.transforms import EtreeCheckCommandTransform

        transform = EtreeCheckCommandTransform()
    except ImportError:
        from gvm.transforms import EtreeTransform

        transform = EtreeTransform()

    return TLSConnection, UnixSocketConnection, GMP, transform


@contextmanager
def _session(
    *,
    socket_path: str | None,
    host: str,
    port: int,
    username: str,
    password: str,
    verify: bool = False,
    timeout: float | None = None,
) -> Iterator[Any]:
    TLSConnection, UnixSocketConnection, GMP, transform = _imports()
    timeout = _gmp_timeout() if timeout is None else max(1.0, float(timeout))
    if socket_path:
        try:
            conn = UnixSocketConnection(path=socket_path, timeout=timeout)
        except TypeError:
            conn = UnixSocketConnection(path=socket_path)
    else:
        conn = TLSConnection(hostname=host, port=port, timeout=timeout, verify=verify)

    # python-gvm manages connect/disconnect at the GMP protocol layer.
    # UnixSocketConnection itself is not a context manager in current 26.x.
    with GMP(connection=conn, transform=transform) as gmp:
        gmp.authenticate(username, password)
        yield gmp


def _find_config_id(gmp: Any, name: str = "Full and fast") -> str:
    resp = gmp.get_scan_configs()
    available: list[str] = []
    by_name: dict[str, str] = {}
    wanted = name.strip().casefold()
    is_full_and_fast = wanted in {"full and fast", FULL_AND_FAST_ID.casefold()}
    for node in resp.xpath("config"):
        cid = (node.get("id") or "").strip()
        config_name = (node.findtext("name") or "").strip()
        if config_name:
            available.append(config_name)
            if cid:
                by_name[config_name.casefold()] = cid
        if cid and config_name.casefold() == wanted:
            return cid
        if cid == FULL_AND_FAST_ID and is_full_and_fast:
            return cid
    # V1.9.0: this Aetheris deployment re-imports the stock "Full and fast" base
    # config under the name "Aetheris Full and fast" (the stock name/ID may be
    # absent). When the stock Full-and-fast was requested but not present, fall
    # back to the Aetheris copy instead of failing readiness with
    # "Scan config not found: Full and fast".
    if is_full_and_fast:
        for candidate in (AETHERIS_SCAN_CONFIG, "aetheris full and fast"):
            cid = by_name.get(candidate.strip().casefold())
            if cid:
                global _BASE_CONFIG_NOTE_AT
                now = time.monotonic()
                if now >= _BASE_CONFIG_NOTE_AT:
                    # V1.9.6: once an hour (was on every readiness probe).
                    _BASE_CONFIG_NOTE_AT = now + 3600.0
                    log.info(
                        "Base config 'Full and fast' not present; using '%s' instead. gvmd is not importing its "
                        "predefined data objects: set the Feed Import Owner (scripts/Repair-Greenbone-Feed-v1.4.1.ps1)",
                        AETHERIS_SCAN_CONFIG,
                    )
                return cid
    summary = ", ".join(available[:8]) if available else "none"
    raise RuntimeError(
        f"Scan config not found: {name}. Available configs: {summary}. "
        "Greenbone feed data is still loading or the Feed Import Owner/data-object rebuild is missing."
    )


def _find_scanner_id(gmp: Any) -> str:
    resp = gmp.get_scanners()
    for node in resp.xpath("scanner"):
        n = (node.findtext("name") or "").lower()
        if "openvas" in n or "default" in n:
            sid = node.get("id")
            if sid:
                return str(sid)
    node = resp.find("scanner")
    if node is not None and node.get("id"):
        return str(node.get("id"))
    raise RuntimeError("No OpenVAS scanner found in Greenbone")


def _apply_nmap_speed_prefs(gmp: Any, config_id: str) -> None:
    """SYN scan plus short retries. Connect()+UDP on every TCP port sits at ~15% for hours.

    The preference name must be the full ``oid:id:type:name`` string. A short name is
    stored with no NVT id, and OpenVAS then ignores it and stays on connect().
    """
    prefs = (
        (f"{NMAP_NVT_OID}:1:radio:TCP scanning technique :", "SYN scan"),
        (f"{NMAP_NVT_OID}:8:entry:Max Retries :", "2"),
        (f"{NMAP_NVT_OID}:23:checkbox:Defeat ICMP ratelimit", "yes"),
        (f"{NMAP_NVT_OID}:22:checkbox:Defeat RST ratelimit", "yes"),
    )
    for name, value in prefs:
        try:
            gmp.modify_scan_config_set_nvt_preference(
                config_id=config_id,
                name=name,
                nvt_oid=NMAP_NVT_OID,
                value=value,
            )
        except Exception as exc:
            # gvmd rejects preference edits while any task is using the config.
            # The SYN settings were saved when the config was created, so keep it.
            if "in use" in str(exc).lower():
                log.info(
                    "Scan config %s is in use; using the Nmap SYN settings already saved",
                    config_id,
                )
                return
            raise


def _ensure_portscan_config(gmp: Any, base_name: str) -> str:
    """Return a writable Full-and-fast clone whose Nmap NVT uses a SYN scan.

    The built-in config is predefined, so its Nmap technique stays connect().
    A connect scan of T:1-65535 plus UDP holds OpenVAS around 15% until nmap exits.
    """
    base_label = (base_name or "Full and fast").strip()
    # V1.6.5: one writable clone per base config. Previously every base name
    # resolved to the "Full and fast" clone, so a Discovery policy silently ran
    # the full vulnerability config.
    clone_name = (
        AETHERIS_SCAN_CONFIG
        if base_label.casefold() in {"full and fast", FULL_AND_FAST_ID.casefold()}
        else f"Aetheris {base_label}"
    )
    wanted = clone_name.casefold()
    base_wanted = base_label.casefold()
    resp = gmp.get_scan_configs(filter_string="rows=-1")
    existing = ""
    base_id = ""
    for node in resp.xpath("config"):
        cid = (node.get("id") or "").strip()
        config_name = (node.findtext("name") or "").strip()
        if not cid or not config_name:
            continue
        folded = config_name.casefold()
        if folded == wanted:
            existing = cid
        elif folded == base_wanted or cid == FULL_AND_FAST_ID and base_wanted == "full and fast":
            base_id = cid
    if existing:
        _apply_nmap_speed_prefs(gmp, existing)
        return existing
    if not base_id:
        base_id = _find_config_id(gmp, base_name or "Full and fast")
    cloned = gmp.clone_scan_config(base_id)
    new_id = str(cloned.get("id") or "").strip()
    if not new_id:
        raise RuntimeError("Greenbone did not return a cloned scan config id")
    gmp.modify_scan_config_set_name(new_id, clone_name)
    _apply_nmap_speed_prefs(gmp, new_id)
    log.info("Created scan config %s (%s) with Nmap SYN scan", clone_name, new_id)
    return new_id


# Families every scoped config keeps, otherwise ports/services/products are
# never discovered and the selected families have nothing to test.
BASE_FAMILIES = ("Port scanners", "Service detection", "Product detection", "Settings", "General", "Credentials")


def _ensure_family_config(gmp: Any, config_id: str, families: list[str],
                          require: bool = False) -> tuple[str, str]:
    """Clone ``config_id`` restricted to ``families`` (+ base families).

    Returns (config_id_to_use, status). Any GMP rejection falls back to the
    unscoped config: a superset of tests is safer than a silently empty scan.
    """
    import hashlib

    # gvmd silently ignores unknown family names, so check what this feed has.
    try:
        present = set(_config_families(gmp, config_id))
    except Exception:
        present = set()
    missing = sorted(f for f in families if present and f not in present)
    usable = [f for f in families if not present or f in present]
    if require and present and not [f for f in usable if f not in BASE_FAMILIES]:
        raise ValueError(
            "This Greenbone feed has none of the required check families: " + ", ".join(sorted(families))
        )
    wanted = sorted(set(usable) | set(BASE_FAMILIES))
    digest = hashlib.sha256("|".join(wanted).encode()).hexdigest()[:10]
    name = f"Aetheris families {digest}"
    try:
        resp = gmp.get_scan_configs(filter_string=f'name="{name}" rows=5')
        for node in resp.xpath("config"):
            if (node.findtext("name") or "").strip() == name and node.get("id"):
                return str(node.get("id")), f"scoped to {len(wanted)} families (reused {name})"
        cloned = gmp.clone_scan_config(config_id)
        new_id = str(cloned.get("id") or "").strip()
        if not new_id:
            raise RuntimeError("clone returned no id")
        gmp.modify_scan_config_set_name(new_id, name)
        gmp.modify_scan_config_set_family_selection(
            new_id, [(fam, True, True) for fam in wanted], auto_add_new_families=False,
        )
        log.info("Created family-scoped scan config %s (%s): %s", name, new_id, ", ".join(wanted))
        note = f"; not in this feed: {', '.join(missing)}" if missing else ""
        return new_id, f"scoped to {len(wanted)} families ({name}){note}"
    except Exception as exc:
        if require:
            raise ValueError(f"Required check families could not be selected: {exc}") from exc
        log.warning("Family scoping rejected by Greenbone (%s); using the unscoped config", exc)
        return config_id, f"not applied ({str(exc)[:120]}); full config used"


# --- V1.6.8 vulnerability-only check scope -----------------------------------
# Discovery infrastructure stays whole: without it no port/service is found.
CHECK_SCOPE_WHOLE_FAMILIES = ("Port scanners", "Settings", "Credentials", "Service detection")
# Not network vulnerability checks, or not run by Nessus by default.
CHECK_SCOPE_EXCLUDED_FAMILIES = (
    "Brute force attacks", "Compliance", "Policy", "IT-Grundschutz", "IT-Grundschutz-15",
    "IT-Grundschutz-Deprecated", "Nmap NSE", "Nmap NSE net", "Denial of Service",
)
# Cheap end-of-scan reporting checks the coverage logic reads (open ports, OS,
# host details). Kept even though they are informational.
CHECK_SCOPE_ESSENTIAL_OIDS = (
    "1.3.6.1.4.1.25623.1.0.900239",  # Check Open TCP Ports (host detail "ports")
    "1.3.6.1.4.1.25623.1.0.103997",  # Host Details
    "1.3.6.1.4.1.25623.1.0.105937",  # OS Detection Consolidation and Reporting
    "1.3.6.1.4.1.25623.1.0.810003",  # Host Summary
    "1.3.6.1.4.1.25623.1.0.810002",  # CPE Inventory
    "1.3.6.1.4.1.25623.1.0.108449",  # Hostname Determination Reporting
)


def _nvt_info_type() -> Any:
    try:
        from gvm.protocols.gmp.requests.v224 import InfoType

        return InfoType.NVT
    except Exception:  # older/newer python-gvm layouts
        class _NVT:
            value = "NVT"

        return _NVT()


def _config_families(gmp: Any, config_id: str) -> list[str]:
    resp = gmp.get_scan_config(config_id)
    names = []
    for fam in resp.xpath(".//families/family"):
        name = (fam.findtext("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _info_oids(resp: Any) -> list[str]:
    oids: list[str] = []
    for info in resp.xpath(".//info"):
        oid = (info.get("id") or "").strip()
        if not oid:
            nvt = info.find("nvt")
            oid = (nvt.get("oid") or "").strip() if nvt is not None else ""
        if oid and oid not in oids:
            oids.append(oid)
    return oids


def _feed_digest(gmp: Any) -> str:
    import hashlib

    try:
        feeds = gmp.get_feeds()
        versions = sorted(f"{f.findtext('type')}={f.findtext('version')}" for f in feeds.xpath(".//feed"))
    except Exception:
        versions = []
    return hashlib.sha256("|".join(versions).encode()).hexdigest()[:10] if versions else "nofeed"


def _severity_filter(nvt_filter: dict[str, Any] | None) -> str:
    """gvmd filter terms for an NVT selection. gvmd has no '>=': severity has one
    decimal, so ">= 7.0" is written "severity>6.9"."""
    flt = nvt_filter or {}
    min_sev = flt.get("min_severity")
    terms = [f"severity>{round(float(min_sev) - 0.1, 1)}" if min_sev else "severity>0"]
    if flt.get("name_contains"):
        terms.append(f'name~"{flt["name_contains"]}"')
    return " ".join(terms)


# --- V1.9.1 check-scope engine ------------------------------------------------
# Field regression (jobs 1598a7c8, dffcee8e, 64b549f1 on 192.168.0.163): every
# scan since V1.6.8 finished Info-only, while V1.6.4 on the same laptop reported
# 2 Medium + 1 Low. V1.6.8 built a *static* per-family OID list with
# ``get_info_list(... rows=-1)``. gvmd caps every GET at its immutable
# "Max Rows Per Page" setting (default 1000; rows=-1 is rewritten to 1000), so
# every family with more than 1000 matching checks was silently truncated, and
# the truncated snapshot was then reused by name forever because the
# verification comment was never stored (python-gvm takes ``comment=`` as a
# keyword-only argument; the positional call raised TypeError inside a bare
# ``except``).
#
# Now:
# * ``vulnerability`` (default): every family whole and growing, minus the
#   excluded families. No OID enumeration, so nothing can be truncated and new
#   feed checks are picked up automatically (Nessus "Advanced Scan" parity).
# * ``severity`` (opt-in, SCAN_CHECK_SCOPE=severity) and Advanced Dynamic
#   ``nvt_filter``: static OID lists fetched in pages below the gvmd cap and
#   verified against gvmd's own filtered total.
# * Every config is verified family-by-family (selected == available for whole
#   families, selected == expected for static ones) before it is used, and
#   again before a stored config is reused. A config that fails is rebuilt.
CHECK_SCOPE_CONFIG_VERSION = "v2"
# Families that stay whole in the opt-in severity mode: discovery, plus the
# detection checks whose evidence every vulnerability check depends on.
SEVERITY_SCOPE_WHOLE_FAMILIES = CHECK_SCOPE_WHOLE_FAMILIES + ("Product detection",)
_LEGACY_SCOPE_PREFIXES = ("Aetheris vuln-scope ", "Aetheris dynamic ")


def _info_page_rows() -> int:
    """Rows per get_info page; always below gvmd's default Max Rows Per Page (1000)."""
    try:
        return max(50, min(1000, int(os.environ.get("GVM_INFO_PAGE_ROWS") or 500)))
    except (TypeError, ValueError):
        return 500


def _filtered_total(resp: Any) -> int | None:
    for xpath in (".//info_count/filtered/text()", ".//nvt_count/filtered/text()"):
        try:
            values = resp.xpath(xpath)
        except Exception:
            values = []
        for raw in values:
            try:
                return int(str(raw).strip())
            except (TypeError, ValueError):
                continue
    return None


def _paged_info_oids(gmp: Any, filter_terms: str) -> list[str]:
    """Every NVT OID matching ``filter_terms``, fetched in pages under the gvmd row cap.

    Raises RuntimeError when the collected set does not match gvmd's own
    filtered total, so an incomplete list can never become a scan config.
    """
    page = _info_page_rows()
    last_error = ""
    for attempt in range(2):
        oids: list[str] = []
        seen: set[str] = set()
        expected: int | None = None
        first = 1
        for _guard in range(10000):
            resp = gmp.get_info_list(
                _nvt_info_type(),
                filter_string=f"{filter_terms} sort=name first={first} rows={page}",
                details=False,
            )
            if expected is None:
                expected = _filtered_total(resp)
            batch = _info_oids(resp)
            for oid in batch:
                if oid not in seen:
                    seen.add(oid)
                    oids.append(oid)
            if len(batch) < page or (expected is not None and first - 1 + len(batch) >= expected):
                break
            first += page
        if expected is None or len(oids) == expected:
            return oids
        last_error = f"collected {len(oids)} of {expected} matching checks ({filter_terms})"
        log.warning("NVT list incomplete on attempt %d: %s", attempt + 1, last_error)
    raise RuntimeError(f"incomplete NVT list from gvmd: {last_error}")


def _config_family_stats(gmp: Any, config_id: str) -> tuple[dict[str, dict[str, Any]], int | None]:
    """Per-family selection of a scan config: {family: {nvt_count, max_nvt_count, growing}}."""
    resp = gmp.get_scan_config(config_id)
    stats: dict[str, dict[str, Any]] = {}
    for fam in resp.xpath(".//families/family"):
        name = (fam.findtext("name") or "").strip()
        if not name:
            continue
        growing_node = fam.find("growing")
        growing = None
        if growing_node is not None:
            growing = (growing_node.text or "").strip().lower() in {"1", "true", "yes"}
        stats[name] = {
            "nvt_count": _as_int(fam.findtext("nvt_count"), -1),
            "max_nvt_count": _as_int(fam.findtext("max_nvt_count"), -1),
            "growing": growing,
        }
    return stats, _feed_count_from_xml(resp)


def _partial_families(stats: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Families that carry only part of their checks, as {family: "selected/available"}.

    gvmd lists every feed family, unselected ones as 0/N (GSA's "0 of N"). An
    unselected family is excluded, not truncated, so it is not partial.
    """
    out: dict[str, str] = {}
    for name, row in stats.items():
        sel, avail = row.get("nvt_count", -1), row.get("max_nvt_count", -1)
        if sel > 0 and avail >= 0 and sel < avail:
            out[name] = f"{sel}/{avail}"
    return out


def _unselected_families(stats: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(name for name, row in stats.items()
                  if row.get("nvt_count", -1) == 0 and row.get("max_nvt_count", 0) > 0)


def _verify_scope_config(
    gmp: Any,
    config_id: str,
    *,
    whole: list[str],
    excluded: list[str],
    static_counts: dict[str, int] | None = None,
    min_total: int | None = None,
) -> dict[str, Any]:
    """Prove a scope config contains what it should. Returns {"ok": bool, ...evidence}."""
    stats, total = _config_family_stats(gmp, config_id)
    problems: list[str] = []
    truncated: dict[str, str] = {}
    for fam in whole:
        row = stats.get(fam)
        if row is None:
            problems.append(f"missing family {fam}")
            continue
        sel, avail = row["nvt_count"], row["max_nvt_count"]
        if sel >= 0 and avail >= 0 and sel < avail:
            truncated[fam] = f"{sel}/{avail}"
        elif row.get("growing") is False:
            problems.append(f"whole family not growing: {fam}")
    if truncated:
        problems.append("whole families truncated: " + ", ".join(f"{k} {v}" for k, v in sorted(truncated.items())))
    for fam in excluded:
        row = stats.get(fam)
        if row is not None and row.get("nvt_count", 0) > 0:
            problems.append(f"excluded family selected: {fam}")
    for fam, want in (static_counts or {}).items():
        row = stats.get(fam)
        have = row["nvt_count"] if row else 0
        if have >= 0 and have != want:
            problems.append(f"{fam}: {have} selected, expected {want}")
    if min_total is not None and isinstance(total, int) and 0 <= total < min_total:
        problems.append(f"{total} checks, below GVM_MIN_NVT_COUNT={min_total}")
    return {"ok": not problems, "problems": problems[:12], "nvt_count": total,
            "families": len(stats), "partial_families": _partial_families(stats),
            "families_unselected": _unselected_families(stats)}


def _nvt_feed_version(gmp: Any) -> str:
    """NVT feed version only; SCAP/CERT/data-object versions do not change NVT selection."""
    try:
        for feed in gmp.get_feeds().xpath(".//feed"):
            if (feed.findtext("type") or "").strip().upper() == "NVT":
                version = (feed.findtext("version") or "").strip()
                if version:
                    return version
    except Exception:
        log.debug("NVT feed version unavailable", exc_info=True)
    return "nofeed"


def _set_config_comment(gmp: Any, config_id: str, payload: dict[str, Any]) -> bool:
    """Store JSON evidence on a config. python-gvm takes ``comment`` keyword-only."""
    try:
        gmp.modify_scan_config_set_comment(config_id, comment=json.dumps(payload, sort_keys=True))
        return True
    except Exception:
        log.warning("Could not store the verification comment on scan config %s", config_id, exc_info=True)
        return False


def _scope_candidates(gmp: Any, name: str) -> list[tuple[str, str, bool, dict[str, Any]]]:
    """Existing configs called ``name`` or ``name r<n>``: (id, name, in_use, saved_comment)."""
    out = []
    try:
        resp = gmp.get_scan_configs(filter_string=f'name~"{name}" rows=50')
    except Exception:
        return out
    for node in resp.xpath("config"):
        cname = (node.findtext("name") or "").strip()
        cid = str(node.get("id") or "").strip()
        if not cid or not (cname == name or cname.startswith(name + " r")):
            continue
        try:
            saved = json.loads(node.findtext("comment") or "{}")
        except ValueError:
            saved = {}
        in_use = (node.findtext("in_use") or "0").strip() not in {"0", ""}
        out.append((cid, cname, in_use, saved if isinstance(saved, dict) else {}))
    return out


def _retire_legacy_scope_configs(gmp: Any) -> None:
    """Best effort: delete unused pre-V1.9.1 scope configs so they can never be reused."""
    try:
        resp = gmp.get_scan_configs(filter_string='name~"Aetheris" rows=200')
    except Exception:
        return
    for node in resp.xpath("config"):
        cname = (node.findtext("name") or "").strip()
        cid = str(node.get("id") or "").strip()
        if not cid or not cname.startswith(_LEGACY_SCOPE_PREFIXES):
            continue
        if f" {CHECK_SCOPE_CONFIG_VERSION} " in cname:
            continue
        if (node.findtext("in_use") or "0").strip() not in {"0", ""}:
            continue
        try:
            gmp.delete_scan_config(cid, ultimate=True)
            log.info("Retired legacy scan config %s (%s)", cname, cid)
        except Exception:
            log.debug("Could not retire legacy scan config %s", cid, exc_info=True)


def _ensure_check_scope_config(
    gmp: Any, base_config_id: str, nvt_filter: dict[str, Any] | None = None, mode: str = "vulnerability",
) -> tuple[str, dict[str, Any]]:
    """Clone ``base_config_id`` for the requested check scope and prove its contents.

    Modes: ``vulnerability`` (default, whole growing families minus exclusions),
    ``severity`` (static severity>0 selection, opt-in), or an Advanced Dynamic
    ``nvt_filter``. Non-dynamic failures fall back to the unscoped base config
    (all checks); dynamic failures raise, because running everything would
    silently ignore the user's filter.
    """
    dynamic = bool(nvt_filter)
    mode = "dynamic" if dynamic else ("severity" if str(mode).lower() == "severity" else "vulnerability")
    base_count = None
    try:
        base_count = _feed_count_from_xml(gmp.get_scan_config(base_config_id))
    except Exception:
        pass
    status: dict[str, Any] = {"scope": mode, "config": "base", "base_nvt_count": base_count,
                              "version": CHECK_SCOPE_CONFIG_VERSION}
    if dynamic:
        status["filter"] = dict(nvt_filter or {})
    base8 = str(base_config_id)[:8]
    try:
        _retire_legacy_scope_configs(gmp)
        families = _config_families(gmp, base_config_id)
        if not families:
            raise RuntimeError("base config lists no families")
        wanted = set((nvt_filter or {}).get("families") or [])
        lsc = [f for f in families if f.endswith("Local Security Checks")]

        if mode == "vulnerability":
            excluded = [f for f in families if f in CHECK_SCOPE_EXCLUDED_FAMILIES]
            whole = [f for f in families if f not in excluded]
            filtered: list[str] = []
            digest = hashlib.sha256("|".join(sorted(excluded) + ["#"] + sorted(families)).encode()).hexdigest()[:8]
            name = f"Aetheris vuln-scope {CHECK_SCOPE_CONFIG_VERSION} {digest}-{base8}"
        else:
            whole_set = SEVERITY_SCOPE_WHOLE_FAMILIES if mode == "severity" else CHECK_SCOPE_WHOLE_FAMILIES
            whole = [f for f in families if f in whole_set]
            whole += [f for f in lsc if (not wanted or f in wanted) and f not in whole]
            if wanted:  # explicit family list: honour it, including normally excluded families
                excluded = [f for f in families if f not in wanted and f not in whole]
                filtered = [f for f in families if f in wanted and f not in whole]
            else:
                excluded = [f for f in families if f in CHECK_SCOPE_EXCLUDED_FAMILIES]
                filtered = [f for f in families if f not in whole and f not in excluded and f not in lsc]
            fdigest = hashlib.sha256(json.dumps(nvt_filter or {}, sort_keys=True).encode()).hexdigest()[:8]
            label = "dynamic" if dynamic else "severity-scope"
            name = f"Aetheris {label} {CHECK_SCOPE_CONFIG_VERSION} {fdigest}-{_nvt_feed_version(gmp)}-{base8}"

        min_total = None if dynamic else _minimum_nvt_count()

        # Reuse only a config that still proves its contents.
        for cid, cname, in_use, saved in _scope_candidates(gmp, name):
            static_counts = {k: int(v) for k, v in (saved.get("static_counts") or {}).items()} if filtered else None
            if filtered and not static_counts:
                verdict = {"ok": False, "problems": ["no stored selection evidence"]}
            else:
                verdict = _verify_scope_config(gmp, cid, whole=whole, excluded=excluded,
                                               static_counts=static_counts, min_total=min_total)
            if verdict["ok"]:
                status.update({k: v for k, v in saved.items() if k not in {"config"}})
                status.update({"config": f"reused {cname}", "verification": verdict})
                log.info("Check-scope config %s reused: %s checks, verified (%d families, partial: %s)",
                         cname, verdict.get("nvt_count"), verdict.get("families", 0),
                         verdict.get("partial_families") or "none")
                return cid, status
            log.warning("Check-scope config %s failed verification (%s); rebuilding",
                        cname, "; ".join(verdict.get("problems") or []))
            if not in_use:
                try:
                    gmp.delete_scan_config(cid, ultimate=True)
                except Exception:
                    log.debug("Could not delete invalid scope config %s", cid, exc_info=True)

        flt_terms = _severity_filter(nvt_filter)
        essential: dict[str, list[str]] = {}
        selections: dict[str, list[str]] = {}
        essential_added = 0
        if filtered:
            for oid in CHECK_SCOPE_ESSENTIAL_OIDS:
                try:
                    info = gmp.get_info(oid, _nvt_info_type())
                    fam = (info.findtext(".//nvt/family") or "").strip()
                    if fam:
                        essential.setdefault(fam, []).append(oid)
                except Exception:
                    log.debug("Essential NVT %s not found in feed", oid)
            for fam in filtered:
                oids = _paged_info_oids(gmp, f'family="{fam}" {flt_terms}')
                for oid in essential.get(fam, []):
                    if oid not in oids:
                        oids.append(oid)
                        essential_added += 1
                if oids:
                    selections[fam] = oids

        existing_names = {c[1] for c in _scope_candidates(gmp, name)}
        final_name = name if name not in existing_names else f"{name} r{int(time.time())}"
        cloned = gmp.clone_scan_config(base_config_id)
        new_id = str(cloned.get("id") or "").strip()
        if not new_id:
            raise RuntimeError("clone returned no id")
        gmp.modify_scan_config_set_name(new_id, final_name)
        family_rows = [(f, True, True) for f in whole] + [(f, False, True) for f in selections]
        gmp.modify_scan_config_set_family_selection(new_id, family_rows, auto_add_new_families=False)
        for fam, oids in selections.items():
            gmp.modify_scan_config_set_nvt_selection(new_id, fam, oids)
        try:
            gmp.modify_scan_config_set_scanner_preference(new_id, "auto_enable_dependencies", value="yes")
        except Exception:
            log.debug("auto_enable_dependencies preference not set; ospd default (1) applies")

        selected = sum(len(v) for v in selections.values())
        if dynamic and selected - essential_added <= 0:
            raise RuntimeError(f"dynamic filter {_severity_filter(nvt_filter)} matched no checks")
        static_counts = {fam: len(oids) for fam, oids in selections.items()}
        verdict = _verify_scope_config(gmp, new_id, whole=whole, excluded=excluded,
                                       static_counts=static_counts, min_total=min_total)
        if not verdict["ok"]:
            try:
                gmp.delete_scan_config(new_id, ultimate=True)
            except Exception:
                log.debug("Could not delete rejected scope config %s", new_id, exc_info=True)
            raise RuntimeError("new check-scope config failed verification: " + "; ".join(verdict["problems"]))
        status.update({
            "config": f"created {final_name}",
            "nvt_count": verdict.get("nvt_count"),
            "whole_families": len(whole),
            "filtered_families": len(selections),
            "severity_checks_selected": selected,
            "excluded_families": excluded,
            "essential_reporting_checks": essential_added,
            "verification": verdict,
        })
        _set_config_comment(gmp, new_id, {
            **{k: status[k] for k in ("scope", "version", "nvt_count", "base_nvt_count", "whole_families",
                                      "filtered_families", "severity_checks_selected", "excluded_families",
                                      "filter") if k in status},
            "static_counts": static_counts,
        })
        log.info(
            "Check-scope config %s (%s) [%s]: %s of %s checks verified; %d whole families, "
            "%d filtered, excluded %s; partial families: %s",
            final_name, new_id, mode, verdict.get("nvt_count"), base_count, len(whole), len(selections),
            ", ".join(excluded) or "none", verdict.get("partial_families") or "none",
        )
        return new_id, status
    except Exception as exc:
        if dynamic:
            # Falling back to "all checks" would silently ignore the user's filter.
            raise ValueError(f"Advanced Dynamic Scan filter could not be applied: {exc}") from exc
        log.warning("Check scope %s not applied (%s); running all checks", mode, exc)
        status["config"] = f"not applied ({str(exc)[:160]}); all checks run"
        return base_config_id, status


def effective_selection(gmp: Any, config_id: str) -> dict[str, Any]:
    """What the task's config will actually run: total checks and any partial families."""
    try:
        stats, total = _config_family_stats(gmp, config_id)
    except Exception as exc:
        return {"available": False, "error": str(exc)[:200]}
    selected_families = [f for f, row in stats.items() if row.get("nvt_count", 0) > 0]
    return {"available": True, "nvt_count": total, "families_selected": len(selected_families),
            "families_total": len(stats), "partial_families": _partial_families(stats),
            "families_unselected": _unselected_families(stats)}


def _nmap_timing_pref_name(gmp: Any, config_id: str) -> str | None:
    """Full ``oid:id:type:name`` of the Nmap "Timing policy" preference, read from gvmd.

    The id is looked up rather than hard-coded: a wrong id is stored without
    effect and OpenVAS silently keeps its default timing.
    """
    resp = gmp.get_scan_config(config_id)
    for pref in resp.xpath(".//preferences/preference"):
        nvt = pref.find("nvt")
        if nvt is None or (nvt.get("oid") or "").strip() != NMAP_NVT_OID:
            continue
        name = pref.findtext("name") or ""
        if name.strip().lower().startswith("timing policy"):
            pid = (pref.findtext("id") or "").strip()
            ptype = (pref.findtext("type") or "radio").strip() or "radio"
            if pid:
                return f"{NMAP_NVT_OID}:{pid}:{ptype}:{name}"
    return None


def _ensure_profile_config(
    gmp: Any,
    base_config_id: str,
    scanner_prefs: dict[str, str],
    caps: dict[str, int],
    nmap_timing: str | None,
) -> tuple[str, dict[str, Any]]:
    """Clone ``base_config_id`` carrying this scan's engine settings (V1.6.7).

    gvmd forwards only max_checks/max_hosts from *task* preferences; every
    other scanner value (plugins_timeout, checks_read_timeout, optimize_test,
    safe_checks, ...) comes from the config's SERVER_PREFS, falling back to
    gvmd's global defaults (verified in gvmd manage_osp.c and
    init_preference_iterator). So the values are written onto a config clone:

    * scanner preferences via ``modify_scan_config_set_scanner_preference``;
    * per-NVT timeout caps as ``<oid>:0:entry:timeout`` (sent as VT value 0);
    * the Nmap "Timing policy" preference, looked up by name.

    One clone per distinct setting set (gvmd refuses edits to configs in use).
    Any rejection falls back to the base config, which is slower, never narrower.
    """
    from agent.scan_performance import caps_digest

    status: dict[str, Any] = {"nvt_timeout_caps": 0, "nmap_timing": "unchanged", "config": "base",
                              "scanner_preferences": {}}
    scanner_prefs = {k: v for k, v in (scanner_prefs or {}).items() if k not in _OPENVAS_CONF_ONLY_PREFS}
    if not caps and not nmap_timing and not scanner_prefs:
        return base_config_id, status
    # "conf_only" in the digest makes every older profile config (V1.9.3 ones carry
    # log_whole_attack) be replaced once by a clone that has those prefs removed.
    digest = caps_digest(caps, json.dumps({"base": base_config_id, "timing": nmap_timing or "",
                                           "prefs": scanner_prefs,
                                           "conf_only": list(_OPENVAS_CONF_ONLY_PREFS)}, sort_keys=True))
    name = f"Aetheris profile {digest}"
    try:
        resp = gmp.get_scan_configs(filter_string=f'name="{name}" rows=5')
        for node in resp.xpath("config"):
            if (node.findtext("name") or "").strip() == name and node.get("id"):
                try:
                    saved = json.loads(node.findtext("comment") or "{}")
                except ValueError:
                    saved = {}
                saved["config"] = f"reused {name}"
                log.info("Scan profile config %s reused: scanner prefs %s, %s NVT timeout cap(s), Nmap timing %s",
                         name, saved.get("scanner_preferences"), saved.get("nvt_timeout_caps"),
                         saved.get("nmap_timing"))
                return str(node.get("id")), saved
        cloned = gmp.clone_scan_config(base_config_id)
        new_id = str(cloned.get("id") or "").strip()
        if not new_id:
            raise RuntimeError("clone returned no id")
        gmp.modify_scan_config_set_name(new_id, name)
        # A preference without a value is deleted by gvmd (manage_set_config_preference)
        # while no task uses the config - true for a fresh clone. Removing a missing
        # one is a no-op. openvas.conf then decides these settings.
        removed: list[str] = []
        for conf_only in _OPENVAS_CONF_ONLY_PREFS:
            try:
                gmp.modify_scan_config_set_scanner_preference(new_id, conf_only)
                removed.append(conf_only)
            except Exception as exc:
                log.warning("Could not remove scanner preference %s from %s (%s); OpenVAS may read it as off",
                            conf_only, name, exc)
        status["removed_scanner_prefs"] = removed
        applied_prefs: dict[str, str] = {}
        for pref_name, value in scanner_prefs.items():
            try:
                gmp.modify_scan_config_set_scanner_preference(new_id, pref_name, value=str(value))
                applied_prefs[pref_name] = str(value)
            except Exception as exc:
                log.warning("Scanner preference %s=%s rejected (%s)", pref_name, value, exc)
        status["scanner_preferences"] = applied_prefs
        if nmap_timing:
            pref = _nmap_timing_pref_name(gmp, new_id)
            if pref:
                gmp.modify_scan_config_set_nvt_preference(new_id, name=pref, nvt_oid=NMAP_NVT_OID, value=nmap_timing)
                status["nmap_timing"] = nmap_timing
            else:
                status["nmap_timing"] = "Timing policy preference not found; Nmap default kept"
        applied = 0
        for oid, seconds in caps.items():
            try:
                gmp.modify_scan_config_set_nvt_preference(
                    new_id, name=f"{oid}:0:entry:timeout", nvt_oid=oid, value=str(int(seconds)),
                )
                applied += 1
            except Exception as exc:
                log.warning("Could not cap NVT %s timeout (%s)", oid, exc)
        status["nvt_timeout_caps"] = applied
        status["config"] = f"created {name}"
        # V1.9.1: ``comment`` is keyword-only in python-gvm; the old positional
        # call raised TypeError, was swallowed, and every reuse logged "None".
        _set_config_comment(gmp, new_id, {k: status[k] for k in ("nvt_timeout_caps", "nmap_timing",
                                                                  "scanner_preferences")})
        _cleanup_fast_configs(gmp, keep_id=new_id)
        log.info("Scan profile config %s (%s): scanner prefs %s, %d NVT timeout cap(s), Nmap timing %s",
                 name, new_id, applied_prefs, applied, status["nmap_timing"])
        return new_id, status
    except Exception as exc:
        log.warning("Scan profile config not applied (%s); using the base config and gvmd defaults", exc)
        return base_config_id, {"nvt_timeout_caps": 0, "nmap_timing": "unchanged", "scanner_preferences": {},
                                "config": f"not applied ({str(exc)[:120]}); base config used"}


def _ensure_fast_config(gmp: Any, base_config_id: str, caps: dict[str, int],
                        nmap_timing: str | None) -> tuple[str, dict[str, Any]]:
    """Compatibility wrapper (V1.6.6 name)."""
    return _ensure_profile_config(gmp, base_config_id, {}, caps, nmap_timing)


def _cleanup_fast_configs(gmp: Any, keep_id: str, keep: int = 3) -> None:
    """Best effort: delete superseded, unused "Aetheris fast" clones."""
    try:
        resp = gmp.get_scan_configs(filter_string='name~"Aetheris" rows=200 sort-reverse=creation_time')
        nodes = [n for n in resp.xpath("config")
                 if (n.findtext("name") or "").startswith(("Aetheris fast ", "Aetheris profile "))]
        for node in nodes[keep:]:
            cid = str(node.get("id") or "")
            if not cid or cid == keep_id or (node.findtext("in_use") or "0").strip() not in {"0", ""}:
                continue
            try:
                gmp.delete_scan_config(cid, ultimate=True)
            except Exception:
                pass
    except Exception:
        log.debug("Fast config cleanup skipped", exc_info=True)


def _named_port_list_tcp(gmp: Any, name: str) -> set[int]:
    """TCP ports of a Greenbone port list, looked up by name (feed data object)."""
    resp = gmp.get_port_lists(filter_string=f'name="{name}" rows=5', details=True)
    for node in resp.xpath(".//port_list"):
        if (node.findtext("name") or "").strip().casefold() != name.casefold():
            continue
        ports: set[int] = set()
        for rng in node.xpath(".//port_ranges/port_range"):
            kind = (rng.findtext("type") or "tcp").strip().lower()
            if kind != "tcp":
                continue
            lo = _as_int(rng.findtext("start"), 0)
            hi = _as_int(rng.findtext("end"), lo)
            if 1 <= lo <= hi <= 65535:
                ports.update(range(lo, hi + 1))
        if ports:
            return ports
    raise LookupError(f"Greenbone port list not found or empty: {name}")


def _ospd_feed_state(gmp: Any) -> dict[str, Any]:
    """Return conservative scanner-feed readiness evidence.

    A live OSP socket alone is not readiness.  The scanner is only ready to
    claim jobs after gvmd can see the NVT inventory populated from OSPd.
    """
    minimum = _minimum_nvt_count()
    try:
        health = _feed_health(gmp, None)
    except Exception as exc:
        return {
            "ready": False,
            "reason": "feed_probe_failed",
            "detail": f"Greenbone feed probe failed: {exc}",
            "nvt_count": None,
            "minimum": minimum,
        }

    count = health.get("nvt_count")
    if health.get("syncing"):
        return {
            "ready": False,
            "reason": "feed_syncing",
            "detail": "Greenbone feed is still synchronizing/loading; queued scans will start automatically when ready",
            "nvt_count": count,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    if count is None:
        return {
            "ready": False,
            "reason": "nvt_inventory_unavailable",
            "detail": "OSPd OpenVAS has not published its NVT inventory yet; initial VT loading is still in progress",
            "nvt_count": None,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    if count == -1:
        versions = health.get("versions") or []
        if versions:
            # Current gvmd/python-gvm combinations can expose NVT objects and
            # feed versions without a total-count element.  This is positive
            # inventory evidence, not an incomplete-feed signal.  Full scan
            # readiness still requires the configured scan config to exist in
            # LocalOpenVAS.ready(), so this does not fail open.
            return {
                "ready": True,
                "reason": "nvt_inventory_present_count_unavailable",
                "detail": "OSPd OpenVAS NVT inventory is present and feed versions are available; gvmd did not expose a total NVT count, so readiness will be confirmed by the scan-config gate",
                "nvt_count": count,
                "minimum": minimum,
                "versions": versions,
                "count_trustworthy": False,
            }
        return {
            "ready": False,
            "reason": "nvt_count_unavailable",
            "detail": "OSPd OpenVAS exposes NVT data but no feed version or trustworthy total count yet",
            "nvt_count": count,
            "minimum": minimum,
            "versions": versions,
        }
    if count < minimum:
        return {
            "ready": False,
            "reason": "nvt_inventory_loading",
            "detail": f"OSPd OpenVAS NVT inventory is still loading ({count}/{minimum} minimum)",
            "nvt_count": count,
            "minimum": minimum,
            "versions": health.get("versions") or [],
        }
    return {
        "ready": True,
        "reason": "ready",
        "detail": f"OSPd OpenVAS NVT inventory ready ({count} VTs)",
        "nvt_count": count,
        "minimum": minimum,
        "versions": health.get("versions") or [],
    }


def _ospd_feed_ready(gmp: Any) -> bool:
    """True only with positive NVT inventory evidence; never fail open."""
    return bool(_ospd_feed_state(gmp).get("ready"))


def _task_status(gmp: Any, task_id: str) -> tuple[str, float, Any]:
    resp = gmp.get_task(task_id)
    task = resp.find("task")
    if task is None:
        nodes = resp.xpath(".//task")
        task = nodes[0] if nodes else None
    if task is None:
        return "unknown", 0.0, None
    status = (task.findtext("status") or "unknown").strip().lower()
    try:
        progress = float(task.findtext("progress") or 0)
    except (TypeError, ValueError):
        progress = 0.0
    return status, progress, task


def _split_host_list(text: str | None) -> list[str]:
    hosts: list[str] = []
    for raw in str(text or "").replace("\n", ",").split(","):
        host = raw.strip()
        if host:
            hosts.append(host)
    return hosts


def _hosts_from_target_elem(target: Any) -> list[str]:
    if target is None:
        return []
    for xpath in ("hosts", "hosts/host", "ip"):
        text = target.findtext(xpath) if hasattr(target, "findtext") else None
        hosts = _split_host_list(text)
        if hosts:
            return hosts
    return _split_host_list(target.findtext("hosts") if hasattr(target, "findtext") else None)


def _hosts_from_task_elem(task: Any) -> list[str]:
    if task is None:
        return []
    target = task.find("target") if hasattr(task, "find") else None
    hosts = _hosts_from_target_elem(target)
    if hosts:
        return hosts
    return _split_host_list(task.findtext("hosts") if hasattr(task, "findtext") else None)


def _task_report_id(task: Any) -> str | None:
    if task is None:
        return None
    for xpath in ("current_report/report", "last_report/report"):
        elem = task.find(xpath)
        if elem is not None and elem.get("id"):
            return str(elem.get("id"))
    return None


def _inner_report(response: Any) -> Any:
    """Return the report element that contains scan/host/result evidence."""
    candidates = response.xpath(".//report") if hasattr(response, "xpath") else []
    for node in candidates:
        if (
            node.find("scan_run_status") is not None
            or node.find("hosts") is not None
            or node.find("results") is not None
            or node.find("scan_start") is not None
        ):
            return node
    return candidates[-1] if candidates else response


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _text_values(node: Any, xpath: str) -> list[str]:
    try:
        values = node.xpath(xpath)
    except Exception:
        return []
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            out.append(text)
    return out


def _plugin_error_details(report: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    """Extract structured Greenbone report error records for audit/reporting."""
    try:
        nodes = report.xpath("./errors/error")
        if not nodes:
            nodes = report.xpath(".//errors/error")
    except Exception:
        nodes = []

    details: list[dict[str, Any]] = []
    for err in nodes[: max(0, limit)]:
        nvt = err.find("nvt")
        host = (err.findtext("host") or "").strip() or None
        port = (err.findtext("port") or "").strip() or None
        description = (err.findtext("description") or "").strip()
        severity = (err.findtext("severity") or "").strip() or None
        nvt_oid = (nvt.get("oid") or "").strip() if nvt is not None else ""
        nvt_name = (nvt.findtext("name") or "").strip() if nvt is not None else ""
        if not nvt_name:
            nvt_name = (err.findtext("name") or "").strip()
        details.append(
            {
                "host": host,
                "port": port,
                "nvt_oid": nvt_oid or None,
                "nvt_name": nvt_name or None,
                "severity": severity,
                "description": description[:2000] if description else None,
            }
        )
    return details


def _report_evidence_from_xml(
    response: Any,
    *,
    report_id: str,
    task_status: str,
    progress: float,
    expected_targets: list[str],
    alive_test: str,
    detail_response: Any | None = None,
) -> dict[str, Any]:
    report = _inner_report(response)
    # V1.6.5: host <detail> rows and <error> rows only exist on a details=True
    # page. Use it for coverage/error evidence when the metadata page lacks them.
    detail_report = _inner_report(detail_response) if detail_response is not None else None

    # Greenbone native XML contains direct report/host/ip and host_start/host /
    # host_end/host nodes for hosts that actually entered the scan. Result host
    # values are included as an additional source, but are not required for a
    # clean host because a successfully assessed host may have zero actionable
    # findings.
    host_ips = set(_text_values(report, "./host/ip/text()"))
    host_ips.update(_text_values(report, "./host_start/host/text()"))
    host_ips.update(_text_values(report, "./host_end/host/text()"))
    host_ips.update(_text_values(report, ".//results/result/host/text()"))
    host_ips.update(_text_values(report, ".//host/ip/text()"))
    if detail_report is not None:
        host_ips.update(_text_values(detail_report, "./host/ip/text()"))
        host_ips.update(_text_values(detail_report, ".//host/ip/text()"))
    # Some Greenbone builds stash the address on host/@ip or asset attributes.
    try:
        for node in report.xpath(".//host"):
            for attr in ("ip", "host"):
                val = (node.get(attr) or "").strip()
                if val:
                    host_ips.add(val)
            asset = node.find("asset")
            if asset is not None:
                for attr in ("asset_id", "id"):
                    val = (asset.get(attr) or "").strip()
                    if val and val.replace(".", "").isdigit() is False and ":" not in val:
                        continue
                    if val:
                        host_ips.add(val)
    except Exception:
        pass
    host_ips = {h.strip() for h in host_ips if h and str(h).strip()}

    host_count = _as_int(report.findtext("hosts/count"), len(host_ips))
    hosts_assessed = max(host_count, len(host_ips))
    result_nodes = _xml_result_nodes(report)
    materialized_result_count = len(result_nodes)
    full_result_count = _as_int(report.findtext("result_count/full"), -1)
    filtered_result_count = _as_int(report.findtext("result_count/filtered"), -1)
    legacy_result_count = _as_int(report.findtext("result_count"), -1)

    # GMP's <full> count is the number before the report filter is applied.
    # The <filtered> count describes the rows returned under <results>.  Using
    # <full> as the upload count produced false failures such as full=36 while
    # filtered/materialized/parsed=35.  The materialized count remains the
    # authoritative upload-integrity boundary when filtered metadata is absent.
    if filtered_result_count >= 0:
        result_count = filtered_result_count
    elif materialized_result_count > 0:
        result_count = materialized_result_count
    elif legacy_result_count >= 0:
        result_count = legacy_result_count
    else:
        result_count = 0
    plugin_error_details = _plugin_error_details(report)
    declared_errors = _as_int(report.findtext("errors/count"), 0)
    if detail_report is not None:
        if not plugin_error_details:
            plugin_error_details = _plugin_error_details(detail_report)
        declared_errors = max(declared_errors, _as_int(detail_report.findtext("errors/count"), 0))
    plugin_errors = max(declared_errors, len(plugin_error_details))
    coverage_source = detail_report if detail_report is not None else report
    # V45.4: explicit per-host coverage verdict (port scanner killed => degraded).
    host_coverage: dict[str, dict[str, Any]] = {}
    try:
        from agent.scan_coverage import coverage_from_report

        cov_hosts = [str(t).strip() for t in expected_targets if str(t).strip()] or sorted(host_ips)
        for cov_host in cov_hosts:
            host_coverage[cov_host] = coverage_from_report(
                coverage_source, host=cov_host, errors=plugin_error_details
            )
            host_coverage[cov_host]["detail_page_available"] = detail_report is not None
    except Exception:
        log.debug("coverage verdict failed for report %s", report_id, exc_info=True)
    scan_start = (report.findtext("scan_start") or "").strip() or None
    scan_end = (report.findtext("scan_end") or "").strip() or None
    run_status = (report.findtext("scan_run_status") or task_status or "").strip()

    targets = [str(t).strip() for t in expected_targets if str(t).strip()]
    target_count = len(targets)
    report_has_host_evidence = bool(host_ips)

    # For literal IP targets, require identity evidence from the report, not just
    # a host count.  This prevents a different/resolved host from satisfying the
    # coverage gate.  Hostnames and network expressions still require host
    # evidence/count, but their identity is not guessed here.
    import ipaddress

    literal_ip_targets: list[str] = []
    for target in targets:
        try:
            literal_ip_targets.append(str(ipaddress.ip_address(target)))
        except ValueError:
            pass
    normalized_hosts: set[str] = set()
    for host in host_ips:
        try:
            normalized_hosts.add(str(ipaddress.ip_address(host)))
        except ValueError:
            normalized_hosts.add(host.casefold())
    missing_ip_targets = [t for t in literal_ip_targets if t not in normalized_hosts]
    assessed_expected = [t for t in literal_ip_targets if t in normalized_hosts]
    # Wrong-host guard: at least one expected literal IP must appear. Hosts
    # OpenVAS did not find alive stay in missing_ip_targets for skip accounting.
    target_identity_ok = not literal_ip_targets or bool(assessed_expected)

    timestamps_ok = bool(scan_start and scan_end)
    plugin_health_ok = plugin_errors == 0

    # Completion/coverage and scanner warnings are different concepts.
    # Greenbone report <errors> entries are per-VT/scanner errors and can
    # coexist with a successfully completed task and full host coverage.
    # They must prevent a *clean* conclusion, but must not turn a fully
    # assessed host into a failed scan.
    #
    # OpenVAS "1 alive hosts of 2" is the same: the missing IP was not alive.
    # Require the assessed IPs to be expected targets, not that every expected
    # IP appears in the report.
    assessment_complete = (
        task_status in {"done", "finished", "succeeded"}
        and bool(report_id)
        and report_has_host_evidence
        and timestamps_ok
        and (
            (bool(literal_ip_targets) and bool(assessed_expected))
            or (not literal_ip_targets and target_count > 0 and hosts_assessed >= 1)
        )
    )
    clean_eligible = bool(assessment_complete and plugin_health_ok and not missing_ip_targets)

    if assessment_complete and plugin_errors > 0:
        verdict = "assessed_with_warnings"
        log.warning(
            "OpenVAS report %s completed target coverage with %d plugin/scanner error(s); "
            "marking completed-with-warnings (not clean-eligible)",
            report_id,
            plugin_errors,
        )
    elif assessment_complete and missing_ip_targets:
        verdict = "assessed_with_unreachable_skips"
    elif assessment_complete:
        verdict = "assessed"
    elif not report_id:
        verdict = "no_report"
    elif not report_has_host_evidence:
        verdict = "no_host_evidence"
    elif missing_ip_targets:
        verdict = "target_not_in_report"
    elif hosts_assessed < target_count:
        verdict = "partial_coverage"
    elif not timestamps_ok:
        verdict = "missing_scan_timestamps"
    else:
        verdict = "unverified"

    return {
        "report_id": report_id,
        "task_status": task_status,
        "scan_run_status": run_status,
        "progress": progress,
        "hosts_attempted": target_count,
        "hosts_assessed": hosts_assessed,
        "assessed_hosts": sorted(host_ips),
        "missing_ip_targets": missing_ip_targets,
        "target_identity_ok": target_identity_ok,
        "report_result_count": result_count,
        "report_result_count_full": full_result_count,
        "report_result_count_filtered": filtered_result_count,
        "report_materialized_result_count": materialized_result_count,
        "plugin_error_count": plugin_errors,
        "plugin_errors_unclassified": max(0, plugin_errors - len(plugin_error_details)),
        "plugin_error_details": plugin_error_details,
        "host_coverage": host_coverage,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "assessment_complete": assessment_complete,
        "assessment_verdict": verdict,
        "plugin_health_ok": plugin_health_ok,
        "clean_eligible": clean_eligible,
        "alive_test": alive_test,
    }


def _vulnerabilities_from_report(response: Any) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for res in response.xpath(".//results/result"):
        nvt = res.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid") or ""
        name = nvt.findtext("name") or res.findtext("name") or ""
        family = nvt.findtext("family") or ""

        tags_raw = nvt.findtext("tags") or ""
        tag_values: dict[str, str] = {}
        for part in tags_raw.split("|"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value and key not in tag_values:
                tag_values[key] = value

        cvss, cvss_source, cvss_candidates = _best_cvss(nvt, res, tag_values)
        versioned_cvss = _versioned_cvss_scores(cvss_candidates)
        result_severity_raw = (res.findtext("severity") or "").strip() or None
        threat_raw = (res.findtext("threat") or "").strip() or None
        severity = _canonical_severity(threat_raw, cvss)

        cves: list[str] = []
        cwes: list[str] = []
        references: list[str] = []
        for ref in nvt.xpath("refs/ref"):
            rtype = (ref.get("type") or "").strip().lower()
            rid = (ref.get("id") or "").strip()
            if not rid:
                continue
            references.append(f"{rtype}:{rid}" if rtype else rid)
            if rtype == "cve":
                cve_id = rid.upper()
                if cve_id not in cves:
                    cves.append(cve_id)
            elif rtype == "cwe":
                cwe_id = rid.upper()
                if not cwe_id.startswith("CWE-") and cwe_id.isdigit():
                    cwe_id = f"CWE-{cwe_id}"
                if cwe_id not in cwes:
                    cwes.append(cwe_id)
        cve = cves[0] if cves else None
        cwe = cwes[0] if cwes else None

        port_raw = res.findtext("port") or ""
        port = None
        protocol = None
        if "/" in port_raw:
            port_part, protocol = port_raw.split("/", 1)
            try:
                port = int(port_part)
            except ValueError:
                port = None

        qod_raw = res.findtext("qod/value") or res.findtext("qod") or ""
        try:
            qod = float(qod_raw) if str(qod_raw).strip() else None
        except (TypeError, ValueError):
            qod = None
        qod_type = (res.findtext("qod/type") or "").strip() or None

        def _tag_float(*keys: str) -> float | None:
            for key in keys:
                raw = tag_values.get(key)
                if raw is None:
                    continue
                try:
                    return float(raw)
                except (TypeError, ValueError):
                    continue
            return None

        cvss_v2_vector = (tag_values.get("cvss_v2_vector") or tag_values.get("cvss2_vector") or None)
        cvss_v3_vector = (tag_values.get("cvss_v3_vector") or tag_values.get("cvss3_vector") or None)
        cvss_v4_vector = (tag_values.get("cvss_v4_vector") or tag_values.get("cvss4_vector") or None)
        cvss_vector = (
            cvss_v4_vector
            or cvss_v3_vector
            or cvss_v2_vector
            or tag_values.get("cvss_base_vector")
            or tag_values.get("cvss_vector")
            or None
        )
        exploit_maturity = (
            tag_values.get("exploit_maturity")
            or tag_values.get("exploit_code_maturity")
            or tag_values.get("exploit")
            or None
        )

        vulns.append(
            {
                "source_result_id": (res.get("id") or "").strip() or None,
                "result_id": (res.get("id") or "").strip() or None,
                "plugin_id": oid,
                "nvt_oid": oid,
                "plugin_family": family,
                "cve": cve,
                "cves": cves,
                "cwe": cwe,
                "cwes": cwes,
                "references": references,
                "score": cvss,
                "cvss": cvss,
                "cvss_v2": versioned_cvss["cvss_v2"],
                "cvss_v3": versioned_cvss["cvss_v3"],
                "cvss_v4": versioned_cvss["cvss_v4"],
                "cvss_source": cvss_source,
                "score_available": bool(cvss_candidates),
                "cvss_candidates": cvss_candidates,
                "cvss_vector": cvss_vector,
                "cvss_v2_vector": cvss_v2_vector,
                "cvss_v3_vector": cvss_v3_vector,
                "cvss_v4_vector": cvss_v4_vector,
                "greenbone_result_severity": result_severity_raw,
                "scanner_threat": threat_raw,
                "risk_factor": threat_raw,
                "severity": severity,
                "scan_engine": "openvas",
                "engine": "openvas",
                "qod": qod,
                "qod_type": qod_type,
                "vpr_score": _tag_float("vpr", "vpr_score"),
                "epss_percentile": _tag_float("epss_percentile", "epss"),
                "exploit_maturity": exploit_maturity,
                "plugin_name": name,
                "description": res.findtext("description") or tag_values.get("insight") or tag_values.get("summary") or "",
                "synopsis": tag_values.get("summary") or name,
                "solution": tag_values.get("solution") or "",
                "port": port,
                "protocol": protocol,
                "service": res.findtext("service") or tag_values.get("detected_protocol"),
                "product": res.findtext("product") or tag_values.get("detected_product"),
                "cpe": res.findtext("cpe") or tag_values.get("detected_cpe"),
                "version": res.findtext("version") or tag_values.get("detected_version"),
                "host": (res.findtext("host") or "").strip() or None,
            }
        )
    return vulns


def _get_report_once(gmp: Any, report_id: str, **kwargs: Any) -> Any:
    return gmp.get_report(report_id=report_id, **kwargs)


def _harvest_report_xml(gmp: Any, report_id: str) -> tuple[Any | None, list[dict[str, Any]], Exception | None]:
    """Compatibility wrapper: (metadata report, parsed results, last error)."""
    meta, vulns, last_exc, _detail = _harvest_report_bundle(gmp, report_id)
    return meta, vulns, last_exc


def _harvest_report_bundle(
    gmp: Any, report_id: str
) -> tuple[Any | None, list[dict[str, Any]], Exception | None, Any | None]:
    """Load a Greenbone report without assuming one giant GMP reply.

    gvmd often closes the Unix socket when ``details=True`` + ``rows=-1`` is
    asked in one shot after a long scan. Metadata first, then paged results,
    then a full dump as last resort.

    V1.6.5: the metadata request uses ``details=False``. gvmd then omits the
    per-host ``<detail>`` rows (``ports``/``tcp_ports``) and the individual
    ``<error>`` rows while still sending ``<errors><count>``. Classifying
    coverage from that page alone produced "no open ports" on hosts whose
    results were on 139/445 and could not tell an NVT timeout from a killed
    port scanner. The first ``details=True`` page is therefore returned too.
    """
    detail_chunk: Any | None = None
    last_exc: Exception | None = None
    page_rows = _report_page_rows()

    meta = None
    for details, filt in (
        (False, _report_filter_string(first=1, rows=1)),
        (False, _report_filter_string(first=1, rows=10)),
    ):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=filt,
                ignore_pagination=False,
                details=details,
            )
            last_exc = None
            log.info("OpenVAS report %s metadata ok details=%s filter=%s", report_id, details, filt)
            break
        except Exception as exc:
            last_exc = exc
            log.warning(
                "get_report(%s) metadata details=%s filter=%s failed: %s",
                report_id,
                details,
                filt,
                exc,
            )
            if _gmp_connection_lost(exc):
                return None, [], last_exc

    vulns: list[dict[str, Any]] = []
    first = 1
    pages = 0
    while True:
        filt = _report_filter_string(first=first, rows=page_rows)
        chunk = None
        for details in (True, False):
            try:
                chunk = _get_report_once(
                    gmp,
                    report_id,
                    filter_string=filt,
                    ignore_pagination=False,
                    details=details,
                )
                last_exc = None
                if details and detail_chunk is None:
                    detail_chunk = chunk
                break
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "get_report(%s, details=%s, first=%s) failed: %s",
                    report_id,
                    details,
                    first,
                    exc,
                )
                if _gmp_connection_lost(exc):
                    break
        if chunk is None:
            break
        if meta is None:
            meta = chunk
        try:
            page_vulns = _vulnerabilities_from_report(chunk)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities page first=%s: %s", first, exc)
            page_vulns = []
        vulns.extend(page_vulns)
        nodes = _xml_result_nodes(_inner_report(chunk))
        pages += 1
        if len(nodes) < page_rows:
            break
        first += page_rows
        if pages >= 500:
            log.warning("OpenVAS report %s page cap reached (%s pages)", report_id, pages)
            break

    if meta is None and pages == 0 and not (last_exc and _gmp_connection_lost(last_exc)):
        try:
            meta = _get_report_once(
                gmp,
                report_id,
                filter_string=_report_filter_string(first=1, rows=page_rows),
                ignore_pagination=False,
                details=False,
            )
            last_exc = None
            vulns = _vulnerabilities_from_report(meta)
        except Exception as exc:
            last_exc = exc
            log.warning("get_report(%s) compact dump failed: %s", report_id, exc)

    if detail_chunk is None:
        log.warning(
            "OpenVAS report %s: no details=True page was readable; host port details and "
            "per-NVT error rows are unavailable, coverage is classified from results only",
            report_id,
        )
    return meta, vulns, last_exc, detail_chunk


_TERMINAL_GMP = {"done", "finished", "succeeded"}


def _same_host(a: Any, b: Any) -> bool:
    import ipaddress

    def canon(v: Any) -> str:
        raw = str(v or "").strip()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw.casefold()

    return canon(a) == canon(b)


def _coverage_includes_parsed_results(evidence: dict[str, Any], vulns: list[dict[str, Any]]) -> None:
    """Fold paged findings into the per-host coverage verdict (V1.6.5).

    Rules:
    * Only a *port-scanner* NVT error (Nmap / Ping Host / Services / Open TCP
      Port) degrades a host. Ordinary NVT errors such as "NVT timed out after
      320 seconds" are recorded as named warnings: those specific checks are
      incomplete, the port enumeration is not.
    * Open ports come from host details (``ports``/``tcp_ports``) and from
      every result row of the form ``N/tcp``/``N/udp``.
    * ``nvts_evidenced`` counts distinct NVT OIDs, never result rows.
    * Hostname/OS/traceroute rows alone still do not prove a port scan.
    """
    coverage = evidence.get("host_coverage")
    if not isinstance(coverage, dict) or not coverage:
        return
    hosts = [host for host, cov in coverage.items() if isinstance(cov, dict)]
    task_done = str(evidence.get("task_status") or "").strip().lower() in _TERMINAL_GMP
    error_details = [e for e in (evidence.get("plugin_error_details") or []) if isinstance(e, dict)]
    unclassified_total = int(evidence.get("plugin_errors_unclassified") or 0)
    if not unclassified_total:
        unclassified_total = max(0, int(evidence.get("plugin_error_count") or 0) - len(error_details))
    for host, cov in coverage.items():
        if not isinstance(cov, dict):
            continue
        rows = [r for r in vulns if _same_host(r.get("host"), host)]
        if not rows and len(hosts) == 1:
            rows = list(vulns)
        tcp = {int(p) for p in (cov.get("open_tcp_ports") or []) if str(p).isdigit()}
        udp = {int(p) for p in (cov.get("open_udp_ports") or []) if str(p).isdigit()}
        oids: set[str] = set()
        for row in rows:
            port = row.get("port")
            proto = str(row.get("protocol") or "").lower()
            if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                (udp if proto == "udp" else tcp).add(port)
            oid = str(row.get("nvt_oid") or row.get("plugin_id") or "").strip()
            if oid:
                oids.add(oid)
        nvts = max(int(cov.get("nvts_evidenced") or 0), len(oids))
        cov["open_tcp_ports"] = sorted(tcp)[:512]
        cov["open_udp_ports"] = sorted(udp)[:128]
        cov["nvts_evidenced"] = nvts
        cov["nvts_launched"] = nvts  # compatibility alias: evidenced, not an execution inventory
        cov["results_evidenced"] = len(rows)

        from agent.scan_coverage import is_port_scanner_error

        # V1.10.3: "Nmap OS Identification" and the nmap service-detection
        # wrappers are not port scanners. Their timeouts are check warnings;
        # only a real port-scanner failure makes the network scan incomplete.
        scanner_errors = [
            e for e in (cov.get("port_scanner_errors") or [])
            if isinstance(e, dict)
            and is_port_scanner_error(str(e.get("nvt_oid") or ""), str(e.get("nvt_name") or ""),
                                      str(e.get("description") or ""))
        ]
        cov["port_scanner_errors"] = scanner_errors
        scanner_keys = {(str(e.get("nvt_oid") or ""), str(e.get("nvt_name") or "")) for e in scanner_errors}
        host_errors = [
            e for e in error_details
            if (not e.get("host") or _same_host(e.get("host"), host))
            and (str(e.get("nvt_oid") or ""), str(e.get("nvt_name") or "")) not in scanner_keys
        ]
        unclassified = unclassified_total if len(hosts) == 1 else 0
        warnings: list[str] = []
        for err in host_errors[:20]:
            label = str(err.get("nvt_name") or err.get("nvt_oid") or "NVT")
            port = f" on {err.get('port')}" if err.get("port") else ""
            desc = str(err.get("description") or "error").strip().splitlines()[0][:160]
            warnings.append(f"{label}{port}: {desc}"[:240])
        if unclassified:
            warnings.append(
                f"{unclassified} scanner error(s) reported by count only; the detailed report page was unavailable"
            )
        cov["warnings"] = warnings
        cov["plugin_error_count"] = len(scanner_errors) + len(host_errors) + unclassified
        cov["coverage_complete"] = False
        cov["service_checks_verified"] = False

        if scanner_errors:
            first = scanner_errors[0]
            cov["verdict"] = "degraded_port_scan_failed"
            cov["network_scan_complete"] = False
            cov["reason"] = (
                f"port scanner NVT failed ({first.get('nvt_name') or first.get('nvt_oid') or 'scanner'}: "
                f"{str(first.get('description') or 'error')[:120]}); service NVTs may not have run"
            )
            continue
        if tcp or udp:
            cov["verdict"] = "observed_unverified"
            cov["network_scan_complete"] = bool(task_done)
            cov["assessment_scope"] = cov.get("assessment_scope") or "network"
            port_text = ", ".join(
                [f"{p}/tcp" for p in sorted(tcp)[:12]] + [f"{p}/udp" for p in sorted(udp)[:6]]
            )
            more = "" if len(tcp) + len(udp) <= 18 else f" (+{len(tcp) + len(udp) - 18} more)"
            reason = (
                f"Network scan finished: {len(tcp)} open TCP / {len(udp)} UDP port(s) [{port_text}{more}]; "
                f"{nvts} distinct NVT(s) produced {len(rows)} result(s)"
            )
            if warnings:
                reason += f"; {len(warnings)} NVT warning(s), those specific checks are incomplete"
            cov["reason"] = reason + ". Per-service execution and authenticated checks are not proven"
            continue
        cov["verdict"] = "degraded_no_ports"
        cov["network_scan_complete"] = False
        cov["reason"] = (
            f"Greenbone reported no open listeners ({len(rows)} result(s) from {nvts} NVT(s), 0 open ports). "
            "This does not prove the host is unreachable or that all catalog probes ran; "
            "verify Docker-to-target routing, firewall and port scanner evidence"
        )


def _apply_scan_purpose(evidence: dict[str, Any], purpose: str | None) -> None:
    """Record what the scan was for; ping-only discovery judges hosts by aliveness."""
    purpose = purpose or "vulnerability"
    coverage = evidence.get("host_coverage")
    if not isinstance(coverage, dict):
        return
    alive_hosts = {str(h).strip() for h in (evidence.get("assessed_hosts") or []) if str(h).strip()}
    for host, cov in coverage.items():
        if not isinstance(cov, dict):
            continue
        cov["scan_purpose"] = purpose
        if purpose != "ping_discovery":
            continue
        alive = any(_same_host(host, h) for h in alive_hosts)
        cov["alive"] = alive
        cov["network_scan_complete"] = False  # no port scan by design
        cov["coverage_complete"] = False
        if alive:
            cov["verdict"] = "discovery_alive"
            cov["reason"] = "Host answered the alive test (ping-only discovery: no ports or vulnerabilities checked)"
        else:
            cov["verdict"] = "discovery_not_alive"
            cov["reason"] = "No answer to ICMP, TCP-ACK or ARP ping (ping-only discovery)"


def _report_payload(
    gmp: Any,
    task_id: str,
    *,
    expected_targets: list[str],
    alive_test: str,
    task_status: str,
    progress: float,
    policy_snapshot: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _, _, task = _task_status(gmp, task_id)
    report_id = _task_report_id(task)
    if not report_id:
        evidence = {
            "report_id": None,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "no_report",
            "alive_test": alive_test,
        }
        return [], evidence

    response, paged_vulns, last_exc, detail_response = _harvest_report_bundle(gmp, report_id)
    if response is None:
        evidence = {
            "report_id": report_id,
            "task_status": task_status,
            "progress": progress,
            "hosts_attempted": len(expected_targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "scan_start": None,
            "scan_end": None,
            "assessment_complete": False,
            "assessment_verdict": "report_read_error",
            "alive_test": alive_test,
            "report_read_error": str(last_exc)[:1000] if last_exc else "get_report failed",
        }
        return [], evidence

    evidence = _report_evidence_from_xml(
        response,
        report_id=report_id,
        task_status=task_status,
        progress=progress,
        expected_targets=expected_targets,
        alive_test=alive_test,
        detail_response=detail_response,
    )
    vulns = paged_vulns
    if not vulns:
        try:
            vulns = _vulnerabilities_from_report(response)
        except Exception as exc:
            log.warning("Could not parse vulnerabilities for report %s: %s", report_id, exc)
            vulns = []
            evidence["report_read_error"] = (
                ((evidence.get("report_read_error") or "") + f"; vuln_parse: {exc}")[:1000]
            )

    declared = int(evidence.get("report_result_count") or 0)
    full = int(evidence.get("report_result_count_full", -1))
    filtered = int(evidence.get("report_result_count_filtered", -1))
    materialized = int(evidence.get("report_materialized_result_count") or 0)
    parsed = len(vulns)
    if parsed and (materialized == 0 or materialized < parsed):
        evidence["report_materialized_result_count"] = parsed
        evidence["report_result_count"] = parsed
        materialized = parsed
        declared = parsed
    histogram: dict[str, int] = {}
    for row in vulns:
        sev = str(row.get("severity") or "info").lower()
        histogram[sev] = histogram.get(sev, 0) + 1
    log.info(
        "OpenVAS report %s result integrity full=%d filtered=%d materialized=%d parsed=%d severity=%s",
        report_id, full, filtered, materialized, parsed, histogram,
    )
    mismatch = ""
    # Paged harvest often returns fewer <results> in the metadata XML than the
    # combined pages. Do not fail coverage for that.
    if parsed > 0 and materialized == parsed:
        mismatch = ""
    elif filtered >= 0 and filtered != materialized and parsed == 0:
        mismatch = (
            f"filtered_result_count_mismatch filtered={filtered} "
            f"materialized={materialized}"
        )
    elif materialized != parsed:
        mismatch = f"parser_result_count_mismatch materialized={materialized} parsed={parsed}"
    elif declared != parsed:
        mismatch = f"result_count_mismatch returned={declared} parsed={parsed}"
    if mismatch:
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + mismatch)[:1000]
        )
        evidence["assessment_complete"] = False
        evidence["assessment_verdict"] = "result_count_mismatch"
    elif last_exc and (parsed == 0 or (filtered >= 0 and parsed < filtered)):
        err = str(last_exc)[:1000]
        evidence["report_read_error"] = (
            ((evidence.get("report_read_error") or "") + ("; " if evidence.get("report_read_error") else "") + err)[:1000]
        )
    _coverage_includes_parsed_results(evidence, vulns)
    _apply_scan_purpose(evidence, (policy_snapshot or {}).get("scan_purpose") if isinstance(policy_snapshot, dict) else None)
    extra_hosts = {
        str(row.get("host") or "").strip()
        for row in vulns
        if str(row.get("host") or "").strip()
    }
    if extra_hosts:
        assessed = {str(h).strip() for h in (evidence.get("assessed_hosts") or []) if str(h).strip()}
        assessed.update(extra_hosts)
        evidence["assessed_hosts"] = sorted(assessed)
        evidence["hosts_assessed"] = max(int(evidence.get("hosts_assessed") or 0), len(assessed))
    snapshot = policy_snapshot if isinstance(policy_snapshot, dict) else {}
    watch = mark_cve_watchlist(vulns, snapshot.get("cve_watchlist"))
    if watch:
        evidence["cve_watchlist"] = watch
    evidence["service_coverage"] = {
        host: analyze_services(
            vulns,
            host=host,
            coverage=(evidence.get("host_coverage") or {}).get(host),
            scanned_port_range=snapshot.get("port_range"),
        )
        for host in expected_targets
    }
    return vulns, evidence


def _task_port_range_with(gmp: Any, tid: str) -> str:
    """Target port range of a GMP task using an existing session ("" when unknown)."""
    _, _, task = _task_status(gmp, tid)
    if task is None or not hasattr(task, "find"):
        return ""
    target = task.find("target")
    target_id = (target.get("id") if target is not None else None) or None
    if not target_id:
        return ""
    try:
        tresp = gmp.get_target(str(target_id))
    except Exception:
        tresp = gmp.get_targets(filter_string=f"uuid={target_id}")
    tnode = tresp.find("target") if hasattr(tresp, "find") else None
    if tnode is None and hasattr(tresp, "xpath"):
        nodes = tresp.xpath(".//target")
        tnode = nodes[0] if nodes else None
    if tnode is None or not hasattr(tnode, "find"):
        return ""
    node = tnode.find("port_range")
    direct = (node.text or "").strip() if node is not None and node.text else ""
    if direct:
        return direct
    port_list = tnode.find("port_list")
    port_list_id = (port_list.get("id") if port_list is not None else None) or None
    if not port_list_id:
        return ""
    presp = gmp.get_port_list(str(port_list_id))
    parts: list[str] = []
    for item in presp.xpath(".//port_range") if hasattr(presp, "xpath") else []:
        start = (item.findtext("start") or "").strip()
        end = (item.findtext("end") or "").strip()
        kind = (item.findtext("type") or "tcp").strip().lower()
        prefix = "U" if kind == "udp" else "T"
        if not start or not end:
            continue
        parts.append(f"{prefix}:{start}" if start == end else f"{prefix}:{start}-{end}")
    return ",".join(parts)


class LocalOpenVAS:
    # V1.9.3: IP starts run concurrently; the port-list note set while resolving
    # one IP's range must not leak into another IP's policy snapshot.
    @property
    def _port_list_status(self) -> str:
        return str(getattr(self.__dict__.setdefault("_thread_state", threading.local()), "port_list_status", ""))

    @_port_list_status.setter
    def _port_list_status(self, value: str) -> None:
        self.__dict__.setdefault("_thread_state", threading.local()).port_list_status = value

    def __init__(self) -> None:
        self.socket_path = (os.environ.get("GVM_SOCKET_PATH") or "").strip() or None
        url = (os.environ.get("GVM_URL") or "").strip()
        self.host, self.port = "127.0.0.1", 9390
        if url and not self.socket_path:
            if "://" not in url:
                url = f"tls://{url}"
            parsed = urlparse(url)
            self.host = parsed.hostname or "127.0.0.1"
            self.port = parsed.port or 9390
            if parsed.scheme == "unix":
                self.socket_path = parsed.path or None
        self.username = os.environ.get("GVM_USERNAME") or "admin"
        self.password = os.environ.get("GVM_PASSWORD") or "admin"
        self.port_profile = (os.environ.get("PORT_PROFILE") or "nexus").strip().lower()
        self.udp_profile = (os.environ.get("UDP_PROFILE") or "priority").strip().lower()
        # V1.8.0: task_id -> {scan address: authorized target} for self-scans.
        from agent.self_target import AliasStore

        self.self_scan_aliases = AliasStore()
        plugins_raw = int(os.environ.get("PLUGINS_TIMEOUT_SEC") or 0)
        scanner_raw = int(os.environ.get("SCANNER_PLUGINS_TIMEOUT_SEC") or 0)
        # V45 (Nessus parity). The previous 60 s / 90 s floors were added to stop
        # an SMB connect loop from pinning a host at 94-97 %, but
        # ``scanner_plugins_timeout`` is the budget for the *port-scanner* NVTs
        # (Nmap / find_service). A full T:1-65535 sweep needs minutes, so at 90 s
        # the scanner was killed, no services were discovered and every host
        # finished with only 3 informational results (plugin_errors=1).
        #
        # Use Greenbone's defaults (NVT 320 s, scanner NVTs 36 000 s). Hung
        # hosts are bounded by the agent-side watchdog instead
        # (MAX_SCAN_RUNTIME_SEC / STALL_SEC), which cancels the task and keeps
        # partial results rather than silently degrading coverage.
        if plugins_raw <= 0:
            plugins_raw = 320
        if scanner_raw <= 0:
            scanner_raw = 36000
        self.plugins_timeout = max(60, plugins_raw)
        self.scanner_plugins_timeout = max(self.plugins_timeout, scanner_raw)
        # V45: honour the configured per-host check concurrency. The old
        # ``max(configured, 16)`` silently overrode GVM_MAX_CHECKS=8, so eight
        # concurrent IP tasks became 128 NVT processes on a laptop.
        configured_checks = max(1, int(os.environ.get("GVM_MAX_CHECKS") or 8))
        self.max_hosts = max(1, int(os.environ.get("GVM_MAX_HOSTS") or 1))
        # V1.9.0: ceiling raised 16 -> 128 so the turbo profile can run many NVTs
        # at once against a single host (the only concurrency that helps one IP).
        # The configured GVM_MAX_CHECKS is still honoured as the floor for
        # standard/fast; turbo overrides it via the performance profile.
        self.max_checks_cap = max(16, int(os.environ.get("GVM_MAX_CHECKS_CAP") or 128))
        self.max_checks = min(configured_checks, self.max_checks_cap)
        assessment = self.port_profile == "full" or self.port_profile in _VULN_PROFILES
        read_raw = max(1, int(os.environ.get("GVM_CHECKS_READ_TIMEOUT") or (10 if assessment else 5)))
        retry_raw = max(0, int(os.environ.get("GVM_TIMEOUT_RETRY") or (3 if assessment else 1)))
        sock_raw = max(1, int(os.environ.get("GVM_OPEN_SOCK_MAX_ATTEMPTS") or (5 if assessment else 2)))
        # The short fast profile keeps the aggressive socket caps. The
        # Nessus-style catalog uses the configured read and retry budget so
        # SMB, SSH, TLS, and database checks are not abandoned early.
        if self.max_hosts <= 1 and not assessment:
            read_raw = min(read_raw, 5)
            retry_raw = min(retry_raw, 1)
            sock_raw = min(sock_raw, 2)
        self.checks_read_timeout = read_raw
        self.timeout_retry = retry_raw
        self.open_sock_max_attempts = sock_raw
        self.scan_config_name = (os.environ.get("GVM_SCAN_CONFIG") or "Full and fast").strip()
        # V1.6.5 Nessus parity: Nessus ships optimize_test=yes (Tenable notes that
        # disabling it lengthens scans and increases false positives). OpenVAS
        # optimize_test=yes likewise only launches an NVT when its required
        # ports/services were detected. GVM_OPTIMIZE_TEST=no restores the old
        # forced behaviour; a scan policy/template can set it per job.
        configured_optimization = (os.environ.get("GVM_OPTIMIZE_TEST") or "").strip().lower()
        self.optimize_test = "no" if configured_optimization in {"no", "false", "0", "off"} else "yes"
        # Use current OpenVAS scanner preference names.  A previous build sent
        # `thorough_tests`, which is not a current scanner preference and can
        # make gvmd reject the entire preference payload on some releases.
        self.safe_checks = (os.environ.get("GVM_SAFE_CHECKS") or "yes").strip().lower()
        self.expand_vhosts = (os.environ.get("GVM_EXPAND_VHOSTS") or "yes").strip().lower()
        self.test_empty_vhost = (os.environ.get("GVM_TEST_EMPTY_VHOST") or "yes").strip().lower()
        self.allow_bare_task_fallback = (
            os.environ.get("GVM_ALLOW_BARE_TASK_FALLBACK") or "false"
        ).strip().lower() in {"1", "true", "yes", "on"}
        # Explicitly authorized single-host scans must not be silently skipped
        # merely because ICMP/TCP discovery is blocked. python-gvm create_target
        # accepts the literal GMP alive-test string "Consider Alive".
        self.alive_test = (os.environ.get("GVM_ALIVE_TEST") or "Consider Alive").strip()
        self._next_not_ready_log = 0.0
        self.last_readiness_detail = "Greenbone readiness has not been checked yet"
        self.policy_snapshots: dict[str, dict[str, Any]] = {}
        self._iana_tcp_cache: tuple[float, set[int]] | None = None
        self._port_list_status = ""
        # Completed report tasks are never eligible for a second stop request.
        self._terminal_task_ids: set[str] = set()

    def ready(self) -> bool:
        # V1.9.6: a positive result is reused for READINESS_RECHECK_SEC (default 60 s).
        # The dispatcher calls ready() on every pass (QUEUE_POLL_INTERVAL_SEC = 3 s).
        # Until V1.9.4 one probe took ~40 s, which hid that; once it got fast,
        # gvmd was probed - scanners, feeds, NVT count, every scan config, the full
        # base config - every ~4 s, also during scans. Not-ready is still
        # re-checked on every pass so a starting gvmd is picked up quickly.
        now = time.monotonic()
        if now < float(getattr(self, "_ready_until", 0.0) or 0.0):
            return True
        result = self._probe_ready()
        try:
            ttl = max(0, min(600, int(os.environ.get("READINESS_RECHECK_SEC") or 60)))
        except ValueError:
            ttl = 60
        self._ready_until = (time.monotonic() + ttl) if result else 0.0
        return result

    def invalidate_readiness(self) -> None:
        """Force the next ready() to probe gvmd again."""
        self._ready_until = 0.0

    def _probe_ready(self) -> bool:
        sock = (self.socket_path or "").strip()
        if sock and not os.path.exists(sock):
            self._log_not_ready("GMP socket not present yet (%s) — waiting for gvmd" % sock)
            return False
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _find_scanner_id(gmp)
                feed_state = _ospd_feed_state(gmp)
                if not feed_state.get("ready"):
                    self._log_not_ready(str(feed_state.get("detail") or "OSPd OpenVAS feed is still loading"))
                    return False
                config_id = _find_config_id(gmp, self.scan_config_name)
                health = _assert_feed_quality(gmp, config_id)
            count = health.get("nvt_count")
            self.last_readiness_detail = (
                f"Greenbone ready: {self.scan_config_name}; NVTs={count}"
                if count is not None
                else f"Greenbone ready: {self.scan_config_name}"
            )
            return True
        except Exception as exc:
            self._log_not_ready("Local OpenVAS not ready: %s" % exc)
            return False

    def _log_not_ready(self, message: str) -> None:
        self.last_readiness_detail = str(message)[:500]
        now = time.monotonic()
        if now < self._next_not_ready_log:
            return
        log.warning("%s", message)
        self._next_not_ready_log = now + 60.0

    def resolve_port_range(
        self,
        targets: list[str],
        port_range: str | None = None,
        scan_policy: dict[str, Any] | None = None,
        *,
        apply_udp: bool = True,
    ) -> str:
        """Return the port range start_scan would send for these targets."""
        host_list = [t.strip() for t in targets if t and t.strip()]
        snapshot = _effective_scan_policy(scan_policy, self.port_profile, self.udp_profile)
        supplied_range = (port_range or "").strip()
        udp_profile = str(snapshot.get("udp_profile") or self.udp_profile)
        if supplied_range:
            resolved = _with_udp_range(supplied_range, udp_profile) if apply_udp else supplied_range
        else:
            resolved = str(snapshot["port_range"] or "")
            if snapshot.get("port_profile") in NESSUS_MODES:
                resolved = self._widen_with_iana(resolved)
        try:
            from agent.control_plane import port_range_without_control_plane

            adjusted = port_range_without_control_plane(resolved, host_list)
            if adjusted != resolved:
                log.info("OpenVAS port_range excludes Aetheris control-plane HTTP ports")
                resolved = adjusted
        except Exception:
            log.debug("Control-plane port exclusion skipped", exc_info=True)
        return resolved

    def _iana_tcp_ports(self) -> set[int]:
        """Greenbone "All IANA assigned TCP" ports, cached for 6 h (retry failures after 10 min)."""
        now = time.monotonic()
        if self._iana_tcp_cache is not None:
            stamp, ports = self._iana_tcp_cache
            if now - stamp < (21600 if ports else 600):
                return ports
        try:
            with _session(**self._session_kwargs()) as gmp:
                ports = _named_port_list_tcp(gmp, NESSUS_IANA_PORT_LIST)
            log.info("Nessus profile: loaded %d TCP ports from Greenbone port list '%s'",
                     len(ports), NESSUS_IANA_PORT_LIST)
        except Exception as exc:
            log.warning("Nessus profile: Greenbone port list '%s' unavailable (%s); using TCP 1-1024 + catalog",
                        NESSUS_IANA_PORT_LIST, exc)
            ports = set()
        self._iana_tcp_cache = (now, ports)
        return ports

    def _widen_with_iana(self, port_range: str) -> str:
        iana = self._iana_tcp_ports()
        if not iana:
            self._port_list_status = "fallback: TCP 1-1024 + 52-family catalog (IANA list unavailable)"
            return port_range
        tcp: set[int] = set()
        udp_tokens: list[str] = []
        for token in (port_range or "").split(","):
            piece = token.strip()
            if piece.upper().startswith("U:"):
                udp_tokens.append(piece)
            elif piece:
                tcp.update(port_numbers(piece[2:] if piece.upper().startswith("T:") else piece))
        tcp |= iana
        self._port_list_status = f"widened with '{NESSUS_IANA_PORT_LIST}' ({len(iana)} ports)"
        return ",".join(x for x in [format_ports(sorted(tcp), "T"), *udp_tokens] if x)

    def start_scan(self, *, name: str, targets: list[str], port_range: str | None = None,
                   scan_policy: dict[str, Any] | None = None,
                   max_checks: int | None = None,
                   apply_udp: bool = True,
                   scan_addresses: dict[str, str] | None = None) -> str:
        host_list = [t.strip() for t in targets if t and t.strip()]
        if not host_list:
            raise ValueError("At least one target is required")
        # V1.8.0: an authorized target that is this scanner's own address is
        # scanned through the Docker loopback alias (see agent/self_target.py).
        # Everything reported back stays keyed by the authorized target.
        aliases = {
            h: str(scan_addresses[h]).strip()
            for h in host_list
            if scan_addresses and str((scan_addresses or {}).get(h) or "").strip()
        }
        scan_hosts = [aliases.get(h, h) for h in host_list]
        snapshot = _effective_scan_policy(scan_policy, self.port_profile, self.udp_profile)
        # V1.9.0: a required credential kind the laptop can provision locally is
        # not a gap; the credential is created inside the session below. Evaluate
        # the gap against refs the policy supplied PLUS kinds the laptop can
        # provide, so a Nexpose/credentialed audit with the SMB login set on the
        # laptop launches instead of being refused.
        gap_request = dict(snapshot)
        try:
            from agent.local_credentials import available_kinds

            local_kinds = set(available_kinds())
        except Exception:
            local_kinds = set()
        if local_kinds:
            merged_refs = dict(gap_request.get("gmp_credential_refs") or {})
            for kind in local_kinds:
                merged_refs.setdefault(kind, "pending-local-provision")
            gap_request["gmp_credential_refs"] = merged_refs
        gap = credential_gap(gap_request)
        if gap:
            # Fail before any target/task exists: a patch audit without
            # credentials would look complete while testing nothing it promised.
            raise ValueError(gap)
        self._port_list_status = ""
        port_range = self.resolve_port_range(
            host_list, port_range, scan_policy, apply_udp=apply_udp,
        )
        if snapshot.get("port_profile") in NESSUS_MODES:
            snapshot["port_list_status"] = self._port_list_status or "supplied port range (resolved earlier)"
        base_config = str(snapshot.get("scan_config") or self.scan_config_name)
        alive_test = str(snapshot.get("alive_test") or self.alive_test)
        safe_checks = str(snapshot.get("safe_checks") or self.safe_checks)
        optimize_test = str(snapshot.get("optimize_test") or self.optimize_test)
        families = list(snapshot.get("nvt_families") or [])
        from agent.scan_performance import hang_registry, profile_settings, resolve_profile, static_caps

        performance = resolve_profile(snapshot)
        from agent.scan_performance import resolve_check_scope

        check_scope = resolve_check_scope(snapshot)
        snapshot["check_scope"] = check_scope
        perf_cfg = profile_settings(performance)
        read_timeout = int(perf_cfg["checks_read_timeout"] or self.checks_read_timeout)
        try:
            learned_caps = hang_registry().caps() if perf_cfg["hang_caps"] else {}
        except Exception:
            log.warning("NVT hang statistics unavailable; no learned timeout caps applied", exc_info=True)
            learned_caps = {}
        # V1.9.0: always bound the known-slow SSL/TLS cipher checks (the tail hang
        # at ~98% on full-port scans), even in the standard profile and on the
        # first run before the hang registry has learned them. Learned caps still
        # win where they are tighter.
        hang_caps = dict(static_caps())
        cap_sources = {"static_ssl": len(hang_caps), "learned": len(learned_caps), "long_timeout": 0}
        for oid, secs in learned_caps.items():
            hang_caps[oid] = min(hang_caps.get(oid, secs), secs)
        # V1.9.3: checks whose OWN script_timeout is above SCAN_NVT_MAX_SEC (or
        # unbounded). OpenVAS uses that value instead of plugins_timeout, which
        # is what holds a host at 98-99 % for 30-60 min (job 3c4f45e0).
        from agent.nvt_timeouts import long_timeout_caps, timeout_index
        from agent.scan_performance import nvt_max_sec

        long_max = nvt_max_sec()
        long_caps: dict[str, int] = {}
        if long_max > 0:
            try:
                long_caps = long_timeout_caps(long_max)
            except Exception:
                log.warning("NVT timeout index unavailable; long-timeout caps not applied", exc_info=True)
        for oid, secs in long_caps.items():
            hang_caps[oid] = min(hang_caps.get(oid, secs), secs)
        cap_sources["long_timeout"] = len(long_caps)
        index_status = timeout_index().status() if long_max > 0 else "off (SCAN_NVT_MAX_SEC=0)"
        cap = getattr(self, "max_checks_cap", 128)
        lane_checks = self.max_checks if max_checks is None else max(1, min(cap, int(max_checks)))
        if perf_cfg["max_checks"]:
            # Nessus default is 5 simultaneous checks per host; the turbo profile
            # scales with CPU count. capacity.py still limits how many IPs run at
            # once under thermal/memory pressure.
            lane_checks = max(lane_checks, min(cap, int(perf_cfg["max_checks"])))
        if (os.environ.get("SCAN_PORT_SEMAPHORE") or "").strip():
            # V1.10.3: the per-IP port semaphore is a hard upper bound.
            from agent.scan_performance import port_semaphore

            lane_checks = min(lane_checks, port_semaphore())
        snapshot["requested_port_range"] = snapshot["port_range"]
        for transport, key in (("T", "tcp_port_count"), ("U", "udp_port_count")):
            snapshot[key] = len({p for token in port_range.split(",") if token.startswith(transport + ":")
                                 for p in port_numbers(token[2:])})
        with _session(
            socket_path=self.socket_path,
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
        ) as gmp:
            # V1.9.3: IPs start concurrently. Config lookup/creation is serialised so two
            # starts never clone the same profile twice; target/task creation is not.
            with _CONFIG_PREP_LOCK:
                try:
                    config_id = _ensure_portscan_config(gmp, base_config)
                except Exception:
                    log.warning("Nmap SYN config unavailable; using %s", base_config, exc_info=True)
                    config_id = _find_config_id(gmp, base_config)
                full_config = base_config.casefold() == "full and fast"
                nvt_filter = snapshot.get("nvt_filter") if isinstance(snapshot.get("nvt_filter"), dict) else None
                if families:
                    config_id, snapshot["family_scope_status"] = _ensure_family_config(
                        gmp, config_id, families, require=bool(snapshot.get("require_families")))
                elif full_config and nvt_filter:
                    config_id, snapshot["check_scope_status"] = _ensure_check_scope_config(gmp, config_id, nvt_filter)
                elif full_config and check_scope in {"vulnerability", "severity"}:
                    config_id, snapshot["check_scope_status"] = _ensure_check_scope_config(
                        gmp, config_id, mode=check_scope)
                scanner_prefs = {
                    "plugins_timeout": str(int(perf_cfg["plugins_timeout"] or self.plugins_timeout)),
                    "checks_read_timeout": str(read_timeout),
                    "optimize_test": optimize_test,
                    "safe_checks": safe_checks,
                }
                # V1.9.5: per-check logging (log_whole_attack) is NOT set here any more:
                # through a scan config it can only switch logging off (see
                # _OPENVAS_CONF_ONLY_PREFS). It comes from openvas.conf, written by
                # configure-openvas from OPENVAS_LOG_WHOLE_ATTACK.
                # V1.9.3: caps and Nmap timing for every profile. Before, they were
                # passed only when performance == "fast", so turbo and standard
                # scans ran without even the static SSL caps.
                config_id, perf_status = _ensure_profile_config(
                    gmp, config_id, scanner_prefs, hang_caps, perf_cfg["nmap_timing"],
                )
            # V1.9.1: record what the task's own config will run. A partial family
            # here is exactly the silent truncation that hid every Medium/Low.
            selection = effective_selection(gmp, config_id)
            snapshot["check_selection"] = selection
            if selection.get("available"):
                partial = selection.get("partial_families") or {}
                log.info(
                    "Effective check selection for task config %s: %s checks in %s/%s families; "
                    "partial families: %s; not selected: %s",
                    config_id, selection.get("nvt_count"), selection.get("families_selected"),
                    selection.get("families_total"),
                    ", ".join(f"{k} {v}" for k, v in sorted(partial.items())) or "none",
                    ", ".join(selection.get("families_unselected") or []) or "none",
                )
            log.info(
                "NVT timeout caps on %s: %d static SSL, %d long-timeout (own timeout above %ss or none; "
                "index %s), %d learned; per-check logging comes from openvas.conf (checked in openvas.log)",
                config_id, cap_sources["static_ssl"], cap_sources["long_timeout"], long_max or "off",
                index_status, cap_sources["learned"],
            )
            # The 10k-NVT config floor only applies to an unscoped Full-and-fast
            # config; Discovery or family-scoped configs are smaller by design.
            # The feed-wide NVT floor is always enforced.
            narrowed = str(snapshot.get("family_scope_status") or "").startswith("scoped") or bool(nvt_filter)
            floor_config = config_id if full_config and not narrowed else None
            known_count = selection.get("nvt_count") if selection.get("available") else None
            if floor_config and isinstance(known_count, int) and known_count >= 0:
                # V1.9.3: the config's check count was just read (effective_selection).
                # Reading the same config again with details cost 30-40 s per IP start
                # on the 185k-check config; check the floor from the count we have.
                health = dict(_assert_feed_quality(gmp, None) or {})
                minimum = _minimum_nvt_count()
                if known_count < minimum:
                    raise RuntimeError(
                        f"Greenbone config_nvt_count={known_count} is below required minimum {minimum}; "
                        "feed/config import is incomplete, so the scanner will not claim the job"
                    )
                health["config_nvt_count"] = known_count
            else:
                health = _assert_feed_quality(gmp, floor_config)
            scanner_id = _find_scanner_id(gmp)
            bindings: dict[str, str] = {}
            credential_status: dict[str, str] = {}
            # V1.9.0: provision SMB/SSH credentials held locally on the laptop so a
            # policy that asks for credentials (or auto-bind) runs authenticated,
            # instead of only accepting a pre-existing Greenbone credential UUID.
            # Passwords/keys never came through the central policy; they are read
            # from the laptop environment inside agent.local_credentials.
            try:
                from agent.local_credentials import resolve_refs

                resolved = resolve_refs(
                    gmp,
                    requested_kinds=list(snapshot.get("require_credentials") or []),
                    existing_refs=dict(snapshot.get("gmp_credential_refs") or {}),
                )
                snapshot["gmp_credential_refs"] = dict(resolved["refs"])
                if resolved["provisioned"]:
                    snapshot["auto_provisioned_credentials"] = resolved["provisioned"]
                if resolved["status"]:
                    snapshot["local_credential_status"] = resolved["status"]
                    log.info(
                        "Local credential provisioning: %s",
                        ", ".join(f"{k}: {v}" for k, v in sorted(resolved["status"].items())),
                    )
            except Exception:
                log.warning("Local credential provisioning failed; using only policy-supplied refs", exc_info=True)
            for kind, credential_id in snapshot["gmp_credential_refs"].items():
                try:
                    response = gmp.get_credential(credential_id)
                    if not response.xpath(".//credential[@id=$id]", id=credential_id):
                        raise ValueError("Credential reference is unavailable on this scanner")
                    bindings[f"{kind}_credential_id"] = credential_id
                    if kind == "ssh":
                        bindings["ssh_credential_port"] = snapshot["ssh_credential_port"]
                    credential_status[kind] = "bound; authentication success requires native report evidence"
                except Exception:
                    credential_status[kind] = "not-tested; local credential reference lookup failed"
            target_args = {"name": f"{name}-tgt-{int(time.time())}", "hosts": scan_hosts,
                           "port_range": port_range, "alive_test": alive_test}
            try:
                target = gmp.create_target(**target_args, **bindings)
            except Exception as exc:
                if not bindings or not (isinstance(exc, TypeError) or "credential" in str(exc).lower()):
                    raise
                # Unauthenticated protocol detection still runs if credential
                # binding is unsupported; the gap is kept in the policy evidence.
                credential_status = {k: "not-tested; credential binding rejected" for k in credential_status}
                target = gmp.create_target(**target_args)
            target_id = target.get("id")
            if not target_id:
                raise RuntimeError("Failed to create Greenbone target")
            # These names are current OpenVAS scanner preferences.  Do not
            # send legacy/non-scanner keys: one rejected key can cause the
            # whole task preference payload to be rejected.
            prefs = {
                "max_checks": str(lane_checks),
                "max_hosts": str(self.max_hosts),
                "checks_read_timeout": str(read_timeout),
                "timeout_retry": str(self.timeout_retry),
                "open_sock_max_attempts": str(self.open_sock_max_attempts),
                "optimize_test": optimize_test,
                "safe_checks": safe_checks,
                "plugins_timeout": str(self.plugins_timeout),
                "scanner_plugins_timeout": str(self.scanner_plugins_timeout),
                "expand_vhosts": self.expand_vhosts,
                "test_empty_vhost": self.test_empty_vhost,
                "report_host_details": "yes",
            }
            log.info(
                "OpenVAS quality profile max_checks=%s max_hosts=%s "
                "checks_read_timeout=%ss timeout_retry=%s open_sock_max_attempts=%s "
                "plugins_timeout=%ss scanner_plugins_timeout=%ss optimize_test=%s "
                "safe_checks=%s expand_vhosts=%s test_empty_vhost=%s",
                lane_checks,
                self.max_hosts,
                read_timeout,
                self.timeout_retry,
                self.open_sock_max_attempts,
                self.plugins_timeout,
                self.scanner_plugins_timeout,
                optimize_test,
                safe_checks,
                self.expand_vhosts,
                self.test_empty_vhost,
            )
            applied_prefs = dict(prefs)
            preference_status = "full"
            try:
                task = gmp.create_task(
                    name=name[:128],
                    config_id=config_id,
                    target_id=str(target_id),
                    scanner_id=scanner_id,
                    preferences=prefs,
                )
            except Exception as pref_exc:
                # Retry once with the smallest quality-critical preference set.
                # Do not silently fall back to a bare task: that can change
                # optimize/thorough behavior and produce a misleadingly shallow
                # report that still reaches 100%.
                minimal_prefs = {
                    "max_checks": str(lane_checks),
                    "max_hosts": str(self.max_hosts),
                    "optimize_test": prefs["optimize_test"],
                    "safe_checks": safe_checks,
                }
                log.warning(
                    "create_task full preferences failed (%s); retrying quality-critical preferences",
                    pref_exc,
                )
                try:
                    applied_prefs = dict(minimal_prefs)
                    preference_status = "quality-critical fallback"
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                        preferences=minimal_prefs,
                    )
                except Exception as minimal_exc:
                    if not self.allow_bare_task_fallback:
                        raise RuntimeError(
                            "Greenbone rejected required task quality preferences; refusing a bare/degraded scan. "
                            "Set GVM_ALLOW_BARE_TASK_FALLBACK=true only for diagnostic compatibility."
                        ) from minimal_exc
                    log.error(
                        "DEGRADED SCAN: Greenbone rejected task preferences (%s); bare fallback explicitly enabled",
                        minimal_exc,
                    )
                    applied_prefs = {}
                    preference_status = "degraded bare task explicitly enabled"
                    task = gmp.create_task(
                        name=name[:128],
                        config_id=config_id,
                        target_id=str(target_id),
                        scanner_id=scanner_id,
                    )
            task_id = task.get("id")
            if not task_id:
                raise RuntimeError("Failed to create Greenbone task")
            if aliases:
                # Persist before start so a restart mid-scan still maps results back.
                self._self_scan_store().put(str(task_id), {alias: target for target, alias in aliases.items()})
                snapshot["scan_addresses"] = dict(aliases)
                snapshot["self_scan"] = True
            start_response = gmp.start_task(str(task_id))
            snapshot.update({"port_range": port_range, "targets": host_list, "task_id": str(task_id),
                             "config_id": config_id, "scanner_id": scanner_id,
                             "scan_config_name": base_config, "alive_test": alive_test,
                             "performance": performance,
                             "performance_status": {
                                 **perf_status,
                                 "checks_read_timeout": read_timeout,
                                 "plugins_timeout": int(perf_cfg["plugins_timeout"] or self.plugins_timeout),
                                 "max_checks": lane_checks,
                             },
                             "nvt_timeout_caps": {
                                 "count": len(hang_caps),
                                 "applied": int(perf_status.get("nvt_timeout_caps") or 0),
                                 "cap_sec": max(hang_caps.values()) if hang_caps else None,
                                 "oids": sorted(hang_caps)[:20],
                                 "sources": cap_sources,
                                 "long_timeout_max_sec": long_max or None,
                                 "timeout_index": index_status,
                             },
                             "preferences": applied_prefs,
                             "preference_status": preference_status, "credential_status": credential_status,
                             "nvt_count": (health or {}).get("nvt_count"),
                             "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "snapshot_status": "captured_at_task_start"})
            try:
                feeds = gmp.get_feeds()
                snapshot["feed_versions"] = {str(f.findtext("type") or "unknown"): str(f.findtext("version") or "unknown")
                                             for f in feeds.xpath(".//feed")}
            except Exception:
                snapshot["feed_versions"] = {"status": "not available from GMP"}
            import hashlib
            import json
            snapshot["configuration_sha256"] = hashlib.sha256(json.dumps({k: v for k, v in snapshot.items() if k != "configuration_sha256"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.policy_snapshots[str(task_id)] = snapshot
            report_id = None
            try:
                report_id = start_response.findtext("report_id") or (
                    start_response[0].text if len(start_response) else None
                )
            except Exception:
                report_id = None
            log.info(
                "Started local OpenVAS task %s report=%s hosts=%s alive_test=%s "
                "port_profile=%s udp_profile=%s template=%s config=%s port_range=%s",
                task_id,
                report_id,
                host_list,
                alive_test,
                snapshot.get("port_profile"),
                snapshot.get("udp_profile"),
                snapshot.get("template") or "-",
                base_config,
                port_range if len(port_range) <= 400 else port_range[:400] + "...",
            )
            return str(task_id)

    def get_task_hosts(self, task_id: str) -> list[str] | None:
        """Return the hosts bound to an OpenVAS task, or None if unverifiable.

        None means the task is missing or GMP did not return a host list. Callers
        must not guess by chunk index — that is how one network's IPs get
        attached to another job. Self-scan loopback aliases are translated back
        to the authorized target (V1.8.0).
        """
        tid = str(task_id or "").strip()
        if not tid:
            return None
        hosts = self._get_task_hosts_raw(tid)
        mapping = self._self_scan_mapping(tid)
        if hosts and mapping:
            return [mapping.get(h, h) for h in hosts]
        return hosts

    def _self_scan_store(self):
        store = getattr(self, "self_scan_aliases", None)
        if store is None:
            from agent.self_target import AliasStore

            store = self.self_scan_aliases = AliasStore()
        return store

    def _self_scan_mapping(self, task_id: str) -> dict[str, str]:
        try:
            return self._self_scan_store().get(str(task_id or ""))
        except Exception:
            log.debug("Self-scan alias lookup failed for %s", task_id, exc_info=True)
            return {}

    def _get_task_hosts_raw(self, tid: str) -> list[str] | None:
        try:
            with _session(
                socket_path=self.socket_path,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
            ) as gmp:
                _, _, task = _task_status(gmp, tid)
                if task is None:
                    return None
                hosts = _hosts_from_task_elem(task)
                if hosts:
                    return hosts
                target = task.find("target") if hasattr(task, "find") else None
                target_id = (target.get("id") if target is not None else None) or None
                if not target_id:
                    return None
                try:
                    tresp = gmp.get_target(str(target_id))
                except Exception:
                    tresp = gmp.get_targets(filter_string=f"uuid={target_id}")
                tnode = tresp.find("target") if hasattr(tresp, "find") else None
                if tnode is None and hasattr(tresp, "xpath"):
                    nodes = tresp.xpath(".//target")
                    tnode = nodes[0] if nodes else None
                hosts = _hosts_from_target_elem(tnode)
                return hosts or None
        except Exception as exc:
            msg = str(exc).lower()
            status = str(getattr(exc, "status", "") or "")
            if status == "404" or "failed to find task" in msg:
                log.info("OpenVAS task %s is gone; treating leftover id as stale", tid)
                return []
            log.warning("Could not read hosts for OpenVAS task %s", tid, exc_info=True)
            return None

    def task_port_range(self, task_id: str) -> str:
        """Return the GMP target port range, or empty when it cannot be read."""
        tid = str(task_id or "").strip()
        if not tid:
            return ""
        try:
            with _session(**self._session_kwargs()) as gmp:
                return _task_port_range_with(gmp, tid)
        except Exception:
            log.debug("Could not read port range for OpenVAS task %s", tid, exc_info=True)
            return ""

    def _session_kwargs(self) -> dict[str, Any]:
        return {
            "socket_path": self.socket_path,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
        }

    def poll(
        self,
        task_id: str,
        *,
        expected_targets: list[str] | None = None,
        include_running_report: bool = False,
    ) -> dict[str, Any]:
        targets = [str(t).strip() for t in (expected_targets or []) if str(t).strip()]
        # V1.8.0: alias -> authorized target for a self-scan task.
        alias_to_target = self._self_scan_mapping(task_id)
        target_to_alias = {target: alias for alias, target in alias_to_target.items()}
        report_targets = [target_to_alias.get(t, t) for t in targets]
        with _session(**self._session_kwargs()) as gmp:
            status, progress, _ = _task_status(gmp, task_id)
        mapped = "running"
        # Greenbone stays at ~99% with status Processing while it writes the
        # report. That is not a failure — wait for Done, then harvest.
        if status in {"done", "finished", "succeeded"}:
            mapped = "completed"
        elif status in {"stopped", "interrupted", "stop requested"}:
            mapped = "stopped"
        elif status in {"failed", "internal error", "delete requested"}:
            mapped = "failed"
        elif status == "processing":
            mapped = "running"
            progress = max(progress, 99.0)

        vulns: list[dict[str, Any]] = []
        evidence: dict[str, Any] = {
            "report_id": None,
            "task_status": status,
            "progress": progress,
            "hosts_attempted": len(targets),
            "hosts_assessed": 0,
            "assessed_hosts": [],
            "report_result_count": 0,
            "plugin_error_count": 0,
            "plugin_error_details": [],
            "assessment_complete": False,
            "assessment_verdict": "not_finished" if mapped == "running" else "pending_report",
            "alive_test": self.alive_test,
        }
        if mapped in {"completed", "stopped", "failed"} or include_running_report:
            snapshot_for_report = self.policy_snapshots.get(task_id)
            last_exc: Exception | None = None
            for attempt in range(8):
                try:
                    # Never reuse a GMP socket after get_report. gvmd closes it
                    # under large XML and every retry on that handle fails fast.
                    with _session(**self._session_kwargs()) as gmp:
                        if not snapshot_for_report and mapped == "completed":
                            # Resumed after an agent restart: recover the scanned
                            # range from the GMP target (same session) so closed
                            # services are not shown as untested.
                            try:
                                recovered = _task_port_range_with(gmp, task_id)
                            except Exception:
                                recovered = ""
                            snapshot_for_report = {"port_range": recovered} if recovered else None
                        vulns, evidence = _report_payload(
                            gmp,
                            task_id,
                            expected_targets=report_targets,
                            alive_test=self.alive_test,
                            task_status=status,
                            progress=progress,
                            policy_snapshot=snapshot_for_report,
                        )
                    last_exc = None
                except Exception as exc:
                    last_exc = exc
                    evidence["assessment_verdict"] = "report_read_error"
                    evidence["report_read_error"] = str(exc)[:1000]
                    log.warning("Could not read results/evidence for %s (attempt %s)", task_id, attempt + 1)
                filtered_n = int(evidence.get("report_result_count_filtered") or 0)
                incomplete_results = bool(evidence.get("report_read_error")) and (
                    not evidence.get("scan_start")
                    or (filtered_n > 0 and len(vulns) < filtered_n)
                )
                if evidence.get("report_id") and not incomplete_results and (
                    evidence.get("assessment_complete")
                    or not evidence.get("report_read_error")
                ):
                    break
                if mapped != "completed":
                    break
                time.sleep(min(8, 2 + attempt))
                try:
                    with _session(**self._session_kwargs()) as gmp:
                        status, progress, _ = _task_status(gmp, task_id)
                    if status in {"done", "finished", "succeeded"}:
                        mapped = "completed"
                except Exception:
                    log.warning("Could not refresh task status for %s after harvest retry", task_id)
            if last_exc and not evidence.get("report_id"):
                log.warning("Could not read results/evidence for %s", task_id, exc_info=True)

        # GMP completion is authoritative. Retain terminal state across a
        # subsequent coverage retry/cleanup call from another worker thread.
        if mapped in {"completed", "stopped", "failed"}:
            self._terminal_task_ids.add(task_id)
        if alias_to_target:
            from agent.self_target import remap

            vulns = remap(vulns, alias_to_target)
            evidence = remap(evidence, alias_to_target)
            evidence["self_scan"] = {
                target: {
                    "scanned_via": alias,
                    "view": "local",
                    "note": (
                        "This target is the scanner laptop itself. It was scanned through the Docker "
                        f"loopback address {alias}, which the laptop's own firewall does not filter, so the "
                        "results show every listening service (local view), not only what other machines can reach."
                    ),
                }
                for alias, target in alias_to_target.items()
            }
            for target, info in evidence["self_scan"].items():
                cov = (evidence.get("host_coverage") or {}).get(target)
                if isinstance(cov, dict):
                    cov["self_scan"] = info
        evidence["policy_snapshots"] = {task_id: self.policy_snapshots.get(task_id) or {
            "task_id": task_id, "targets": targets, "snapshot_status": "unknown-resumed-task",
            "reason": "Original task policy was not captured by this build"}}
        return {
            "status": mapped,
            "gmp_status": status,
            "progress": progress,
            "vulnerabilities": vulns,
            "evidence": evidence,
        }

    def stop(self, task_id: str) -> bool:
        """Best-effort cancellation of an active task, never a completed report.

        A GMP timeout is an *unknown acknowledgement*, not evidence that a
        finished scan failed. Avoid retrying a possibly accepted stop request.
        Report storage and central result upload are unaffected by this method.
        """
        task_id = str(task_id or "").strip()
        if not task_id:
            log.warning("Ignoring empty OpenVAS stop task ID")
            return False
        terminal = getattr(self, "_terminal_task_ids", set())
        if task_id in terminal:
            log.debug("Skipping stop_task for already harvested terminal task %s", task_id)
            return False
        raw = (os.environ.get("GVM_STOP_TIMEOUT_SEC") or "8").strip()
        try:
            timeout = min(30.0, max(2.0, float(raw)))
        except (ValueError, TypeError):
            timeout = 8.0
        phase = "checking task state"
        try:
            with _session(**self._session_kwargs(), timeout=timeout) as gmp:
                status, _, task = _task_status(gmp, task_id)
                if task is None:
                    log.warning("Cannot stop task %s: task not returned by gvmd", task_id)
                    return False
                if status in {
                    "done", "finished", "succeeded", "stopped", "interrupted",
                    "failed", "internal error", "deleted",
                }:
                    terminal.add(task_id)
                    log.info("No stop required for terminal Greenbone task %s (state=%s)", task_id, status)
                    return False
                if status in {"stop requested", "delete requested"}:
                    log.info("No duplicate stop required for task %s (state=%s)", task_id, status)
                    return False
                if status == "unknown":
                    log.warning("Cannot safely stop task %s: gvmd returned unknown state", task_id)
                    return False
                phase = "sending stop request"
                gmp.stop_task(task_id)
                log.info("Stop requested for active Greenbone task %s (state=%s)", task_id, status)
                return True
        except (TimeoutError, OSError) as exc:
            log.warning(
                "Greenbone cancellation %s timed out for task %s (%s: %s); "
                "state remains unconfirmed, no blind stop retry; existing results retained",
                phase, task_id, type(exc).__name__, exc,
            )
            return False
        except Exception as exc:
            log.warning(
                "Greenbone stop request failed for task %s (%s: %s); "
                "existing scan results remain unchanged",
                task_id, type(exc).__name__, exc,
            )
            return False
