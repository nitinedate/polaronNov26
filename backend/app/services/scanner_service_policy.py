"""Versioned guide policy and evidence-based service routing (no active probes)."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import UUID

CATALOG_PATH = Path(__file__).with_name("service_catalog.json")
SERVICE_PORT_POLICY_PATH = Path(__file__).with_name("service_port_policy.json")
POLICY_PORT_MODES = {"nexus", "catalog"}
TEMPLATES_PATH = Path(__file__).with_name("scan_templates.json")
# nexus    DEFAULT. The Nexus service-port catalog (52 families, ~88 TCP +
#          30 priority UDP ports). V1.6.7 restores this meaning.
# catalog  same scope as nexus
# nessus   wider, opt-in: TCP 1-1024 + catalog, widened at scan time with
#          Greenbone's "All IANA assigned TCP" port list (much slower on
#          Windows hosts with many registered-port listeners)
# full     TCP 1-65535
# vuln/fast/common  legacy catalog-based profiles
# focused  only custom_tcp_ports / custom_udp_ports (threat templates)
MODES = {"full", "fast", "common", "vuln", "nessus", "nexus", "catalog", "focused"}
NESSUS_MODES = {"nessus"}
UDP_MODES = {"priority", "full", "off"}
NESSUS_IANA_PORT_LIST = "All IANA assigned TCP"
SCAN_CONFIGS = {"Full and fast", "Discovery", "Host Discovery", "System Discovery", "Base"}
ALIVE_TESTS = {
    "Scan Config Default", "ICMP Ping", "TCP-ACK Service Ping", "TCP-SYN Service Ping",
    "ARP Ping", "ICMP & TCP-ACK Service Ping", "ICMP & ARP Ping",
    "TCP-ACK Service & ARP Ping", "ICMP, TCP-ACK Service & ARP Ping", "Consider Alive",
}
CREDENTIAL_KINDS = {"ssh", "smb", "snmp", "esxi"}
_FAMILY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 :._/&()+,-]{0,79}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_YES_NO = {"yes": "yes", "no": "no", "true": "yes", "false": "no", "1": "yes", "0": "no", "on": "yes", "off": "no"}
SNAPSHOT_FIELDS = {
    "ssh_credential_port",
    "policy_version",
    "port_profile",
    "udp_profile",
    "port_range",
    "requested_port_range",
    "tcp_port_count",
    "udp_port_count",
    "service_count",
    "udp_baseline",
    "udp_extensions",
    "custom_tcp_ports",
    "custom_udp_ports",
    "gmp_credential_refs",
    "credential_status",
    "targets",
    "task_id",
    "config_id",
    "scanner_id",
    "scan_config_name",
    "preferences",
    "preference_status",
    "nvt_count",
    "started_at",
    "snapshot_status",
    "reason",
    "feed_versions",
    "configuration_sha256",
    "network_scoped_methods",
    "rule_engine",
    "template",
    "template_name",
    "alive_test",
    "safe_checks",
    "optimize_test",
    "require_credentials",
    "require_credentials_mode",
    "nvt_families",
    "family_scope_status",
    "cve_watchlist",
    "port_list_name",
    "port_list_status",
    "performance",
    "performance_status",
    "nvt_timeout_caps",
    "check_scope",
    "check_scope_status",
    # V1.9.1: what the task's config really runs (total checks, partial families).
    "check_selection",
    "scan_purpose",
    "nvt_filter",
    "require_families",
    "disabled_services",
    "service_port_policy_version",
    "scan_addresses",
    "self_scan",
    # V1.9.0: laptop-local credential provisioning (kind names + status only; no
    # secret ever enters a snapshot).
    "auto_provisioned_credentials",
    "local_credential_status",
}
SCAN_PURPOSES = {"vulnerability", "ping_discovery", "credential_validation", "compliance"}
_NAME_FILTER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()+-]{0,59}$")
PERFORMANCE_PROFILES = {"standard", "fast", "turbo"}
CHECK_SCOPES = {"vulnerability", "all", "severity"}
PREFERENCE_FIELDS = {
    "max_checks",
    "max_hosts",
    "checks_read_timeout",
    "timeout_retry",
    "open_sock_max_attempts",
    "optimize_test",
    "safe_checks",
    "plugins_timeout",
    "scanner_plugins_timeout",
    "expand_vhosts",
    "test_empty_vhost",
    "report_host_details",
}


def clip_policy_snapshots(raw: Any, targets: list[str]) -> dict[str, Any]:
    """Keep only small, source-task policies whose entire host list is assigned."""
    import ipaddress

    def canonical(host: Any) -> str:
        try:
            return str(ipaddress.ip_address(str(host).strip()))
        except ValueError:
            return str(host).strip().lower()

    allowed = {canonical(h) for h in targets}
    out = {}
    if not isinstance(raw, dict):
        return out
    for task_id, policy in list(raw.items())[:4096]:
        if not isinstance(policy, dict) or len(str(task_id)) > 128:
            continue
        hosts = policy.get("targets")
        if (
            not isinstance(hosts, list)
            or not hosts
            or not {canonical(h) for h in hosts} <= allowed
        ):
            continue
        item = {k: v for k, v in policy.items() if k in SNAPSHOT_FIELDS}
        item["task_id"] = str(task_id)
        for key in ("gmp_credential_refs", "credential_status"):
            item[key] = (
                {
                    k: str(v)[:200]
                    for k, v in (item.get(key) or {}).items()
                    if k in {"ssh", "smb", "snmp", "esxi"}
                }
                if isinstance(item.get(key), dict)
                else {}
            )
        item["preferences"] = (
            {
                k: str(v)[:100]
                for k, v in (item.get("preferences") or {}).items()
                if k in PREFERENCE_FIELDS
            }
            if isinstance(item.get("preferences"), dict)
            else {}
        )
        item["feed_versions"] = (
            {
                str(k)[:40]: str(v)[:100]
                for k, v in list((item.get("feed_versions") or {}).items())[:12]
            }
            if isinstance(item.get("feed_versions"), dict)
            else {}
        )
        try:
            encoded = json.dumps(item, allow_nan=False)
        except (TypeError, ValueError):
            continue
        if len(encoded) <= 32000:
            out[str(task_id)] = item
    return out


@lru_cache(maxsize=1)
def service_catalog() -> dict[str, Any]:
    doc = json.loads(CATALOG_PATH.read_text())
    if len(doc["services"]) != 52 or [s["id"] for s in doc["services"]] != list(
        range(1, 53)
    ):
        raise ValueError("Invalid 52-service catalog")
    return doc


@lru_cache(maxsize=1)
def service_port_policy() -> dict[str, Any]:
    """The services/ports Aetheris checks (V1.7.0). Single source for the nexus scope."""
    doc = json.loads(SERVICE_PORT_POLICY_PATH.read_text(encoding="utf-8"))
    keys = [s["key"] for s in doc["services"]]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate service key in service_port_policy.json")
    families = {s["key"] for s in service_catalog()["services"]}
    for svc in doc["services"]:
        for port in list(svc["tcp"]) + list(svc["udp"]):
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError(f"Invalid port {port!r} for {svc['key']}")
        if svc.get("catalog_family") and svc["catalog_family"] not in families:
            raise ValueError(f"Unknown catalog family {svc['catalog_family']} for {svc['key']}")
    return doc


def policy_ports(disabled: list[str] | None = None) -> tuple[list[int], list[int]]:
    """TCP and UDP ports of every enabled policy service."""
    off = set(disabled or [])
    tcp: set[int] = set()
    udp: set[int] = set()
    for svc in service_port_policy()["services"]:
        if svc["key"] in off or not svc.get("enabled_by_default", True):
            continue
        tcp.update(svc["tcp"])
        udp.update(svc["udp"])
    return sorted(tcp), sorted(udp)


def port_numbers(value: Any) -> list[int]:
    if value is None or value == "":
        return []
    tokens = value if isinstance(value, list) else str(value).split(",")
    ports: set[int] = set()
    for raw in tokens:
        if isinstance(raw, bool):
            raise ValueError("Boolean is not a port")
        token = str(raw).strip()
        if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", token):
            raise ValueError("Port must be a number or ascending range")
        parts = token.split("-")
        lo = int(parts[0])
        hi = int(parts[-1])
        if not 1 <= lo <= hi <= 65535:
            raise ValueError("Port outside 1-65535 or reversed range")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


@lru_cache(maxsize=1)
def scan_templates() -> dict[str, Any]:
    """Nessus-equivalent scan templates (single source for agent and central)."""
    doc = json.loads(TEMPLATES_PATH.read_text(encoding="utf-8"))
    keys = [t["key"] for t in doc["templates"]]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate scan template key")
    for template in doc["templates"]:
        _validate_fields(dict(template["settings"]))  # fail loudly on a bad shipped template
    defaults = [t["key"] for t in doc["templates"] if t.get("default")]
    if len(defaults) > 1:
        raise ValueError(f"More than one default scan template: {defaults}")
    for key in defaults:
        if not next(t for t in doc["templates"] if t["key"] == key).get("seed_as_builtin"):
            raise ValueError(f"Default scan template {key} must be seeded as a built-in policy")
    return doc


DEFAULT_TEMPLATE_FALLBACK = "polaron"


def default_template_key() -> str:
    """The template preselected at launch (V1.10.2: the Polaron policy)."""
    for template in scan_templates()["templates"]:
        if template.get("default"):
            return str(template["key"])
    return DEFAULT_TEMPLATE_FALLBACK


def template_by_key(key: str) -> dict[str, Any]:
    for template in scan_templates()["templates"]:
        if template["key"] == key:
            return template
    raise ValueError(f"Unknown scan template: {key}")


def expand_template(settings: dict[str, Any] | None) -> dict[str, Any]:
    """Template defaults first, explicit policy settings override them."""
    raw = dict(settings or {})
    key = raw.get("template")
    if key in (None, ""):
        return raw
    template = template_by_key(str(key).strip())
    merged = dict(template["settings"])
    merged.update({k: v for k, v in raw.items() if k != "template"})
    merged["template"] = template["key"]
    merged["template_name"] = template["name"]
    return merged


def validate_request(settings: dict[str, Any] | None) -> dict[str, Any]:
    raw = settings or {}
    if not isinstance(raw, dict):
        raise ValueError("Scan settings must be an object")
    return _validate_fields(expand_template(raw))


def _validate_fields(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if raw.get("template") not in (None, ""):
        out["template"] = str(raw["template"])[:64]
        out["template_name"] = str(raw.get("template_name") or raw["template"])[:120]
    if raw.get("scan_config") not in (None, ""):
        value = str(raw["scan_config"]).strip()
        if value not in SCAN_CONFIGS:
            raise ValueError(f"Unsupported scan_config; allowed: {sorted(SCAN_CONFIGS)}")
        out["scan_config"] = value
    if raw.get("alive_test") not in (None, ""):
        value = str(raw["alive_test"]).strip()
        if value not in ALIVE_TESTS:
            raise ValueError("Unsupported alive_test")
        out["alive_test"] = value
    if raw.get("performance") not in (None, ""):
        value = str(raw["performance"]).strip().lower()
        if value not in PERFORMANCE_PROFILES:
            raise ValueError("performance must be standard, fast or turbo")
        out["performance"] = value
    if raw.get("disabled_services") not in (None, []):
        keys = raw["disabled_services"]
        known = {s["key"] for s in service_port_policy()["services"]}
        if not isinstance(keys, list) or not set(map(str, keys)) <= known:
            raise ValueError("disabled_services must list keys from the service port policy")
        out["disabled_services"] = sorted(set(map(str, keys)))
    if raw.get("scan_purpose") not in (None, ""):
        value = str(raw["scan_purpose"]).strip().lower()
        if value not in SCAN_PURPOSES:
            raise ValueError(f"scan_purpose must be one of {sorted(SCAN_PURPOSES)}")
        out["scan_purpose"] = value
    if raw.get("require_families") is not None:
        out["require_families"] = bool(raw["require_families"])
    if raw.get("nvt_filter") not in (None, "", {}):
        out["nvt_filter"] = _validate_nvt_filter(raw["nvt_filter"])
    if raw.get("check_scope") not in (None, ""):
        value = str(raw["check_scope"]).strip().lower()
        if value not in CHECK_SCOPES:
            raise ValueError("check_scope must be vulnerability, all or severity")
        out["check_scope"] = value
    for key in ("safe_checks", "optimize_test"):
        if raw.get(key) is not None:
            value = _YES_NO.get(str(raw[key]).strip().lower())
            if value is None:
                raise ValueError(f"{key} must be yes or no")
            out[key] = value
    if raw.get("require_credentials") is not None:
        kinds = raw["require_credentials"]
        if not isinstance(kinds, list) or not set(map(str, kinds)) <= CREDENTIAL_KINDS:
            raise ValueError("require_credentials must be a list of ssh/smb/snmp/esxi")
        out["require_credentials"] = sorted(set(map(str, kinds)))
        mode = str(raw.get("require_credentials_mode") or "any").lower()
        if mode not in {"any", "all"}:
            raise ValueError("require_credentials_mode must be any or all")
        out["require_credentials_mode"] = mode
    if raw.get("nvt_families") is not None:
        fams = raw["nvt_families"]
        if not isinstance(fams, list) or len(fams) > 64 or not all(
            isinstance(f, str) and _FAMILY_RE.match(f) for f in fams
        ):
            raise ValueError("nvt_families must be up to 64 Greenbone family names")
        out["nvt_families"] = sorted(set(fams))
    if raw.get("cve_watchlist") is not None:
        cves = raw["cve_watchlist"]
        if not isinstance(cves, list) or len(cves) > 200:
            raise ValueError("cve_watchlist must be a list of up to 200 CVE identifiers")
        norm = sorted({str(c).strip().upper() for c in cves})
        if not all(_CVE_RE.match(c) for c in norm):
            raise ValueError("cve_watchlist entries must look like CVE-YYYY-NNNN")
        out["cve_watchlist"] = norm
    for key, allowed in (("port_profile", MODES), ("udp_profile", UDP_MODES)):
        value = raw.get(key, raw.get("mode") if key == "port_profile" else None)
        if value is not None:
            value = str(value).strip().lower()
            if value not in allowed:
                raise ValueError(f"Invalid {key}")
            out[key] = value
    for key in ("custom_tcp_ports", "custom_udp_ports"):
        if raw.get(key) is not None:
            out[key] = port_numbers(raw[key])
            if len(out[key]) > 4096:
                raise ValueError(
                    "Custom scope exceeds 4096 ports; use the Full profile for an exhaustive scan"
                )
    if raw.get("ssh_credential_port") is not None:
        ports = port_numbers(raw["ssh_credential_port"])
        if len(ports) != 1:
            raise ValueError("SSH credential port must be a single port")
        out["ssh_credential_port"] = ports[0]
    refs = raw.get("gmp_credential_refs")
    if refs is not None:
        if not isinstance(refs, dict):
            raise ValueError("GMP credential references must be an object")
        out["gmp_credential_refs"] = {}
        for kind, value in refs.items():
            if kind not in {"ssh", "smb", "snmp", "esxi"}:
                raise ValueError("Unsupported GMP credential kind")
            out["gmp_credential_refs"][kind] = str(UUID(str(value)))
    if out.get("port_profile") == "focused" and not (out.get("custom_tcp_ports") or out.get("custom_udp_ports")):
        raise ValueError("The focused port profile requires custom_tcp_ports or custom_udp_ports")
    # No passwords, account tokens, URLs or arbitrary scanner preferences cross this contract.
    return out


def _validate_nvt_filter(value: Any) -> dict[str, Any]:
    """Structured Advanced Dynamic filter. Never a raw gvmd filter string.

    min_severity  0.1-10.0: run checks whose severity is at least this
    name_contains short plain text the check name must contain
    families      optional list of Greenbone family names to restrict to
    """
    if not isinstance(value, dict):
        raise ValueError("nvt_filter must be an object")
    unknown = set(value) - {"min_severity", "name_contains", "families"}
    if unknown:
        raise ValueError(f"Unsupported nvt_filter keys: {sorted(unknown)}")
    out: dict[str, Any] = {}
    if value.get("min_severity") not in (None, ""):
        try:
            sev = round(float(value["min_severity"]), 1)
        except (TypeError, ValueError):
            raise ValueError("nvt_filter.min_severity must be a number") from None
        if not 0.1 <= sev <= 10.0:
            raise ValueError("nvt_filter.min_severity must be between 0.1 and 10.0")
        out["min_severity"] = sev
    if value.get("name_contains") not in (None, ""):
        text = str(value["name_contains"]).strip()
        if not _NAME_FILTER_RE.match(text):
            raise ValueError("nvt_filter.name_contains may use letters, digits, spaces and . _ : / ( ) + - only")
        out["name_contains"] = text
    if value.get("families") not in (None, [], ""):
        fams = value["families"]
        if not isinstance(fams, list) or len(fams) > 64 or not all(
            isinstance(f, str) and _FAMILY_RE.match(f) for f in fams
        ):
            raise ValueError("nvt_filter.families must be up to 64 Greenbone family names")
        out["families"] = sorted(set(fams))
    if not out:
        raise ValueError("nvt_filter needs min_severity, name_contains or families")
    return out


def credential_gap(request: dict[str, Any]) -> str | None:
    """Return a human-readable reason when a template's credential requirement is unmet."""
    need = list(request.get("require_credentials") or [])
    if not need:
        return None
    have = set((request.get("gmp_credential_refs") or {}).keys())
    mode = request.get("require_credentials_mode") or "any"
    ok = bool(have & set(need)) if mode == "any" else set(need) <= have
    if ok:
        return None
    sep = " or " if mode == "any" else " and "
    joined = sep.join(k.upper() for k in need)
    name = request.get("template_name") or request.get("template") or "This policy"
    return f"{name} needs a credential reference for {joined} on the scanner (gmp_credential_refs)"


def format_ports(ports: list[int], transport: str) -> str:
    values = sorted(set(ports))
    groups = []
    for port in values:
        if groups and port == groups[-1][1] + 1:
            groups[-1][1] = port
        else:
            groups.append([port, port])
    return ",".join(
        f"{transport}:{a}" if a == b else f"{transport}:{a}-{b}" for a, b in groups
    )


def effective_policy(
    request: dict[str, Any] | None = None,
    *,
    port_profile: str | None = None,
    udp_profile: str | None = None,
    catalog_tcp: list[int] | None = None,
    catalog_udp: list[int] | None = None,
) -> dict[str, Any]:
    doc = service_catalog()
    req = validate_request(request)
    mode = req.get(
        "port_profile", port_profile or os.environ.get("PORT_PROFILE") or "full"
    )
    mode = str(mode).strip().lower()
    if mode not in MODES:
        raise ValueError("Invalid effective PORT_PROFILE")
    udp = req.get(
        "udp_profile", udp_profile or os.environ.get("UDP_PROFILE") or "priority"
    )
    udp = str(udp).strip().lower()
    udp = (
        "off"
        if udp in {"none", "disabled", "false", "0"}
        else "full"
        if udp in {"all", "1-65535"}
        else udp
    )
    if udp not in UDP_MODES:
        raise ValueError("Invalid effective UDP_PROFILE")
    baseline_tcp = sorted({p for s in doc["services"] for p in s["tcp_hints"]})
    extra_tcp = (
        req["custom_tcp_ports"]
        if "custom_tcp_ports" in req
        else port_numbers(os.environ.get("SCAN_TCP_CUSTOM_PORTS"))
    )
    extra_udp = (
        req["custom_udp_ports"]
        if "custom_udp_ports" in req
        else port_numbers(os.environ.get("SCAN_UDP_CUSTOM_PORTS"))
    )
    # Legacy UDP_PORT_RANGE adds ports; it must not erase the agreed baseline.
    legacy_udp = (
        str(os.environ.get("UDP_PORT_RANGE") or "").replace("U:", "").replace("u:", "")
    )
    extra_udp = sorted(set(extra_udp + port_numbers(legacy_udp)))
    policy_mode = mode in POLICY_PORT_MODES
    if policy_mode:
        # V1.7.0: the service port policy is the whole scope. Only explicit extras
        # (SCAN_*_CUSTOM_PORTS, SERVICE_EXTRA_*_PORTS, policy custom ports) are added;
        # the legacy UDP_PORT_RANGE default list is ignored here.
        pol_tcp, pol_udp = policy_ports(req.get("disabled_services"))
        env_tcp = port_numbers(os.environ.get("SERVICE_EXTRA_TCP_PORTS"))
        env_udp = port_numbers(os.environ.get("SERVICE_EXTRA_UDP_PORTS"))
        explicit_udp = (
            req["custom_udp_ports"] if "custom_udp_ports" in req
            else port_numbers(os.environ.get("SCAN_UDP_CUSTOM_PORTS"))
        )
        extra_udp = sorted(set(explicit_udp) | set(env_udp))
    if mode == "full":
        tcp = list(range(1, 65536))
    elif policy_mode:
        tcp = sorted(set(pol_tcp) | set(extra_tcp) | set(env_tcp))
    elif mode == "focused":
        # Threat templates: only the explicitly listed ports, nothing implied.
        tcp = sorted(set(req.get("custom_tcp_ports") or []))
    elif mode in NESSUS_MODES:
        # Static floor; LocalOpenVAS widens this with the Greenbone
        # "All IANA assigned TCP" port list when it is available.
        tcp = sorted(set(range(1, 1025)) | set(baseline_tcp) | set(catalog_tcp or []) | set(extra_tcp))
    else:
        tcp = sorted(set(baseline_tcp + (catalog_tcp or []) + extra_tcp))
    if udp == "full":
        udp_ports = list(range(1, 65536))
    elif udp == "off":
        udp_ports = []
    elif mode == "focused":
        udp_ports = sorted(set(req.get("custom_udp_ports") or []))
    elif policy_mode:
        udp_ports = sorted(set(pol_udp) | set(extra_udp))
    else:
        udp_ports = sorted(
            set(
                doc["udp_baseline"]
                + doc["udp_extensions"]
                + (catalog_udp or [])
                + extra_udp
            )
        )
    spec = ",".join(
        s for s in (format_ports(tcp, "T"), format_ports(udp_ports, "U")) if s
    )
    policy = {
        "policy_version": doc["policy_version"],
        "port_profile": mode,
        "udp_profile": udp,
        "port_range": spec,
        "tcp_port_count": len(tcp),
        "udp_port_count": len(udp_ports),
        "service_count": 52,
        "udp_baseline": doc["udp_baseline"],
        "udp_extensions": doc["udp_extensions"],
        "custom_tcp_ports": extra_tcp,
        "custom_udp_ports": extra_udp,
        "gmp_credential_refs": req.get("gmp_credential_refs", {}),
        "ssh_credential_port": req.get("ssh_credential_port", 22),
        "network_scoped_methods": "DHCP/SSDP/mDNS are not implemented as a standalone network collector",
        "rule_engine": "OpenVAS native feed; per-rule success requires report evidence",
    }
    for key in (
        "template", "template_name", "scan_config", "alive_test", "safe_checks", "optimize_test", "performance",
        "check_scope", "scan_purpose", "nvt_filter", "require_families", "disabled_services",
        "require_credentials", "require_credentials_mode", "nvt_families", "cve_watchlist",
    ):
        if key in req:
            policy[key] = req[key]
    if policy_mode:
        policy["service_port_policy_version"] = service_port_policy()["policy_version"]
    if mode in NESSUS_MODES:
        policy["port_list_name"] = NESSUS_IANA_PORT_LIST
        policy["port_list_status"] = "static floor (TCP 1-1024 + catalog) until widened by the scanner"
    policy["configuration_sha256"] = hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return policy


def matches_service(service: dict[str, Any], endpoint: dict[str, Any]) -> bool:
    """Match explicit protocol/product context; a port number alone never routes a product."""
    protocol = (
        str(endpoint.get("service") or endpoint.get("detected_protocol") or "")
        .strip()
        .lower()
    )
    product = " ".join(str(endpoint.get(k) or "") for k in ("product", "cpe")).lower()
    return protocol in service["protocols"] or any(
        p in product for p in service["product_patterns"]
    )


def evaluate_ip_forwarding(
    evidence: dict[str, Any] | None, *, expected_forwarding: bool | None = None
) -> dict[str, Any]:
    """Evaluate supplied/native authenticated configuration; this function does not collect it."""
    base = {"rule_id": "CFG-IP-FORWARDING", "rule_version": "1", "status": "not-tested"}
    if not evidence or not evidence.get("source_ref"):
        return {**base, "reason": "No source-backed IPv4/IPv6 configuration evidence"}
    values = [evidence.get("ipv4"), evidence.get("ipv6")]
    if any(type(v) not in (int, bool) or v not in (0, 1) for v in values):
        return {**base, "reason": "Both IPv4 and IPv6 forwarding states are required"}
    if not evidence.get("authenticated"):
        return {**base, "reason": "Authenticated host configuration is not established"}
    if not isinstance(expected_forwarding, bool):
        return {
            **base,
            "reason": "Device-role forwarding policy is unknown",
            "source_ref": evidence["source_ref"],
        }
    enabled = any(bool(v) for v in values)
    unexpected = enabled and expected_forwarding is False
    return {
        **base,
        "status": "finding" if unexpected else "passed",
        "forwarding_enabled": enabled,
        "expected_forwarding": expected_forwarding,
        "source_ref": evidence["source_ref"],
        "reason": "Unexpected forwarding against supplied device-role policy"
        if unexpected
        else "Observed forwarding is permitted by supplied role policy",
    }


# ---------------------------------------------------------------------------
# V1.6.5 evidence attribution
# ---------------------------------------------------------------------------
# Extra title rules for wording used by OpenVAS NVT names. Product patterns from
# the catalog are matched with word boundaries as well (so "httpd" no longer
# matches "lighttpd" and "ftp" no longer matches "tftp"/"sftp").
_TITLE_RULES: dict[str, list[str]] = {
    "SVC-01": [r"\bsmb(?:v?\d)?\b", r"\bcifs\b", r"\bnetbios\b", r"\bsamba\b", r"\blanman\b",
               r"\bms17-010\b", r"\beternalblue\b"],
    "SVC-02": [r"\bdce/?rpc\b", r"\bmsrpc\b", r"\bms-rpc\b", r"\bmicrosoft (?:windows )?rpc\b",
               r"\bendpoint mapper\b", r"\bepmap\b"],
    "SVC-04": [r"\bws-?management\b", r"\bwsman\b"],
    "SVC-05": [r"\bms-wbt\b", r"\bterminal services?\b", r"\bcredssp\b"],
    "SVC-06": [r"\bssh\b"],
    "SVC-09": [r"\bhttp\b", r"\bweb ?server\b", r"\bwebdav\b", r"\bweb application\b"],
    "SVC-10": [r"\bhttps\b", r"\bssl/tls\b", r"\bheartbleed\b", r"\bpoodle\b", r"\bciphers?\b",
               r"\bcertificates?\b"],
    "SVC-14": [r"\bdns\b"],
    "SVC-20": [r"\bkerberos\b"],
    "SVC-47": [r"\bntp\b", r"\bnetwork time\b"],
}

# Protocol owner of a well-known port. Used ONLY for results that GMP actually
# reported on that port; it never creates a service from a catalog hint, and it
# never routes product families (Tomcat/IIS/Jenkins share ports and need
# product evidence).
_PORT_OWNERS: dict[tuple[int, str], str] = {}
for _svc, _tcp, _udp in (
    ("SVC-01", (139, 445), (137, 138)), ("SVC-02", (135,), ()), ("SVC-04", (5985, 5986), ()),
    ("SVC-05", (3389,), (3389,)), ("SVC-06", (22,), ()), ("SVC-07", (20, 21, 990), ()),
    ("SVC-09", (80, 8000, 8080), ()), ("SVC-10", (443, 8443), ()), ("SVC-11", (25, 465, 587), ()),
    ("SVC-12", (110, 995), ()), ("SVC-13", (143, 993), ()), ("SVC-14", (53,), (53,)),
    ("SVC-15", (), (161, 162)), ("SVC-16", (23,), ()), ("SVC-17", (), (69,)),
    ("SVC-18", (389,), (389,)), ("SVC-19", (636,), ()), ("SVC-20", (88,), (88,)),
    ("SVC-21", (3268, 3269), ()), ("SVC-22", (1433,), (1434,)), ("SVC-23", (3306,), ()),
    ("SVC-24", (5432,), ()), ("SVC-25", (1521,), ()), ("SVC-26", (27017,), ()),
    ("SVC-27", (6379,), ()), ("SVC-28", (9200, 9300), ()), ("SVC-29", tuple(range(5900, 5910)), ()),
    ("SVC-30", (902,), (902,)), ("SVC-31", (2375, 2376), ()), ("SVC-32", (6443,), ()),
    ("SVC-33", (10250,), ()), ("SVC-35", (9418,), ()), ("SVC-36", (5672, 15672), ()),
    ("SVC-37", (9092,), ()), ("SVC-38", (11211,), (11211,)), ("SVC-40", (9990,), ()),
    ("SVC-44", (7001, 7002), ()), ("SVC-46", (), (500, 4500)), ("SVC-47", (), (123,)),
    ("SVC-48", (), (67, 68)), ("SVC-49", (631,), ()), ("SVC-50", (9100,), ()),
    ("SVC-51", (2049,), (2049,)), ("SVC-52", (111,), (111,)),
):
    for _p in _tcp:
        _PORT_OWNERS[(_p, "tcp")] = _svc
    for _p in _udp:
        _PORT_OWNERS[(_p, "udp")] = _svc

# Services whose checks need Windows/host credentials in Greenbone and Nessus.
_CREDENTIAL_ONLY = {"SVC-03": "WMI checks run only with Windows (SMB) credentials"}
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info", "Unscored")
STATUSES = ("finding", "observation", "not-tested", "closed", "filtered", "not-observed", "not-in-scope",
            "unsupported")
LOW_PLUS = ("Critical", "High", "Medium", "Low")


@lru_cache(maxsize=1)
def _title_regexes() -> dict[str, re.Pattern[str]]:
    out: dict[str, re.Pattern[str]] = {}
    for svc in service_catalog()["services"]:
        parts = [r"(?<![a-z0-9])" + re.escape(p.lower()) + r"(?![a-z])" for p in svc["product_patterns"]]
        parts += _TITLE_RULES.get(svc["key"], [])
        if parts:
            out[svc["key"]] = re.compile("|".join(f"(?:{x})" for x in parts), re.I)
    return out


def _row_severity(row: dict[str, Any]) -> str:
    raw = str(row.get("severity") or "").strip().lower()
    aliases = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
               "low": "Low", "info": "Info", "informational": "Info", "log": "Info", "none": "Info"}
    if raw in aliases:
        return aliases[raw]
    try:
        score = float(row.get("cvss", row.get("score")))
    except (TypeError, ValueError):
        return "Unscored"
    if not math.isfinite(score):
        return "Unscored"
    return ("Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4
            else "Low" if score > 0 else "Info")


def _row_score(row: dict[str, Any]) -> float:
    try:
        score = float(row.get("cvss", row.get("score", 0)) or 0)
    except (TypeError, ValueError):
        return 0.0
    return score if math.isfinite(score) else 0.0


def _row_rid(row: dict[str, Any]) -> str:
    return str(row.get("source_result_id") or row.get("result_id") or row.get("plugin_id") or "")


def _row_endpoint(row: dict[str, Any]) -> tuple[int, str] | None:
    port = row.get("port")
    transport = str(row.get("protocol") or "").lower()
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None
    if transport not in {"tcp", "udp"}:
        return None
    return port, transport


def attribute_row(row: dict[str, Any]) -> tuple[set[str], str]:
    """Return (catalog service keys, method) for one native result row."""
    keys: set[str] = set()
    title = str(row.get("plugin_name") or "")
    regexes = _title_regexes()
    for svc in service_catalog()["services"]:
        if matches_service(svc, row):
            keys.add(svc["key"])
            continue
        rx = regexes.get(svc["key"])
        if rx is not None and rx.search(title):
            keys.add(svc["key"])
    method = "title_or_protocol" if keys else ""
    endpoint = _row_endpoint(row)
    owner = _PORT_OWNERS.get(endpoint) if endpoint else None
    if owner:
        if owner not in keys:
            method = f"{method}+port_owner" if method else "port_owner"
        keys.add(owner)
    return keys, method


def _scanned_ports(spec: Any) -> tuple[set[int], set[int]] | None:
    if not spec or not isinstance(spec, str):
        return None
    tcp: set[int] = set()
    udp: set[int] = set()
    current = "T"
    for token in spec.split(","):
        piece = token.strip()
        if len(piece) >= 2 and piece[1] == ":" and piece[0].upper() in {"T", "U"}:
            current = piece[0].upper()
            piece = piece[2:].strip()
        if not piece:
            continue
        try:
            (tcp if current == "T" else udp).update(port_numbers(piece))
        except ValueError:
            return None
    return tcp, udp


def _bucket(name: str, rows: list[dict[str, Any]], *, key: str) -> dict[str, Any]:
    counts = {sev: 0 for sev in _SEVERITIES}
    findings: list[str] = []
    ids: list[str] = []
    items: list[dict[str, Any]] = []
    for row in rows:
        sev = _row_severity(row)
        counts[sev] += 1
        rid = _row_rid(row)
        if rid:
            ids.append(rid)
            if _row_score(row) > 0:
                findings.append(rid)
        endpoint = _row_endpoint(row)
        items.append({
            "result_id": rid[:128],
            "title": str(row.get("plugin_name") or "")[:200],
            "port": f"{endpoint[0]}/{endpoint[1]}" if endpoint else str(row.get("port") or "general"),
            "severity": sev,
            "cvss": _row_score(row),
            "nvt_oid": str(row.get("nvt_oid") or row.get("plugin_id") or "")[:100],
        })
    order = {s: i for i, s in enumerate(_SEVERITIES)}
    items.sort(key=lambda x: (order.get(x["severity"], 9), -x["cvss"], x["title"]))
    return {
        "service_id": key,
        "name": name,
        "status": "finding" if findings else "observation" if rows else "none",
        "severity_counts": counts,
        "source_result_ids": sorted(set(ids)),
        "finding_result_ids": sorted(set(findings)),
        "results": items[:100],
        "ports": sorted({i["port"] for i in items if i["port"] and i["port"][0].isdigit()}),
    }


def analyze_services(
    vulnerabilities: list[dict[str, Any]],
    *,
    host: str,
    coverage: dict[str, Any] | None = None,
    scanned_port_range: str | None = None,
) -> dict[str, Any]:
    """Describe native engine evidence per service family.

    Lack of a finding is never a per-rule pass. ``not-observed`` means the
    network scan completed, the family's ports were inside the scanned range
    and no listener or native result for the family was seen: the service is
    absent from that scope, which is a scope statement, not a security pass.
    """
    doc = service_catalog()
    import ipaddress

    def canonical(value: Any) -> str:
        raw = str(value or "").strip().casefold()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw

    cov = coverage or {}
    rows = [r for r in vulnerabilities if canonical(r.get("host")) == canonical(host)]
    endpoints: dict[tuple[int, str], dict[str, Any]] = {}

    def endpoint_item(port: int, transport: str) -> dict[str, Any]:
        return endpoints.setdefault((port, transport), {
            "ip": host, "port": port, "transport": transport, "source_result_ids": [],
            "service": None, "product": None, "cpe": None, "version": None,
            "confidence": "port_hint_only",
        })

    for row in rows:
        endpoint = _row_endpoint(row)
        if not endpoint:
            continue
        item = endpoint_item(*endpoint)
        for field in ("service", "product", "cpe", "version"):
            if row.get(field):
                item[field] = str(row[field])[:1000]
        rid = _row_rid(row)
        if rid and rid not in item["source_result_ids"]:
            item["source_result_ids"].append(rid)
        if item["service"] or item["product"] or item["cpe"]:
            item["confidence"] = "native_engine_context"
        elif item["confidence"] == "port_hint_only":
            item["confidence"] = "native_result_on_port"
    for transport, keyname in (("tcp", "open_tcp_ports"), ("udp", "open_udp_ports")):
        for raw in cov.get(keyname) or []:
            try:
                port = int(raw)
            except (ValueError, TypeError):
                continue
            if 1 <= port <= 65535:
                endpoint_item(port, transport)

    attributed: dict[str, list[dict[str, Any]]] = {}
    methods: dict[str, set[str]] = {}
    host_level: list[dict[str, Any]] = []
    other_ports: list[dict[str, Any]] = []
    for row in rows:
        keys, method = attribute_row(row)
        if keys:
            for key in keys:
                attributed.setdefault(key, []).append(row)
                methods.setdefault(key, set()).add(method)
        elif _row_endpoint(row):
            other_ports.append(row)
        else:
            host_level.append(row)

    network_done = cov.get("network_scan_complete") is True
    scanned = _scanned_ports(scanned_port_range)
    tcp_states = {int(k): str(v) for k, v in ((cov.get("port_states") or {}).get("tcp") or {}).items()
                  if str(k).isdigit()}
    services = []
    for svc in doc["services"]:
        key = svc["key"]
        observed = [r for r in endpoints.values() if matches_service(svc, r)]
        port_hints = [
            r for r in endpoints.values()
            if (r["transport"] == "tcp" and r["port"] in svc["tcp_hints"])
            or (r["transport"] == "udp" and r["port"] in svc["udp_hints"])
        ]
        svc_rows = attributed.get(key, [])
        referenced = [rid for rid in (_row_rid(r) for r in svc_rows) if rid]
        findings = [rid for r in svc_rows if _row_score(r) > 0 for rid in [_row_rid(r)] if rid]
        counts = {sev: 0 for sev in _SEVERITIES}
        for r in svc_rows:
            counts[_row_severity(r)] += 1
        hints_in_scope = None
        if scanned is not None:
            hints_in_scope = (
                [p for p in svc["tcp_hints"] if p in scanned[0]]
                + [p for p in svc["udp_hints"] if p in scanned[1]]
            )
        if findings:
            status = "finding"
            reason = f"{len(findings)} scored native result(s); no independent per-check pass inferred"
        elif referenced or observed:
            status = "observation"
            reason = "Native report references (informational); no independent per-check pass inferred"
        elif svc["scope"] == "network":
            status = "unsupported"
            reason = "No DHCP network-scoped collector is implemented by the per-IP agent"
        elif svc["tcp_hints"] and all(p in tcp_states for p in svc["tcp_hints"]) and not any(
            tcp_states[p] == "open" for p in svc["tcp_hints"]
        ):
            # V1.7.0: the agent probed every TCP port of this family and none was open.
            closed = [p for p in svc["tcp_hints"] if tcp_states[p] == "closed"]
            filtered = [p for p in svc["tcp_hints"] if tcp_states[p] == "filtered"]
            status = "closed" if closed else "filtered"
            reason = (
                (f"TCP {', '.join(map(str, closed))} refused the connection (nothing listening)" if closed else "")
                + ("; " if closed and filtered else "")
                + (f"TCP {', '.join(map(str, filtered))} did not answer (firewall or host offline)" if filtered else "")
                + ("; UDP ports were not probed" if svc["udp_hints"] else "")
                + ". Not exposed, not a security pass"
            )
        elif port_hints:
            status = "not-tested"
            shared = sorted({f"{r['port']}/{r['transport']}" for r in port_hints})
            reason = (
                f"Port(s) {', '.join(shared)} open but no native result attributed to this family"
                + (f"; {_CREDENTIAL_ONLY[key]}" if key in _CREDENTIAL_ONLY else "")
            )
        elif network_done and hints_in_scope is not None and (svc["tcp_hints"] or svc["udp_hints"]) and not hints_in_scope:
            status = "not-in-scope"
            reason = "None of this family's default ports were in the scanned port range"
        elif network_done and hints_in_scope is not None:
            status = "not-observed"
            udp_only = not svc["tcp_hints"] and bool(svc["udp_hints"])
            reason = (
                "Network scan finished; default port(s) were in range and closed/filtered, and no open "
                "port was identified as this service"
                + ("; UDP silence can also mean filtered" if udp_only else "")
                + ". Absence in scope, not a security pass"
            )
        else:
            status = "not-tested"
            reason = (
                "No verified protocol/product or matching native check evidence in this report"
                + ("" if network_done else "; network scan not confirmed complete")
                + ("" if scanned is not None else "; scanned port range unknown")
            )
        services.append({
            "service_id": key,
            "name": svc["name"],
            "engine_family": svc["engine_family"],
            "status": status,
            "reason": reason,
            "endpoint_count": len(observed),
            "port_hint_count": len(port_hints),
            "port_hints": sorted({f"{row['port']}/{row['transport']}" for row in port_hints}),
            "source_result_ids": sorted(set(referenced)),
            "finding_result_ids": sorted(set(findings)),
            "severity_counts": counts,
            "attribution": sorted(m for m in methods.get(key, set()) if m),
            "credentialed_checks": "not-tested; authentication/privilege evidence is required",
        })
    totals = {state: sum(s["status"] == state for s in services) for state in STATUSES}
    policy_view = _policy_service_view(rows, cov, scanned, tcp_states, network_done)
    return {
        "policy_version": doc["policy_version"],
        "host": host,
        "services": services,
        "counts": totals,
        "host_level": _bucket("Host / OS / network stack (general)", host_level, key="HOST-GENERAL"),
        "other_ports": _bucket("Other open ports (outside the 52-family catalog)", other_ports, key="OTHER-PORTS"),
        "unattributed_results": 0,
        "policy_services": policy_view["services"],
        "policy_summary": policy_view["summary"],
        "endpoints": sorted(endpoints.values(), key=lambda x: (x["transport"], x["port"])),
        "ip_forwarding": evaluate_ip_forwarding(None),
        "network_scan_complete": network_done,
        "scanned_port_range_known": scanned is not None,
        "coverage_complete": False,
        "limitation": (
            "Per-service rule pass/credential/network coverage is not proven by an OpenVAS Done state. "
            "'not-observed' means absent from the scanned range, not secure"
        ),
    }


def _policy_service_view(
    rows: list[dict[str, Any]],
    cov: dict[str, Any],
    scanned: tuple[set[int], set[int]] | None,
    tcp_states: dict[int, str],
    network_done: bool,
) -> dict[str, Any]:
    """One row per service in the service port policy, with port states and Low+ findings."""
    open_tcp = {int(p) for p in (cov.get("open_tcp_ports") or []) if str(p).isdigit()}
    open_udp = {int(p) for p in (cov.get("open_udp_ports") or []) if str(p).isdigit()}
    findings: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for row in rows:
        endpoint = _row_endpoint(row)
        if endpoint and _row_severity(row) in LOW_PLUS:
            findings.setdefault(endpoint, []).append(row)
    services: list[dict[str, Any]] = []
    for svc in service_port_policy()["services"]:
        tcp = [p for p in svc["tcp"] if scanned is None or p in scanned[0]]
        udp = [p for p in svc["udp"] if scanned is None or p in scanned[1]]
        if not tcp and not udp:
            services.append({"key": svc["key"], "name": svc["name"], "category": svc["category"],
                             "state": "not-in-policy", "ports": [], "severity_counts": {}, "finding_result_ids": []})
            continue
        ports: list[dict[str, Any]] = []
        for p in tcp:
            state = "open" if p in open_tcp else tcp_states.get(p) or ("closed/filtered" if network_done else "unknown")
            ports.append({"port": f"{p}/tcp", "state": state})
        for p in udp:
            state = "open" if p in open_udp else ("no response" if network_done else "unknown")
            ports.append({"port": f"{p}/udp", "state": state})
        hits = [r for p in tcp for r in findings.get((p, "tcp"), [])] + \
               [r for p in udp for r in findings.get((p, "udp"), [])]
        counts = {sev: 0 for sev in LOW_PLUS}
        for r in hits:
            counts[_row_severity(r)] += 1
        states = {pt["state"] for pt in ports}
        if hits:
            state = "finding"
        elif "open" in states:
            state = "open"
        elif "closed" in states:
            state = "closed"
        elif states <= {"filtered"}:
            state = "filtered"
        elif network_done:
            state = "not-observed"
        else:
            state = "unknown"
        services.append({
            "key": svc["key"], "name": svc["name"], "category": svc["category"], "state": state,
            "ports": ports, "severity_counts": counts,
            "finding_result_ids": sorted({_row_rid(r) for r in hits if _row_rid(r)}),
        })
    summary = {st: sum(1 for x in services if x["state"] == st)
               for st in ("finding", "open", "closed", "filtered", "not-observed", "unknown", "not-in-policy")}
    summary["policy_version"] = service_port_policy()["policy_version"]
    return {"services": services, "summary": summary}


def mark_cve_watchlist(vulnerabilities: list[dict[str, Any]], watchlist: Any) -> dict[str, Any] | None:
    """Flag native results whose CVEs are on a threat template's watchlist."""
    if not isinstance(watchlist, list) or not watchlist:
        return None
    wanted = {str(c).strip().upper() for c in watchlist if str(c).strip()}
    hits = []
    for row in vulnerabilities:
        cves = {str(c).upper() for c in (row.get("cves") or []) if c}
        if row.get("cve"):
            cves.add(str(row["cve"]).upper())
        matched = sorted(cves & wanted)
        if matched:
            row["watchlist_cves"] = matched
            hits.append({
                "result_id": _row_rid(row)[:128], "host": row.get("host"),
                "port": row.get("port"), "protocol": row.get("protocol"),
                "title": str(row.get("plugin_name") or "")[:200], "cves": matched,
                "severity": _row_severity(row), "cvss": _row_score(row),
            })
    return {
        "cves": sorted(wanted),
        "hit_count": len(hits),
        "hits": hits[:200],
        "status": "hit" if hits else "no_hit_in_scanned_scope",
        "note": (
            "Watchlist CVE(s) reported by native NVTs" if hits else
            "No native result referenced a watchlist CVE within the scanned ports and credentials; "
            "this is not proof the host is unaffected"
        ),
    }
