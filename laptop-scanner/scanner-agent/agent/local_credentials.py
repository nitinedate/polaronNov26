"""Provision target credentials on the laptop so a policy can run *authenticated* (V1.9.0).

Why this exists
---------------
Before this, a scan could only *reference* a Greenbone credential by UUID
(``gmp_credential_refs``). Nothing created the credential, so an operator who
wanted a Nexpose Full audit *with credentials* (the way to surface missing-patch
High/Critical findings) had to open the Greenbone UI and create an SMB/SSH
credential by hand. The scan-details screen correctly said "Add an SMB
credential", but the scanner gave no way to do it.

This module lets the **laptop** hold the SMB/SSH login locally and have the agent
create (idempotently) the matching Greenbone credential, so a policy that asks
for credentials is honoured automatically.

Security contract
-----------------
* Passwords and private keys are read **only** from the laptop's own environment
  (or a local secrets file). They NEVER travel in the central -> agent policy
  JSON: ``service_policy._validate_fields`` already refuses any password/token
  field, and this module does not change that. Central asks for a *kind*
  (``require_credentials: ["smb"]``); the laptop supplies the secret.
* The gvmd credential is created with ``allow_insecure=True`` only so OpenVAS may
  attempt the SMB/NTLM auth it needs; the secret stays inside the local gvmd.
* Credentials are keyed by a stable name so repeated scans reuse one object
  instead of creating thousands. The name contains the login and a short hash of
  the secret, so rotating the password creates a new object rather than silently
  using a stale one.
* Secret values are never logged. Only the kind, login and credential UUID are.

Configuration (laptop ``.env`` or process environment)
-------------------------------------------------------
    SCAN_SMB_USERNAME / SCAN_SMB_PASSWORD        Windows SMB login
    SCAN_SMB_DOMAIN                               optional; folded into the login as DOMAIN\\user
    SCAN_SSH_USERNAME / SCAN_SSH_PASSWORD         Linux SSH login (password)
    SCAN_SSH_PRIVATE_KEY / SCAN_SSH_KEY_PASSPHRASE  Linux SSH login (key; overrides password)
    SCAN_CREDENTIALS_FILE                         optional JSON file with the same keys
    SCAN_AUTO_CREDENTIALS                         "on" (default) auto-binds configured
                                                  credentials even when the policy did
                                                  not explicitly list require_credentials;
                                                  "off" binds only what the policy asked for.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger("scanner_agent.credentials")

SUPPORTED_KINDS = ("smb", "ssh")
_NAME_PREFIX = "aetheris-auto"


def _secrets_file() -> dict[str, Any]:
    path = (os.environ.get("SCAN_CREDENTIALS_FILE") or "").strip()
    if not path:
        return {}
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return {}
    except Exception:
        log.warning("Could not read SCAN_CREDENTIALS_FILE=%s; ignoring", path, exc_info=True)
        return {}
    return raw if isinstance(raw, dict) else {}


def _value(file_data: dict[str, Any], env_key: str, *file_keys: str) -> str:
    """Environment wins over the file; both are treated as laptop-local secrets."""
    env_val = os.environ.get(env_key)
    if env_val is not None and str(env_val).strip():
        return str(env_val).strip()
    for key in file_keys or (env_key,):
        val = file_data.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def auto_bind_enabled() -> bool:
    raw = (os.environ.get("SCAN_AUTO_CREDENTIALS") or "on").strip().lower()
    return raw not in {"off", "0", "false", "no", "disabled"}


def configured_specs() -> dict[str, dict[str, Any]]:
    """Return the credential specs the laptop is configured to provide.

    Shape per kind: {"login", "password"?, "private_key"?, "key_phrase"?,
    "credential_type", "fingerprint"}. Never includes raw secrets in logs.
    """
    data = _secrets_file()
    specs: dict[str, dict[str, Any]] = {}

    smb_user = _value(data, "SCAN_SMB_USERNAME", "smb_username", "smb_user")
    smb_pass = _value(data, "SCAN_SMB_PASSWORD", "smb_password", "smb_pass")
    smb_domain = _value(data, "SCAN_SMB_DOMAIN", "smb_domain", "domain")
    if smb_user and smb_pass:
        login = f"{smb_domain}\\{smb_user}" if smb_domain and "\\" not in smb_user else smb_user
        specs["smb"] = {
            "credential_type": "up",  # USERNAME_PASSWORD
            "login": login,
            "password": smb_pass,
            "fingerprint": _fingerprint(login, smb_pass),
        }

    ssh_user = _value(data, "SCAN_SSH_USERNAME", "ssh_username", "ssh_user")
    ssh_key = _value(data, "SCAN_SSH_PRIVATE_KEY", "ssh_private_key", "private_key")
    ssh_phrase = _value(data, "SCAN_SSH_KEY_PASSPHRASE", "ssh_key_passphrase", "key_phrase")
    ssh_pass = _value(data, "SCAN_SSH_PASSWORD", "ssh_password", "ssh_pass")
    if ssh_user and ssh_key:
        specs["ssh"] = {
            "credential_type": "usk",  # USERNAME_SSH_KEY
            "login": ssh_user,
            "private_key": ssh_key,
            "key_phrase": ssh_phrase or None,
            "fingerprint": _fingerprint(ssh_user, ssh_key, ssh_phrase or ""),
        }
    elif ssh_user and ssh_pass:
        specs["ssh"] = {
            "credential_type": "up",  # USERNAME_PASSWORD
            "login": ssh_user,
            "password": ssh_pass,
            "fingerprint": _fingerprint(ssh_user, ssh_pass),
        }

    return specs


def available_kinds() -> list[str]:
    """Kinds the laptop can currently provide a credential for (no secrets touched)."""
    return sorted(configured_specs().keys())


def _fingerprint(*parts: str) -> str:
    h = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
    return h[:12]


def _credential_name(kind: str, spec: dict[str, Any]) -> str:
    # Stable per (kind, login, secret). Rotating the secret -> new name -> new object.
    login = str(spec.get("login") or "").strip()
    safe_login = "".join(ch if ch.isalnum() or ch in "._-\\@" else "_" for ch in login)[:60]
    return f"{_NAME_PREFIX}-{kind}-{safe_login}-{spec['fingerprint']}"


def _credential_type_enum(value: str):
    from gvm.protocols.gmp.requests.v225 import CredentialType

    mapping = {
        "up": CredentialType.USERNAME_PASSWORD,
        "usk": CredentialType.USERNAME_SSH_KEY,
    }
    return mapping.get(value, CredentialType.USERNAME_PASSWORD)


def _find_existing(gmp: Any, name: str) -> str | None:
    """Return the UUID of an existing credential with this exact name, if any."""
    try:
        resp = gmp.get_credentials(filter_string=f'name="{name}" rows=2')
    except Exception:
        try:
            resp = gmp.get_credentials()
        except Exception:
            return None
    try:
        for node in resp.xpath("credential"):
            if (node.findtext("name") or "").strip() == name and node.get("id"):
                return str(node.get("id"))
    except Exception:
        return None
    return None


def ensure_credential(gmp: Any, kind: str, spec: dict[str, Any]) -> str | None:
    """Create (idempotently) the gvmd credential for ``spec`` and return its UUID.

    Reuses an existing object with the same stable name. Never logs the secret.
    Returns None if gvmd rejects the credential; the caller then records the gap.
    """
    name = _credential_name(kind, spec)
    existing = _find_existing(gmp, name)
    if existing:
        log.info("Reusing local %s credential for login=%s (%s)", kind, spec.get("login"), existing)
        return existing

    kwargs: dict[str, Any] = {
        "name": name,
        "credential_type": _credential_type_enum(str(spec.get("credential_type") or "up")),
        "login": spec.get("login"),
        "comment": "Aetheris laptop auto-provisioned credential; secret held locally.",
        "allow_insecure": True,
    }
    if spec.get("password") is not None:
        kwargs["password"] = spec["password"]
    if spec.get("private_key") is not None:
        kwargs["private_key"] = spec["private_key"]
    if spec.get("key_phrase"):
        kwargs["key_phrase"] = spec["key_phrase"]

    try:
        resp = gmp.create_credential(**kwargs)
    except TypeError:
        # Older python-gvm without allow_insecure/comment kwargs.
        kwargs.pop("allow_insecure", None)
        kwargs.pop("comment", None)
        resp = gmp.create_credential(**kwargs)
    cid = ""
    try:
        cid = str(resp.get("id") or "").strip()
    except AttributeError:
        cid = ""
    if not cid:
        # Some transforms return an element; find the id attribute.
        try:
            cid = str(resp.xpath("string(@id)") or "").strip()
        except Exception:
            cid = ""
    if not cid:
        log.warning("gvmd did not return an id when creating the %s credential", kind)
        return _find_existing(gmp, name)
    log.info("Created local %s credential for login=%s (%s)", kind, spec.get("login"), cid)
    return cid


def resolve_refs(gmp: Any, *, requested_kinds: list[str] | None, existing_refs: dict[str, str]) -> dict[str, Any]:
    """Merge locally-provisioned credential UUIDs into the policy's credential refs.

    ``requested_kinds``   kinds the policy explicitly required (require_credentials).
    ``existing_refs``     refs already supplied by the policy (gmp_credential_refs);
                          these win and are never overwritten.

    When auto-bind is on, every *configured* kind is provisioned even if the
    policy did not list it, so a Nexpose Full audit uses SMB credentials the
    moment they are set on the laptop. When auto-bind is off, only the explicitly
    required kinds are provisioned.

    Returns {"refs": {kind: uuid}, "status": {kind: text}, "provisioned": [...]}.
    """
    specs = configured_specs()
    out_refs: dict[str, str] = dict(existing_refs or {})
    status: dict[str, str] = {}
    provisioned: list[str] = []

    want: set[str] = set(k for k in (requested_kinds or []) if k in SUPPORTED_KINDS)
    if auto_bind_enabled():
        want |= set(specs.keys())

    for kind in sorted(want):
        if kind in out_refs:
            status[kind] = "policy-supplied credential reference"
            continue
        spec = specs.get(kind)
        if not spec:
            status[kind] = f"not-configured; set SCAN_{kind.upper()}_USERNAME/PASSWORD on the laptop"
            continue
        try:
            cid = ensure_credential(gmp, kind, spec)
        except Exception as exc:
            status[kind] = f"not-provisioned; gvmd rejected the credential ({exc.__class__.__name__})"
            log.warning("Could not provision the %s credential", kind, exc_info=True)
            continue
        if cid:
            out_refs[kind] = cid
            provisioned.append(kind)
            status[kind] = f"auto-provisioned from laptop secret (login={spec.get('login')})"
        else:
            status[kind] = "not-provisioned; gvmd returned no credential id"

    return {"refs": out_refs, "status": status, "provisioned": sorted(provisioned)}
