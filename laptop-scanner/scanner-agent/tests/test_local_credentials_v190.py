"""V1.9.0 - laptop-local SMB/SSH credential provisioning and automatic binding.

A policy that asks for credentials (or the default auto-bind) now provisions the
Greenbone credential from a secret held *on the laptop* and binds it to the scan
target. Passwords never cross the central -> agent policy contract; they are read
from the laptop environment only.
"""
from __future__ import annotations

from contextlib import contextmanager

import pytest
from lxml import etree

from agent import gmp_local as mod
from agent import local_credentials as lc

SMB_ENV = {"SCAN_SMB_USERNAME": "svc_scan", "SCAN_SMB_PASSWORD": "Sekret!23"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("SCAN_SMB_USERNAME", "SCAN_SMB_PASSWORD", "SCAN_SMB_DOMAIN",
                "SCAN_SSH_USERNAME", "SCAN_SSH_PASSWORD", "SCAN_SSH_PRIVATE_KEY",
                "SCAN_SSH_KEY_PASSPHRASE", "SCAN_CREDENTIALS_FILE", "SCAN_AUTO_CREDENTIALS",
                "PORT_PROFILE", "UDP_PROFILE"):
        monkeypatch.delenv(key, raising=False)


class CredGmp:
    """Fake gvmd that records created credentials and bound targets."""

    def __init__(self, existing=None):
        self.existing = dict(existing or {})  # name -> id
        self.created: list[dict] = []
        self.targets: list[dict] = []
        self.tasks: list[dict] = []

    # --- credential API ---
    def get_credentials(self, **kwargs):
        rows = "".join(f'<credential id="{cid}"><name>{n}</name></credential>'
                       for n, cid in self.existing.items())
        return etree.fromstring(f"<r>{rows}</r>".encode())

    def create_credential(self, **kwargs):
        name = kwargs["name"]
        cid = f"cred-{len(self.created) + 1}"
        self.created.append(kwargs)
        self.existing[name] = cid
        return {"id": cid}

    def get_credential(self, cid):
        return etree.fromstring(f'<r><credential id="{cid}"/></r>'.encode())

    # --- scan-config / target / task API ---
    def get_scan_configs(self, **kwargs):
        return etree.fromstring(b"<r/>")

    def clone_scan_config(self, cid):
        return {"id": f"clone-{cid}"}

    def modify_scan_config_set_name(self, *a, **k):
        pass

    def modify_scan_config_set_scanner_preference(self, *a, **k):
        pass

    def modify_scan_config_set_family_selection(self, *a, **k):
        pass

    def create_target(self, **kwargs):
        self.targets.append(kwargs)
        return {"id": "target-1"}

    def create_task(self, **kwargs):
        self.tasks.append(kwargs)
        return {"id": "task-1"}

    def start_task(self, task_id):
        return etree.fromstring(b"<r><report_id>rep-1</report_id></r>")

    def get_feeds(self):
        return etree.fromstring(b"<r/>")


def _launch(monkeypatch, policy, fake):
    monkeypatch.setattr(mod, "_ensure_portscan_config", lambda gmp, base: f"cfg-{base}")
    monkeypatch.setattr(mod, "_assert_feed_quality", lambda gmp, cid: {})
    monkeypatch.setattr(mod, "_find_scanner_id", lambda gmp: "scanner-1")
    monkeypatch.setattr(mod, "_named_port_list_tcp", lambda gmp, name: {5357})

    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setattr(mod, "_session", fake_session)
    scanner = mod.LocalOpenVAS()
    tid = scanner.start_scan(name="t", targets=["192.0.2.50"], scan_policy=policy)
    return scanner, scanner.policy_snapshots[tid]


# --- provider unit behaviour -----------------------------------------------------------

def test_no_credentials_configured_means_nothing_to_bind(monkeypatch):
    assert lc.available_kinds() == []
    g = CredGmp()
    res = lc.resolve_refs(g, requested_kinds=[], existing_refs={})
    assert res["refs"] == {} and res["provisioned"] == []
    assert g.created == []


def test_smb_secret_builds_a_username_password_credential(monkeypatch):
    for k, v in SMB_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SCAN_SMB_DOMAIN", "CORP")
    specs = lc.configured_specs()
    assert specs["smb"]["credential_type"] == "up"
    assert specs["smb"]["login"] == "CORP\\svc_scan"
    # The password is present in the spec but must never be logged; here we only
    # assert the provider does not strip it (it is needed to create the credential).
    assert specs["smb"]["password"] == "Sekret!23"


def test_secret_rotation_changes_the_stable_name(monkeypatch):
    for k, v in SMB_ENV.items():
        monkeypatch.setenv(k, v)
    name1 = lc._credential_name("smb", lc.configured_specs()["smb"])
    monkeypatch.setenv("SCAN_SMB_PASSWORD", "A-different-password")
    name2 = lc._credential_name("smb", lc.configured_specs()["smb"])
    assert name1 != name2  # rotating the secret must not reuse the old object


def test_existing_credential_is_reused_not_recreated(monkeypatch):
    for k, v in SMB_ENV.items():
        monkeypatch.setenv(k, v)
    spec = lc.configured_specs()["smb"]
    name = lc._credential_name("smb", spec)
    g = CredGmp(existing={name: "already-there"})
    res = lc.resolve_refs(g, requested_kinds=["smb"], existing_refs={})
    assert res["refs"]["smb"] == "already-there"
    assert g.created == []  # reused, not duplicated


# --- integration through start_scan ----------------------------------------------------

def test_nexpose_full_audit_auto_binds_smb_when_configured(monkeypatch):
    for k, v in SMB_ENV.items():
        monkeypatch.setenv(k, v)
    fake = CredGmp()
    _, snap = _launch(monkeypatch, {"template": "nx_full_audit"}, fake)
    # One credential created, bound to the target, recorded in the snapshot.
    assert len(fake.created) == 1
    assert fake.targets[0]["smb_credential_id"] == "cred-1"
    assert snap["auto_provisioned_credentials"] == ["smb"]
    assert snap["gmp_credential_refs"]["smb"] == "cred-1"
    assert snap["local_credential_status"]["smb"].startswith("auto-provisioned")
    # The snapshot must not leak the password anywhere.
    import json
    assert "Sekret!23" not in json.dumps(snap)


def test_no_credential_means_unauthenticated_scan_still_runs(monkeypatch):
    # No SMB secret on the laptop: the Full audit still runs, just unauthenticated.
    fake = CredGmp()
    _, snap = _launch(monkeypatch, {"template": "nx_full_audit"}, fake)
    assert fake.created == []
    assert "smb_credential_id" not in fake.targets[0]
    assert not snap.get("auto_provisioned_credentials")


def test_auto_bind_off_binds_only_explicitly_required_kinds(monkeypatch):
    for k, v in SMB_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SCAN_AUTO_CREDENTIALS", "off")
    fake = CredGmp()
    # nx_full_audit does not set require_credentials, so with auto-bind off it stays
    # unauthenticated even though an SMB secret is configured.
    _, snap = _launch(monkeypatch, {"template": "nx_full_audit"}, fake)
    assert fake.created == []
    assert "smb_credential_id" not in fake.targets[0]
    # But a policy that explicitly requires SMB still provisions it.
    fake2 = CredGmp()
    _, snap2 = _launch(monkeypatch,
                       {"template": "nx_full_audit", "require_credentials": ["smb"]}, fake2)
    assert fake2.targets[0]["smb_credential_id"] == "cred-1"
    assert snap2["auto_provisioned_credentials"] == ["smb"]


def test_credentials_file_is_accepted_as_a_local_source(monkeypatch, tmp_path):
    import json
    secrets = tmp_path / "creds.json"
    secrets.write_text(json.dumps({"smb_username": "file_user", "smb_password": "file_pass"}))
    monkeypatch.setenv("SCAN_CREDENTIALS_FILE", str(secrets))
    assert lc.available_kinds() == ["smb"]
    assert lc.configured_specs()["smb"]["login"] == "file_user"
