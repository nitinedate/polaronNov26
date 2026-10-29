"""V1.8.0: built-in Nexpose/Nessus policies, launch by template, warnings vs notes.

Unit tests run everywhere. The PostgreSQL tests run when AETHERIS_TEST_PG_URL
points at a scratch database (for example
postgresql+psycopg2://postgres@/aeth?host=/tmp&port=55432); otherwise they skip.
"""
from __future__ import annotations

import os
import types
import uuid

import pytest

from app.services.builtin_scan_policies import builtin_name, seedable_templates
from app.services.scan_orchestrator import scan_job_progress
from app.services.scanner_agent_jobs import classify_host_coverage
from app.services.scanner_service_policy import scan_templates

HOST = "172.20.10.2"


# --- which templates become ready-made policies ------------------------------------------------
def test_seeded_set_excludes_credentialed_and_unsafe_templates():
    keys = {t["key"] for t in seedable_templates()}
    assert {"nx_full_audit", "nx_exhaustive", "nx_discovery", "nx_internet_dmz_audit", "nx_web_audit",
            "nx_pci_asv_external", "nx_scada_audit", "basic_network", "threat_ms17_010"} <= keys
    # cannot launch without a credential, or can crash client systems
    assert not {"nx_microsoft_hotfix", "nx_linux_rpms", "nx_cis", "nx_disa", "credentialed_patch_audit",
                "policy_compliance", "nx_denial_of_service"} & keys
    for t in seedable_templates():
        assert not t["settings"].get("require_credentials") and t["settings"].get("safe_checks") != "no"


def test_every_nexpose_builtin_template_is_present():
    nexpose = {t["nexpose_template"] for t in scan_templates()["templates"] if t.get("vendor") == "nexpose"}
    # Rapid7 InsightVM built-in list, minus FDCC/USGCB (no Greenbone content; listed as not supported)
    assert {"Full audit", "Exhaustive", "Safe network audit", "Discovery scan", "Discovery scan (aggressive)",
            "Internet DMZ audit", "Web audit", "Penetration test", "Microsoft hotfix", "Linux RPMs",
            "PCI ASV external audit", "PCI internal audit", "HIPAA compliance",
            "Sarbanes-Oxley (SOX) compliance", "SCADA audit", "CIS", "DISA", "Denial of service"} == nexpose
    unsupported = {x["template"] for x in scan_templates()["not_supported"]}
    assert {"FDCC", "USGCB"} <= unsupported


def test_builtin_names_say_which_scanner_they_mirror():
    by_key = {t["key"]: t for t in scan_templates()["templates"]}
    assert builtin_name(by_key["nx_full_audit"]) == "Nexpose · Full audit"
    assert builtin_name(by_key["basic_network"]) == "Nessus · Basic Network Scan"
    assert builtin_name(by_key["threat_ms17_010"]).startswith("Threat check:")


def test_template_endpoint_exposes_vendor_fields():
    from app.routers import vuln

    os.environ.setdefault("VULN_MODULE_ENABLED", "true")
    out = {t["key"]: t for t in vuln.list_policy_templates(current=None)}
    assert out["nx_full_audit"]["vendor"] == "nexpose" and out["nx_full_audit"]["nexpose_template"] == "Full audit"
    assert out["nx_full_audit"]["nessus_template"] is None and out["nx_full_audit"]["reference"]
    assert out["basic_network"]["vendor"] == "nessus" and out["basic_network"]["seed_as_builtin"] is True
    assert out["nx_microsoft_hotfix"]["requires_credentials"] == ["smb"]


def test_policy_row_marks_builtin_and_missing_credentials():
    from app.routers.vuln import _policy_row

    row = _policy_row({"id": uuid.uuid4(), "name": "Nexpose · Microsoft hotfix", "policy_type": "vulnerability",
                       "settings_json": {"template": "nx_microsoft_hotfix"}, "is_builtin": False,
                       "lifecycle_state": "active"})
    assert row["vendor"] == "nexpose" and row["credentials_missing"] is True
    assert row["requires_credentials"] == ["smb"]
    ok = _policy_row({"id": uuid.uuid4(), "name": "x", "policy_type": "vulnerability", "is_builtin": True,
                      "settings_json": {"template": "nx_microsoft_hotfix",
                                        "gmp_credential_refs": {"smb": "11111111-2222-3333-4444-555555555555"}}})
    assert ok["credentials_missing"] is False and ok["is_builtin"] is True


# --- warnings are failures; notes are scope ----------------------------------------------------------
def _cov(**over):
    cov = {"verdict": "observed_unverified", "network_scan_complete": True, "open_tcp_ports": [135, 445],
           "warnings": [], "notes": []}
    cov.update(over)
    return cov


def test_finished_unauthenticated_host_is_completed_not_amber():
    tp, degraded, done = classify_host_coverage({HOST: _cov()}, {})
    assert degraded == [] and done == [HOST]
    assert tp[HOST]["activity"].startswith("Completed - network scan finished, 2 open TCP")
    assert "unauthenticated checks" in tp[HOST]["activity"]


def test_firewall_observation_is_a_note_and_self_scan_is_labelled():
    cov = _cov(notes=["No TCP port answered at all: a firewall dropped every probe"],
               self_scan={"scanned_via": "192.168.65.254", "view": "local",
                          "network_exposure": {"open": [], "filtered_count": 154, "closed_count": 0}})
    tp, _, _ = classify_host_coverage({HOST: cov}, {})
    row = tp[HOST]
    assert row["warnings"] == [] and row["notes"]
    assert "scanner laptop scanned through loopback (192.168.65.254)" in row["activity"]
    assert row["self_scan"]["network_exposure"]["filtered_count"] == 154


def test_job_label_is_complete_without_real_warnings():
    job = {"status": "completed", "orchestration_json": {
        "edge_agent": True, "degraded_hosts": [], "network_complete_hosts": [HOST], "completed_with_warnings": False}}
    assert scan_job_progress(None, job)["progress_label"].startswith("Complete")
    assert "warnings" not in scan_job_progress(None, job)["progress_label"]
    job["orchestration_json"]["completed_with_warnings"] = True
    label = scan_job_progress(None, job)["progress_label"]
    assert label.startswith("Complete") and "warnings" not in label  # V1.10.3


def test_assessment_notes_explain_unauthenticated_scope():
    from app.routers.vuln import _assessment_notes

    notes = _assessment_notes({"host_coverage": {HOST: {"notes": ["laptop firewall hides services"]}}},
                              is_edge=True, service_verified=False)
    assert notes[0].startswith("Unauthenticated scan") and f"{HOST}: laptop firewall hides services" in notes
    assert _assessment_notes({}, is_edge=True, service_verified=True) == []


# --- PostgreSQL: seeding, purge repair, launch by template --------------------------------------------
PG_URL = os.environ.get("AETHERIS_TEST_PG_URL")
pg = pytest.mark.skipif(not PG_URL, reason="AETHERIS_TEST_PG_URL not set")


@pytest.fixture()
def pg_db():
    from sqlalchemy import create_engine, event, text
    from sqlalchemy.orm import sessionmaker

    schema = f"firm_t{uuid.uuid4().hex[:10]}"
    engine = create_engine(PG_URL)
    with engine.begin() as conn:
        conn.exec_driver_sql(f"CREATE SCHEMA {schema}")
        conn.exec_driver_sql(f"""CREATE TABLE {schema}.vuln_scan_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), case_id UUID, name TEXT NOT NULL,
            policy_type TEXT NOT NULL DEFAULT 'basic_network', scanner_id UUID, settings_json JSONB,
            compliance_framework TEXT, lifecycle_state TEXT NOT NULL DEFAULT 'draft', created_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    db = sessionmaker(bind=engine)()

    @event.listens_for(db, "after_begin")
    def _search_path(session, tx, conn):
        conn.exec_driver_sql(f"SET search_path TO {schema}, public")

    yield db, text
    db.close()
    with engine.begin() as conn:
        conn.exec_driver_sql(f"DROP SCHEMA {schema} CASCADE")


@pg
def test_pg_seed_is_idempotent_and_repairs_a_purge(pg_db):
    from app.services import builtin_scan_policies as b

    db, text = pg_db
    expected = len(seedable_templates())
    assert b.ensure_builtin_policies(db) == expected  # upgrades the old table, then seeds
    assert b.ensure_builtin_policies(db) == 0  # nothing to do
    assert db.execute(text("SELECT COUNT(*) FROM vuln_scan_policies")).scalar() == expected
    db.execute(text("DELETE FROM vuln_scan_policies"))  # scripts/_purge_all_jobs.sql
    db.commit()
    assert b.ensure_builtin_policies(db) == expected  # repaired without an API restart
    states = db.execute(text("SELECT DISTINCT lifecycle_state FROM vuln_scan_policies")).scalars().all()
    assert states == ["active"]
    assert b.builtin_policy_id(db, "nx_full_audit") and b.builtin_policy_id(db, "nx_denial_of_service") is None


@pg
def test_pg_list_endpoint_never_empty_and_builtins_are_read_only(pg_db):
    from fastapi import HTTPException

    from app.routers import vuln

    os.environ.setdefault("VULN_MODULE_ENABLED", "true")
    db, _text = pg_db
    rows = vuln.list_policies(case_id=None, db=db, current=None)
    assert len(rows) == len(seedable_templates())
    assert rows[0]["vendor"] == "nexpose"  # Nexpose group first among built-ins
    with pytest.raises(HTTPException) as err:
        vuln.update_policy(rows[0]["id"], vuln.PolicyUpdate(name="changed"), db=db, current=None)
    assert err.value.status_code == 409
