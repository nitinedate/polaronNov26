"""Live PostgreSQL check of the 2026-10-21 inventory / Standard-profile SQL.

Runs every new or changed query through the real module code against a real
PostgreSQL schema (minimal DDL copied from migrations/009). Uses a throw-away
schema and never touches evidence. Usage (any scratch database):

    DATABASE_URL=postgresql+psycopg2://user:pw@host/db python scripts/validate_inventory_sql_20261021.py
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

SCHEMA = "inv_sql_check"
JOB = str(uuid.uuid4())
DDL = f"""
DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
CREATE SCHEMA {SCHEMA};
SET search_path TO {SCHEMA};
CREATE TABLE jobs (id uuid PRIMARY KEY, disk_source jsonb DEFAULT '{{}}'::jsonb, updated_at timestamptz DEFAULT NOW());
CREATE TABLE job_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  file_path text NOT NULL, file_name text, extension text, size_bytes bigint DEFAULT 0,
  sha256 text, encyclopedia_artifact_id text, parse_status text NOT NULL DEFAULT 'pending',
  ocr_status text NOT NULL DEFAULT 'pending', minio_uri text,
  metadata jsonb DEFAULT '{{}}'::jsonb, created_at timestamptz NOT NULL DEFAULT NOW(),
  UNIQUE(job_id, file_path));
CREATE TABLE artifact_parse_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_artifact_id uuid NOT NULL REFERENCES job_artifacts(id) ON DELETE CASCADE,
  parser_name text NOT NULL, parser_version text, record_count integer DEFAULT 0,
  byte_offset bigint, normalized jsonb, error text, created_at timestamptz NOT NULL DEFAULT NOW());
CREATE TABLE forensic_media_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid, job_artifact_id uuid,
  status text, flagged boolean DEFAULT false);
"""


def art(db, path, *, size=5000, sha=None, status="parsed", ext=None, minio=None, enc=None, meta=None):
    aid = str(uuid.uuid4())
    name = path.rsplit("/", 1)[-1]
    if ext is None:
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    db.execute(text("""INSERT INTO job_artifacts(id,job_id,file_path,file_name,extension,size_bytes,sha256,
        parse_status,minio_uri,encyclopedia_artifact_id,metadata)
        VALUES(:id,:j,:p,:n,:e,:s,:h,:st,:m,:enc,CAST(:meta AS jsonb))"""),
        {"id": aid, "j": JOB, "p": path, "n": name, "e": ext, "s": size, "h": sha, "st": status,
         "m": minio, "enc": enc, "meta": json.dumps(meta or {})})
    return aid


def parse(db, aid, parser, records, *, age_sec=0):
    db.execute(text("""INSERT INTO artifact_parse_results(job_artifact_id,parser_name,record_count,normalized,created_at)
        VALUES(:a,:p,:c,CAST(:n AS jsonb), NOW() - make_interval(secs => :age))"""),
        {"a": aid, "p": parser, "c": len(records), "n": json.dumps(records), "age": age_sec})


def main() -> int:
    url = os.environ.get("DATABASE_URL") or "postgresql+psycopg2://t:t@localhost/polaron"
    engine = create_engine(url)
    checks: list[tuple[str, bool, str]] = []

    def check(name, cond, detail=""):
        checks.append((name, bool(cond), str(detail)))

    with Session(engine) as db:
        for stmt in DDL.strip().split(";\n"):
            if stmt.strip():
                db.execute(text(stmt))
        db.execute(text(f"SET search_path TO {SCHEMA}"))
        db.execute(text("INSERT INTO jobs(id, disk_source) VALUES (:j, CAST(:ds AS jsonb))"),
                   {"j": JOB, "ds": json.dumps({"processing_profile": "standard"})})

        # --- registry / SetupAPI fixtures
        sys_a = art(db, "Windows/System32/config/SYSTEM", size=12_000_000, sha="AAA")
        sys_vss = art(db, "System Volume Information/{x}/Windows/System32/config/SYSTEM", size=12_000_000, sha="aaa")
        nt = art(db, "Users/alice/NTUSER.DAT", size=3_000_000, sha="N1")
        nt_to = art(db, "Users/bob/NTUSER.DAT", size=2_000_000, sha="N2", status="skipped")
        soft = art(db, "Windows/System32/config/SOFTWARE", size=80_000_000, sha="S1")
        setup = art(db, "Windows/INF/setupapi.dev.log", size=90_000, sha="U1", ext=".log")
        usb = {"record_type": "usb_device", "bus": "USBSTOR", "class_id": "Disk&Ven_SanDisk", "serial": "4C53"}
        parse(db, sys_a, "registry", [usb, {"record_type": "other_key", "x": 1}])
        parse(db, sys_vss, "registry", [usb])
        parse(db, nt, "registry", [{"record_type": "rdp_connection", "host": "old"}], age_sec=600)  # superseded
        parse(db, nt, "registry", [
            {"record_type": "rdp_connection", "host": "10.0.0.5", "user": "alice"},
            {"record_type": "feature_usage", "metric": "app_launch", "entry_count": 7,
             "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch"},
        ])
        parse(db, nt_to, "timeout", [{"record_type": "parse_retry"}])  # breadcrumb only -> live fallback
        parse(db, soft, "registry", [
            {"record_type": "installed_program", "display_name": "Microsoft Office", "is_microsoft": True, "uninstall_key": "k1"},
            {"record_type": "installed_program", "display_name": "7-Zip", "is_microsoft": False, "uninstall_key": "k2"},
        ])
        parse(db, setup, "setupapi", [{"record_type": "usb_usage_event", "device_id": "USB\\VID_0781&PID_5567\\4C53",
                                       "event_time": "2026-09-01T10:00:00"}])

        # --- email fixtures
        pst = art(db, "Users/alice/Documents/Outlook Files/alice.pst", size=50_000_000)
        parse(db, pst, ".pst", [{"record_type": "outlook_message"}] * 3 + [{"record_type": "outlook_task"}])
        hx = art(db, "Users/alice/AppData/Local/Packages/microsoft.windowscommunicationsapps_8wekyb3d8bbwe/LocalState/HxStore.hxd")
        parse(db, hx, "binary_fallback", [{"record_type": "windows_mail_message", "count": 5}])

        # --- extensionless MIME candidates (Downloads / AppData)
        e_mail = art(db, "Users/alice/Downloads/message", size=4000, ext="")
        parse(db, e_mail, "email_mime", [{"record_type": "email_message"}])
        e_bin = art(db, "Users/alice/AppData/Local/Google/Chrome/User Data/Default/LOCK", size=4000, ext="")
        parse(db, e_bin, "binary_fallback", [{"record_type": "binary"}])
        e_unparsed = art(db, "Users/alice/Downloads/unknownblob", size=4000, ext="", status="skipped")
        e_valid = art(db, "Users/alice/AppData/Roaming/thunder/x", size=4000, ext="", meta={"email_mime_validated": "true"})
        parse(db, e_valid, "binary_fallback", [{"record_type": "binary"}])
        eml = art(db, "Users/alice/Desktop/quote.eml", size=4000)

        # --- media fixtures
        u_img = art(db, "Users/alice/Pictures/IMG_1.jpg", size=900_000)
        v_img = art(db, "Program Files/WindowsApps/App/Assets/logo.png", size=3000)
        w_img = art(db, "Windows/Web/Wallpaper/Windows/img0.jpg", size=900_000)
        r_img = art(db, "$Recycle.Bin/S-1-5-21-1/$RABC.png", size=20_000)
        db.execute(text("INSERT INTO forensic_media_observations(job_id,job_artifact_id,status) VALUES (:j,:a,'done'),(:j,:b,'done')"),
                   {"j": JOB, "a": u_img, "b": v_img})  # v_img observed earlier under Deep
        db.commit()

        # ============ 1. registry evidence index (real SQL) ============
        from app.services import artifact_live_counts as alc
        from app.services import registry_evidence_index as rei
        live_reads = []
        alc._read_job_files = lambda _db, _job, rows, max_bytes=None: (live_reads.append([r["file_path"] for r in rows]) or {})
        rei.clear_registry_evidence_cache()
        idx = rei.registry_evidence(db, JOB)
        usb_recs = list(idx.records("usb_device"))
        check("registry: VSS copy (same SHA, case-insensitive) counted once", len(usb_recs) == 1, len(usb_recs))
        rdp = [r["host"] for _, _, r in idx.records("rdp_connection")]
        check("registry: latest parse per artifact only (no superseded duplicates)", rdp == ["10.0.0.5"], rdp)
        check("registry: hive kinds resolved", {k for _, k, _ in idx.records("feature_usage")} == {"ntuser"})
        check("registry: setupapi kind", [k for _, k, _ in idx.records("usb_usage_event")] == ["setupapi"])
        check("registry: only unparsed hive read live", live_reads == [["Users/bob/NTUSER.DAT"]], live_reads)
        check("registry: non-indexed record types excluded", "other_key" not in idx.by_type)

        # ============ 2. collectors on the index ============
        from app.services import catalog_aligned_counts as cac
        n_usb, devices = cac.count_usb_device_records(db, JOB)
        check("USB Devices = USBSTOR + SetupAPI device", n_usb == 2, devices)
        check("RDP count", cac.count_rdp_connection_records(db, JOB)[0] == 1)
        check("Feature Usage count", cac.count_feature_usage_records(db, JOB) == 7)
        inv = alc.scan_registry_inventory(db, JOB)
        check("Installed programs MS / non-MS", (inv["microsoft_count"], inv["non_microsoft_count"]) == (1, 1), inv)
        from app.services import forensic_inventory as fi
        ev = fi.collect_usb_usage_events(db, JOB)
        check("USB usage events from index", ev["usage_event_count"] == 1, ev["usage_event_count"])
        db.rollback()

        # ============ 3. email aggregate (real SQL) ============
        from app.services import email_inventory as ei
        ei.clear_parsed_record_count_cache()
        counts = ei._parsed_record_counts(db, JOB, ei._EMAIL_RECORD_TYPES)
        check("email aggregate: outlook_message=3", counts.get("outlook_message") == 3, counts)
        check("email aggregate: count field honoured (windows_mail_message=5)", counts.get("windows_mail_message") == 5, counts)
        check("email aggregate: outlook_task=1", counts.get("outlook_task") == 1, counts)
        db.rollback()

        # ============ 4. MIME stage-5 candidate filter (real SQL) ============
        from app.services import email_mime_inventory as emi
        seen_rows: dict[str, list[str]] = {}
        calls = []

        def capture(_db, _job, rows):
            calls.append([r["file_path"] for r in rows])
            return iter(())

        emi._iter_message_bytes = capture
        emi._scan_job_email_mime_inventory_impl(db, JOB, max_eml_files=100, max_extensionless=100)
        eml_paths, ext_paths = (calls + [[], []])[:2]
        check("MIME: .eml rows still scanned", "Users/alice/Desktop/quote.eml" in eml_paths, eml_paths)
        check("MIME: stage-5 email_mime hit kept", "Users/alice/Downloads/message" in ext_paths, ext_paths)
        check("MIME: unparsed file kept as candidate", "Users/alice/Downloads/unknownblob" in ext_paths, ext_paths)
        # Validated messages match EML_RFC822_ANY_WHERE, so the EML pass scans them and
        # the extensionless pass de-duplicates them out (unchanged from before).
        check("MIME: previously validated message scanned exactly once",
              (eml_paths + ext_paths).count("Users/alice/AppData/Roaming/thunder/x") == 1, (eml_paths, ext_paths))
        check("MIME: parsed non-RFC822 binary excluded",
              "Users/alice/AppData/Local/Google/Chrome/User Data/Default/LOCK" not in ext_paths, ext_paths)
        db.rollback()

        # ============ 5. Standard media scope (real SQL) ============
        from app.services.processing_profile import USER_SPACE_PATH_SQL, is_standard
        check("profile: job reads as standard", is_standard(db, JOB))
        in_scope = {r[0] for r in db.execute(text(
            f"SELECT file_path FROM job_artifacts WHERE job_id=:jid AND extension IN ('.jpg','.png') AND {USER_SPACE_PATH_SQL}"),
            {"jid": JOB})}
        check("media: user + recycle bin in scope",
              in_scope == {"Users/alice/Pictures/IMG_1.jpg", "$Recycle.Bin/S-1-5-21-1/$RABC.png"}, sorted(in_scope))
        pred = f"(extension IN ('.jpg','.png')) AND {USER_SPACE_PATH_SQL}"
        scope_sql = f" AND job_artifact_id IN (SELECT id FROM job_artifacts WHERE job_id=:jid AND {pred})"
        done = db.execute(text("SELECT count(*) FILTER(WHERE status='done') FROM forensic_media_observations WHERE job_id=:jid" + scope_sql),
                          {"jid": JOB}).scalar()
        check("media: earlier Deep vendor observation not counted in Standard total", done == 1, done)
        db.rollback()

        # ============ 6. census memo (real SQL) ============
        from app.services import disk_ext_census as dec
        first = dec.ensure_disk_extension_censuses(db, JOB)
        db.commit()
        before = db.execute(text("SELECT disk_source::text FROM jobs WHERE id=:j"), {"j": JOB}).scalar()
        second = dec.ensure_disk_extension_censuses(db, JOB)
        after = db.execute(text("SELECT disk_source::text FROM jobs WHERE id=:j"), {"j": JOB}).scalar()
        check("census: second call reuses stored census (no rewrite)", before == after and first == second)
        art(db, "Users/alice/Documents/new.docx")
        db.commit()
        third = dec.ensure_disk_extension_censuses(db, JOB)
        check("census: recomputed when file count changes",
              third["document_disk_inventory"]["enumerated_files"] == first["document_disk_inventory"]["enumerated_files"] + 1)
        db.commit()

        # ============ 7. jump-list iterator predicate (real SQL) ============
        from app.services.artifact_sections import _iter_jump_records
        jl = art(db, "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/a.automaticDestinations-ms")
        parse(db, jl, "jumplist", [{"record_type": "jump_list_file", "entry_count": 4}])
        db.commit()
        recs = [r for _, r in _iter_jump_records(db, JOB) if r.get("record_type") == "jump_list_file"]
        check("jump lists: parser_name predicate returns records", len(recs) == 1, recs)

        db.execute(text(f"DROP SCHEMA {SCHEMA} CASCADE"))
        db.commit()

    width = max(len(n) for n, _, _ in checks)
    failed = 0
    for name, ok, detail in checks:
        failed += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {'' if ok else detail}")
    print(f"\n{len(checks) - failed}/{len(checks)} live SQL checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
