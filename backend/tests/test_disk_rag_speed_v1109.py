"""V1.10.9: Disk RAG speed-ups without changing which evidence is parsed, OCR'd or graphed."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

import app.services.artifact_materialize as am
import app.services.artifact_parse as ap

PG_DSN = os.environ.get("AETHERIS_TEST_PG_DSN", "")

PATHS = [
    ("Windows/System32/config/SYSTEM", 12_000_000),
    ("Windows/System32/config/SOFTWARE", 80_000_000),
    ("Users/alice/NTUSER.DAT", 3_000_000),
    ("Windows/System32/winevt/Logs/Security.evtx", 90_000_000),
    ("Windows/System32/winevt/Logs/Microsoft-Windows-Bits-Client%4Operational.evtx", 70_000_000),
    ("Windows/System32/winevt/Logs/Microsoft-Windows-Shell-Core%4Operational.evtx", 1_000_000),
    ("Windows/Prefetch/CHROME.EXE-ABC123.pf", 40_000),
    ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", 5_000_000),
    ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History-journal", 10_000),
    ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb/000003.log", 2_000),
    ("Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.docx.lnk", 2_000),
    ("Users/alice/Desktop/scan_0001.jpg", 900_000),
    ("Users/alice/Pictures/holiday.png", 2_000_000),
    ("Users/alice/Videos/clip.mp4", 50_000_000),
    ("Windows/Fonts/arial.ttf", 400_000),
    ("Program Files/Vendor/app/lib/helper.dll", 300_000),
    ("Program Files/Vendor/app/assets/logo.png", 20_000),
    ("Users/alice/Documents/notes.txt", 4_000),
    ("Users/alice/AppData/Local/Microsoft/Outlook/alice.ost", 200_000_000),
    ("$Recycle.Bin/S-1-5-21-1/$RABC123.pdf", 100_000),
]


def _entries():
    return [{"path": p, "size_bytes": size, "sha256": f"{i:064x}", "part_id": 1, "offset": i * 10}
            for i, (p, size) in enumerate(PATHS)]


@pytest.fixture()
def pg_session(monkeypatch):
    if not PG_DSN:
        pytest.skip("set AETHERIS_TEST_PG_DSN to run the PostgreSQL equivalence test")
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(PG_DSN)
    schema = "t_" + uuid.uuid4().hex[:10]
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
        conn.execute(text(f"""CREATE TABLE {schema}.job_artifacts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL,
            file_path text NOT NULL, file_name text, extension text, size_bytes bigint DEFAULT 0,
            sha256 text, encyclopedia_artifact_id text,
            parse_status text NOT NULL DEFAULT 'pending', ocr_status text NOT NULL DEFAULT 'pending',
            minio_uri text, metadata jsonb DEFAULT '{{}}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT NOW(), updated_at timestamptz NOT NULL DEFAULT NOW(),
            UNIQUE (job_id, file_path))"""))
    session = sessionmaker(bind=engine)()
    session.execute(text(f"SET search_path TO {schema}"))
    session.commit()

    @__import__("sqlalchemy").event.listens_for(engine, "connect")
    def _sp(dbapi_conn, _rec):  # new pool connections use the test schema too
        with dbapi_conn.cursor() as cur:
            cur.execute(f"SET search_path TO {schema}")

    monkeypatch.setattr(am, "_load_encyclopedia_cache", lambda db: [])
    monkeypatch.setattr(am, "write_disk_log", lambda *a, **k: None)
    monkeypatch.setattr(ap, "write_disk_log", lambda *a, **k: None)
    yield session
    session.close()
    with engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    engine.dispose()


def _states(db, job_id):
    from app.db.sql_helpers import fetchall

    rows = fetchall(db, "SELECT file_path, parse_status, ocr_status, metadata FROM job_artifacts WHERE job_id=:j", {"j": job_id})
    return {r["file_path"]: (r["parse_status"], r["ocr_status"]) for r in rows}, {r["file_path"]: r["metadata"] for r in rows}


def test_registration_time_filter_equals_the_old_two_pass_filter(pg_session):
    db = pg_session
    new_job, old_job = str(uuid.uuid4()), str(uuid.uuid4())

    def provenance(e):
        meta = {"serial_materialized": True, "extracted_part_id": e["part_id"], "extracted_part_offset": e["offset"]}
        if e["path"].endswith("scan_0001.jpg"):
            meta["ocr_quality_bucket"] = "true"  # media already flagged as unclear
        return meta

    # V1.10.9: one pass with classification + provenance.
    out = am.materialize_index_entries(db, new_job, _entries(), update_status=False, phase1_filter=False,
                                       classify_parse_queue=True, extra_metadata=provenance)
    db.commit()
    # Before: register everything as pending, then the two filtering passes.
    am.materialize_index_entries(db, old_job, _entries(), update_status=False, phase1_filter=False,
                                 extra_metadata=provenance)
    db.commit()
    ap.skip_low_value_pending(db, old_job)
    ap.bulk_skip_non_parser_pending(db, old_job)
    db.commit()

    new_states, new_meta = _states(db, new_job)
    old_states, _ = _states(db, old_job)
    assert len(new_states) == len(PATHS)  # every extracted file is still registered
    assert new_states == old_states  # identical parse/OCR decisions for every path
    pending = {p for p, (ps, _) in new_states.items() if ps == "pending"}
    skipped = {p for p, (ps, _) in new_states.items() if ps == "skipped"}
    assert pending and skipped
    assert out["parse_pending"] == len(pending) and out["parse_skipped_at_registration"] == len(skipped)
    assert "Windows/System32/config/SYSTEM" in pending and "Windows/System32/winevt/Logs/Security.evtx" in pending
    assert "Program Files/Vendor/app/lib/helper.dll" in skipped and "Windows/Fonts/arial.ttf" in skipped
    # provenance stored in the same insert (no second UPDATE pass)
    assert new_meta["Windows/Prefetch/CHROME.EXE-ABC123.pf"]["extracted_part_offset"] == 60
    # nothing left for the old filters to do on the new job
    assert ap.skip_low_value_pending(db, new_job) == 0 and ap.bulk_skip_non_parser_pending(db, new_job) == 0


def test_reregistration_keeps_existing_parse_state(pg_session):
    db = pg_session
    job = str(uuid.uuid4())
    am.materialize_index_entries(db, job, _entries(), update_status=False, phase1_filter=False, classify_parse_queue=True)
    db.commit()
    from app.db.sql_helpers import execute

    execute(db, "UPDATE job_artifacts SET parse_status='parsed' WHERE job_id=:j AND file_path='Windows/System32/config/SYSTEM'", {"j": job})
    db.commit()
    am.materialize_index_entries(db, job, _entries(), update_status=False, phase1_filter=False, classify_parse_queue=True,
                                 extra_metadata=lambda e: {"rerun": True})
    db.commit()
    states, meta = _states(db, job)
    assert states["Windows/System32/config/SYSTEM"][0] == "parsed"  # resumable: done work is kept
    assert meta["Windows/System32/config/SYSTEM"]["rerun"] is True


def test_classification_sql_escapes_percent_for_psycopg2():
    sql = am._classified_insert_sql()
    # psycopg2 formats the whole statement: the only placeholder is VALUES %s,
    # every literal % of the LIKE patterns is doubled.
    assert "VALUES %s" in sql and sql.replace("%%", "").count("%") == 1
    assert "%%Security.evtx" in sql


# --- native parsing ---------------------------------------------------------------------------
def test_serial_drain_does_not_refilter_every_batch(monkeypatch):
    calls = []
    monkeypatch.setattr(ap, "skip_low_value_pending", lambda db, j: calls.append("low") or 0)
    monkeypatch.setattr(ap, "bulk_skip_non_parser_pending", lambda db, j: calls.append("media") or 0)
    monkeypatch.setattr(ap, "recover_stale_parsing_claims", lambda db, j: None)
    monkeypatch.setattr(ap, "fetchall", lambda *a, **k: [])
    ap.parse_job_artifacts_for_paths(object(), "j", paths=None, index_map={}, forensic_only=True, queue_prepared=True)
    assert calls == []
    ap.parse_job_artifacts_for_paths(object(), "j", paths=None, index_map={}, forensic_only=True)
    assert calls == ["low", "media"]  # other callers unchanged


def test_part_paths_are_indexed_once():
    index_map = {f"p/{i}": ("part-a" if i % 2 else "part-b") for i in range(10)}
    first = ap._paths_for_part(index_map, "part-a")
    assert sorted(first) == [f"p/{i}" for i in (1, 3, 5, 7, 9)]
    index_map["p/99"] = "part-a"  # same object: cached reverse map is reused
    assert len(ap._paths_for_part(index_map, "part-a")) == 5
    assert ap._paths_for_part(dict(index_map), "part-a")[-1] == "p/99"  # new map -> rebuilt


def test_serial_parse_stage_uses_prepared_queue_and_one_count_per_batch():
    src = (Path(__file__).resolve().parents[1] / "app/services/forensic_serial_stages.py").read_text(encoding="utf-8")
    body = src.split("def _parse(db, job_id, schema_name):", 1)[1].split("\ndef _recovery(", 1)[0]
    assert "queue_prepared=True" in body
    assert body.count("FROM job_artifacts") == 2  # total once + one status count per batch
    mat = src.split("def _materialize_full(db, job_id):", 1)[1].split("\ndef _parse(", 1)[0]
    assert "classify_parse_queue=True" in mat and "extra_metadata=_provenance" in mat
    assert "UPDATE job_artifacts AS ja SET metadata" not in mat  # no second pass over every row


# --- media review -----------------------------------------------------------------------------
def test_media_progress_is_throttled_and_workers_follow_cpu(monkeypatch):
    import app.services.forensic_media_review as fmr

    fmr._PROGRESS_STATE.clear()
    due = [fmr._progress_due("job") for _ in range(200)]
    assert 3 <= sum(due) <= 10  # first call + every 50 files, not 200 counts
    monkeypatch.setenv("MEDIA_REVIEW_WORKERS", "12")
    assert fmr.media_review_workers() == 12
    monkeypatch.delenv("MEDIA_REVIEW_WORKERS")
    monkeypatch.setattr(fmr.os, "cpu_count", lambda: 32)
    assert fmr.media_review_workers() == 16
    monkeypatch.setattr(fmr.os, "cpu_count", lambda: 4)
    assert fmr.media_review_workers() == 4


# --- graph ------------------------------------------------------------------------------------
class _Session:
    def __init__(self):
        self.calls = []

    def run(self, cypher, **params):
        self.calls.append((" ".join(cypher.split()), params))

        class _R:
            def consume(self_inner):
                return None
        return _R()


def _parsed_rows():
    evtx = [{"event_id": 4624 + (i % 3), "user_profile": "alice"} for i in range(3000)]
    return [
        {"file_path": "Security.evtx", "parser_name": "evtx", "encyclopedia_artifact_id": "A1", "normalized": json.dumps(evtx)},
        {"file_path": "CHROME.pf", "parser_name": "prefetch", "encyclopedia_artifact_id": None,
         "normalized": [{"format": "prefetch_scca", "executable": "CHROME.EXE", "target_paths": ["C:/x.dll"]}]},
        {"file_path": "NTUSER.DAT", "parser_name": "registry", "encyclopedia_artifact_id": "A2",
         "normalized": [{"registry_key": "Software\\\\Run", "table": None}]},
        {"file_path": "History", "parser_name": "sqlite", "encyclopedia_artifact_id": None, "normalized": [{"table": "urls"}]},
        {"file_path": "odd.txt", "parser_name": "text", "encyclopedia_artifact_id": None, "normalized": "plain text"},
    ]


def test_graph_batches_by_relationship_and_keeps_the_same_edges():
    import importlib.util

    import app.services.neo4j_sync as ns

    spec = importlib.util.spec_from_file_location("old_neo4j_sync", "/tmp/oldsrc/old_neo4j_sync.py")
    if not Path("/tmp/oldsrc/old_neo4j_sync.py").exists():
        pytest.skip("previous implementation not available for comparison")
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)

    old_session, new_session = _Session(), _Session()
    old_edges = old._sync_parsed_edges(old_session, "job", _parsed_rows(), max_records=None)
    new_edges = ns._sync_parsed_edges(new_session, "job", _parsed_rows(), max_records=None)
    assert new_edges == old_edges == 6006  # 3000 events x (event + user) + 6 others
    assert len(old_session.calls) > 6000 and len(new_session.calls) <= 10  # round trips

    def expand(calls):  # the (relationship, key, file) facts each implementation writes
        facts = set()
        for cypher, params in calls:
            rows = params.get("rows") or [params]
            rel = cypher.split("]->")[0].rsplit("[:", 1)[-1] if "]->" in cypher else "FILE"
            for r in rows:
                key = r.get("name") or r.get("target") or r.get("eid") or r.get("rkey") or r.get("uname") or r.get("tbl") or r.get("aid") or r.get("parser")
                facts.add((rel, str(key), r.get("path")))
        return facts

    assert expand(new_session.calls) == expand(old_session.calls)
    max_records = ns._sync_parsed_edges(_Session(), "job", _parsed_rows(), max_records=20)
    assert max_records == old._sync_parsed_edges(_Session(), "job", _parsed_rows(), max_records=20)
