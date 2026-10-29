"""V1.11.0: pipelined Disk RAG — parse shards, early GPU OCR, early graph files, recovery at registration."""
from __future__ import annotations

import os
import threading
import uuid
from types import SimpleNamespace

import pytest

PG_DSN = os.environ.get("AETHERIS_TEST_PG_DSN", "")


# --- PostgreSQL: shards partition the queue by part; concurrent claims never overlap ---------
@pytest.fixture()
def pg(monkeypatch):
    if not PG_DSN:
        pytest.skip("set AETHERIS_TEST_PG_DSN to run the PostgreSQL concurrency tests")
    from sqlalchemy import create_engine, event, text
    from sqlalchemy.orm import sessionmaker

    schema = "t_" + uuid.uuid4().hex[:10]
    engine = create_engine(PG_DSN, pool_size=12, max_overflow=4)
    with engine.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
        conn.execute(text(f"""CREATE TABLE {schema}.job_artifacts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_id uuid NOT NULL, file_path text NOT NULL,
            file_name text, extension text, size_bytes bigint DEFAULT 0, sha256 text, encyclopedia_artifact_id text,
            parse_status text NOT NULL DEFAULT 'pending', ocr_status text NOT NULL DEFAULT 'pending',
            minio_uri text, metadata jsonb DEFAULT '{{}}'::jsonb, created_at timestamptz DEFAULT NOW(),
            updated_at timestamptz DEFAULT NOW(), UNIQUE (job_id, file_path))"""))
    engine.dispose()

    @event.listens_for(engine, "connect")
    def _sp(dbapi_conn, _rec):
        with dbapi_conn.cursor() as cur:
            cur.execute(f"SET search_path TO {schema}")

    yield sessionmaker(bind=engine)
    with engine.begin() as conn:
        conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    engine.dispose()


def _seed(Session, job_id, parts=12, per_part=40):
    from app.db.sql_helpers import execute

    db = Session()
    for p in range(parts):
        for i in range(per_part):
            execute(db, """INSERT INTO job_artifacts (job_id,file_path,file_name,extension,metadata)
                VALUES (:j,:p,:n,'.evtx',CAST(:m AS jsonb))""",
                    {"j": job_id, "p": f"Windows/System32/winevt/Logs/p{p}_{i}.evtx", "n": f"p{p}_{i}.evtx",
                     "m": '{"serial_materialized": true, "extracted_part_uri": "part-%d.tar.zst"}' % p})
    db.commit()
    db.close()


def test_part_shards_cover_every_row_once_and_keep_parts_whole(pg):
    from app.db.sql_helpers import fetchall
    from app.services.artifact_parse import count_pending_in_part_bucket

    job = str(uuid.uuid4())
    _seed(pg, job)
    db = pg()
    shards = 6
    total = 0
    part_owner: dict[str, set[int]] = {}
    for b in range(shards):
        total += count_pending_in_part_bucket(db, job, bucket=b, buckets=shards)
        rows = fetchall(db, f"""SELECT metadata->>'extracted_part_uri' AS part FROM job_artifacts
            WHERE job_id=:j AND mod(abs(hashtext(coalesce(metadata->>'extracted_part_uri', file_path))), {shards}) = {b}""",
                        {"j": job})
        for r in rows:
            part_owner.setdefault(r["part"], set()).add(b)
    db.close()
    assert total == 12 * 40  # every pending row is in exactly one shard
    assert all(len(owners) == 1 for owners in part_owner.values())  # a part is never split


def test_concurrent_claims_never_take_the_same_row(pg):
    from app.db.sql_helpers import fetchall
    from app.services.artifact_parse import _claim_artifacts_by_id

    job = str(uuid.uuid4())
    _seed(pg, job, parts=4, per_part=200)
    db = pg()
    ids = [r["id"] for r in fetchall(db, "SELECT id FROM job_artifacts WHERE job_id=:j", {"j": job})]
    db.close()
    claimed: list[list] = []
    lock = threading.Lock()

    def worker():
        s = pg()
        try:
            for _ in range(10):
                got = _claim_artifacts_by_id(s, ids)  # everyone races for the same ids
                s.commit()
                with lock:
                    claimed.append([str(r["id"]) for r in got])
        finally:
            s.close()

    threads = [threading.Thread(target=worker) for _ in range(7)]  # 6 shards + the serial loop
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    flat = [i for batch in claimed for i in batch]
    assert len(flat) == len(set(flat)) == len(ids)


def test_recovery_skips_rows_already_analysed_at_registration(pg, monkeypatch):
    import app.services.forensic_serial_stages as stages
    from app.db.sql_helpers import execute, fetchone

    job = str(uuid.uuid4())
    _seed(pg, job, parts=2, per_part=50)  # registered by the serial stage
    db = pg()
    execute(db, """INSERT INTO job_artifacts (job_id,file_path,metadata) VALUES
        (:j,'$Recycle.Bin/S-1-5-21/$RABC.docx','{}'::jsonb), (:j,'Users/a/notes.txt','{}'::jsonb)""", {"j": job})
    db.commit()
    monkeypatch.setattr(stages, "report_progress", lambda *a, **k: None)
    monkeypatch.setattr("app.services.ocr_gpu.count_pending_ocr", lambda db, j: 0, raising=False)
    import app.tasks as tasks
    monkeypatch.setattr(tasks.quality_ocr_triage_task, "delay", lambda *a, **k: None)
    out = stages._recovery(db, job)
    assert out["analysed_now"] == 2 and out["analysed_at_registration"] == 100 and out["total"] == 102
    hint = fetchone(db, "SELECT metadata FROM job_artifacts WHERE job_id=:j AND file_path LIKE '$Recycle%'", {"j": job})
    assert hint["metadata"]["recovery_state"] == "recycle_bin"
    db.close()


# --- serial parse loop shares the queue with the shards ---------------------------------------
def _stub_parse_prelude(monkeypatch, stages, *, shards_active=True, executed=None):
    import app.tasks as tasks

    monkeypatch.setattr(tasks.quality_ocr_triage_task, "delay", lambda *a, **k: None)
    monkeypatch.setattr(stages, "execute", lambda db, sql, params=None: (executed if executed is not None else []).append(sql))
    monkeypatch.setattr(stages, "_parse_shards_active", lambda db, j: shards_active)
    monkeypatch.setattr("app.services.artifact_parse.recover_stale_parsing_claims", lambda db, j: 0)


def test_serial_parse_waits_for_shards_instead_of_giving_up(monkeypatch):
    import app.services.forensic_serial_stages as stages

    _stub_parse_prelude(monkeypatch, stages)

    pending = iter([500, 500, 500, 420, 420, 0])
    batches = []

    def fake_fetchone(db, sql, params=None):
        if "count(*) FILTER" in sql:
            p = next(pending)
            return {"pending": p, "done": 500 - p, "skipped": 0, "failed": 0, "total": 500}
        return {"c": 500}

    monkeypatch.setattr(stages, "fetchone", fake_fetchone)
    monkeypatch.setattr(stages, "report_progress", lambda *a, **k: None)
    monkeypatch.setattr(stages, "_index_map", lambda db, j: {})
    monkeypatch.setattr(stages, "PARSE_SHARD_WAIT_SEC", 0.0)
    monkeypatch.setattr(stages.time, "sleep", lambda s: None)
    monkeypatch.setattr("app.services.job_control.pipeline_should_stop", lambda db, j: False)
    monkeypatch.setattr("app.services.artifact_parse.prepare_forensic_parse_queue", lambda db, j: {})
    import app.services.artifact_parse as ap

    monkeypatch.setattr(ap, "parse_job_artifacts_for_paths",
                        lambda *a, **k: batches.append(k.get("queue_prepared")) or {"parsed": 0, "skipped": 0})
    src_db = SimpleNamespace(commit=lambda: None, rollback=lambda: None, info={})
    try:
        out = stages._parse(src_db, "job", "firm_x")
    except Exception as exc:  # _parse may start sidecars we do not stub here
        pytest.fail(f"_parse raised {exc!r}")
    assert out["status"] == "ok" and all(batches)  # waited through quiet batches, never gave up


def test_serial_parse_still_reports_a_stuck_queue(monkeypatch):
    import app.services.forensic_serial_stages as stages
    from app.services.forensic_serial_pipeline import StageWaiting

    _stub_parse_prelude(monkeypatch, stages)
    monkeypatch.setattr(stages, "fetchone", lambda db, sql, params=None: {"pending": 9, "done": 0, "skipped": 0, "failed": 0, "total": 9, "c": 9})
    monkeypatch.setattr(stages, "report_progress", lambda *a, **k: None)
    monkeypatch.setattr(stages, "_index_map", lambda db, j: {})
    monkeypatch.setattr(stages, "PARSE_NO_PROGRESS_SEC", 0)
    monkeypatch.setattr(stages.time, "sleep", lambda s: None)
    monkeypatch.setattr("app.services.job_control.pipeline_should_stop", lambda db, j: False)
    monkeypatch.setattr("app.services.artifact_parse.prepare_forensic_parse_queue", lambda db, j: {})
    import app.services.artifact_parse as ap

    monkeypatch.setattr(ap, "parse_job_artifacts_for_paths", lambda *a, **k: {"parsed": 0})
    with pytest.raises(StageWaiting):
        stages._parse(SimpleNamespace(commit=lambda: None, rollback=lambda: None, info={}), "job", "firm_x")


# --- scheduler ---------------------------------------------------------------------------------
def _schedule(monkeypatch, stage, *, mobile=False, early_ocr="1"):
    import app.services.safe_parallel as sp
    import app.tasks as tasks

    launched = []
    monkeypatch.setenv("EARLY_GPU_OCR", early_ocr)
    monkeypatch.setattr("app.forensic_common.job_types.is_mobile_job", lambda db, j: mobile)
    monkeypatch.setattr(sp, "claim_sidecar", lambda db, j, name, details=None: f"tid-{name}")
    for name in ("parse_shard_sidecar_task", "early_ocr_sidecar_task", "graph_files_sidecar_task"):
        monkeypatch.setattr(getattr(tasks, name), "apply_async",
                            lambda args=None, queue=None, task_id=None, _n=name, **k: launched.append((_n, queue, args)))
    out = sp._schedule_pipelined_sidecars(object(), "job", schema_name="firm_x", active_stage=stage, available=10)
    return launched, out


def test_registration_starts_parse_shards_and_gpu_ocr(monkeypatch):
    launched, out = _schedule(monkeypatch, "materialize")
    shards = [l for l in launched if l[0] == "parse_shard_sidecar_task"]
    assert len(shards) == 6 and {l[1] for l in shards} == {"disk-build"}
    assert [a[3] for _, _, a in shards] == list(range(6)) and all(a[4] == 6 for _, _, a in shards)
    assert any(l[0] == "early_ocr_sidecar_task" for l in launched)
    assert not any(l[0] == "graph_files_sidecar_task" for l in launched)  # registration not final yet
    assert out["available"] == 4


def test_parsing_adds_graph_files_and_mobile_is_untouched(monkeypatch):
    launched, _ = _schedule(monkeypatch, "parse")
    names = [l[0] for l in launched]
    assert names.count("parse_shard_sidecar_task") == 6 and "graph_files_sidecar_task" in names
    launched, _ = _schedule(monkeypatch, "ocr")
    assert [l[0] for l in launched] == ["graph_files_sidecar_task"]
    launched, out = _schedule(monkeypatch, "parse", mobile=True)
    assert launched == [] and out["available"] == 10
    launched, _ = _schedule(monkeypatch, "materialize", early_ocr="0")
    assert "early_ocr_sidecar_task" not in [l[0] for l in launched]


def test_shard_count_respects_the_slot_budget(monkeypatch):
    import app.services.safe_parallel as sp

    monkeypatch.setenv("PARSE_SHARD_SIDECARS", "12")
    assert sp.parse_shard_count() <= 8
    monkeypatch.setenv("PARSE_SHARD_SIDECARS", "0")
    assert sp.parse_shard_count() == 0


# --- graph files phase -------------------------------------------------------------------------
def test_graph_files_sidecar_skips_when_already_done(monkeypatch):
    import app.services.neo4j_sync as ns

    class _Sess:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, cypher, **k):
            class R:
                def consume(self_inner):
                    return None

                def single(self_inner):
                    return {"files": True}
            return R()

    monkeypatch.setattr(ns, "_get_driver", lambda: SimpleNamespace(session=lambda: _Sess()))
    monkeypatch.setattr(ns, "_ensure_graph_indexes", lambda d: None)
    called = []
    monkeypatch.setattr(ns, "sync_graph_files_phase", lambda *a, **k: called.append(1) or 0)
    assert ns.run_graph_files_sidecar(object(), "job") == {"status": "ok", "already_done": True}
    assert called == []
    monkeypatch.setattr(ns, "_get_driver", lambda: None)
    assert ns.run_graph_files_sidecar(object(), "job")["status"] == "deferred"


def test_parse_start_keeps_live_shard_claims(monkeypatch):
    """Resetting every 'parsing' row while shards work would parse files twice."""
    import app.services.forensic_serial_stages as stages

    for active, expect_full_reset in ((True, False), (False, True)):
        executed: list[str] = []
        _stub_parse_prelude(monkeypatch, stages, shards_active=active, executed=executed)
        monkeypatch.setattr(stages, "fetchone", lambda db, sql, params=None: {"pending": 0, "done": 3, "skipped": 0, "failed": 0, "total": 3, "c": 3})
        monkeypatch.setattr(stages, "report_progress", lambda *a, **k: None)
        monkeypatch.setattr(stages, "_index_map", lambda db, j: {})
        monkeypatch.setattr("app.services.artifact_parse.prepare_forensic_parse_queue", lambda db, j: {})
        stages._parse(SimpleNamespace(commit=lambda: None, rollback=lambda: None, info={}), "job", "firm_x")
        full_reset = any("SET parse_status='pending' WHERE job_id=:jid AND parse_status='parsing'" in q for q in executed)
        assert full_reset is expect_full_reset


def test_shards_active_check_against_postgres(pg):
    from app.db.sql_helpers import execute
    import app.services.forensic_serial_stages as stages

    db = pg()
    job = str(uuid.uuid4())
    assert stages._parse_shards_active(db, job) is False  # no sidecar table yet
    execute(db, """CREATE TABLE pipeline_sidecar_runs(job_id uuid, sidecar text, status text, task_id text,
        heartbeat_at timestamptz, updated_at timestamptz DEFAULT NOW(), details jsonb DEFAULT '{}'::jsonb,
        PRIMARY KEY(job_id, sidecar))""")
    execute(db, "INSERT INTO pipeline_sidecar_runs(job_id,sidecar,status) VALUES (:j,'parse_shard_3','running'),(:j,'prechunk','running')", {"j": job})
    db.commit()
    assert stages._parse_shards_active(db, job) is True
    execute(db, "UPDATE pipeline_sidecar_runs SET status='done' WHERE sidecar='parse_shard_3'")
    db.commit()
    assert stages._parse_shards_active(db, job) is False  # other sidecars do not count
    db.close()


# --- the shard task: drain, then finish or requeue ----------------------------------------------
@pytest.mark.parametrize("registration,left,expect", [
    ("done", 0, ("finish", None)),
    ("running", 0, ("requeue", 10)),   # registration may still add rows for this shard
    ("done", 25, ("requeue", 2)),      # more of this shard is waiting
])
def test_parse_shard_task_finishes_or_requeues(monkeypatch, registration, left, expect):
    from contextlib import contextmanager

    import app.services.artifact_parse as ap
    import app.services.forensic_serial_stages as stages
    import app.services.safe_parallel as sp
    import app.tasks as tasks

    @contextmanager
    def _noop(*a, **k):
        yield True

    db = SimpleNamespace(commit=lambda: None, rollback=lambda: None)

    @contextmanager
    def _session(schema):
        yield db

    rounds = iter([{"parsed": 40}, {"parsed": 12, "skipped": 3}, {"parsed": 0}])
    seen = {"finish": None, "requeue": None, "kwargs": []}
    monkeypatch.setattr(sp, "sidecar_slot", _noop)
    monkeypatch.setattr(sp, "sidecar_execution", _noop)
    monkeypatch.setattr(tasks, "firm_session", _session)
    monkeypatch.setattr(stages, "_index_map", lambda db, j: {"a": "part-1"})
    monkeypatch.setattr("app.services.job_control.pipeline_should_stop", lambda db, j: False)
    monkeypatch.setattr(ap, "parse_job_artifacts_for_paths", lambda *a, **k: seen["kwargs"].append(k) or next(rounds))
    monkeypatch.setattr(ap, "count_pending_in_part_bucket", lambda db, j, bucket, buckets: left)
    monkeypatch.setattr("app.db.sql_helpers.fetchone", lambda db, sql, params=None: {"status": registration})
    monkeypatch.setattr(sp, "finish_sidecar", lambda db, j, name, tid, status="done", details=None: seen.update(finish=(name, status, details)))
    monkeypatch.setattr(tasks.parse_shard_sidecar_task, "apply_async",
                        lambda args=None, queue=None, countdown=None, **k: seen.update(requeue=(args, queue, countdown)))
    out = tasks.parse_shard_sidecar_task.run("firm_x", "job", "tid-1", 2, 6)
    kw = seen["kwargs"][0]
    assert kw["parse_bucket"] == 2 and kw["parse_buckets"] == 6 and kw["bucket_by_part"] is True and kw["queue_prepared"] is True
    if expect[0] == "finish":
        assert out["status"] == "ok" and seen["finish"][0] == "parse_shard_2" and seen["finish"][1] == "done"
        assert seen["finish"][2]["parsed"] == 52 and seen["requeue"] is None
    else:
        args, queue, countdown = seen["requeue"]
        assert out["status"] == "requeued" and queue == "disk-build" and countdown == expect[1]
        assert args == ("firm_x", "job", "tid-1", 2, 6) and seen["finish"] is None
