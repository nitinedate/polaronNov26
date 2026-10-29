"""Serial adapters for the existing evidence engines, with explicit barriers."""

from __future__ import annotations

import json
import os
import time

RAG_CHUNK_DB_BATCH = int(os.environ.get("RAG_CHUNK_DB_BATCH", "6000") or 6000)
from contextlib import ExitStack

from app.config import get_settings

from app.db.sql_helpers import (
    execute,
    fetchall,
    fetchone,
    lock_job_artifacts_for_paths,
    lock_job_artifacts_in_id_order,
    retry_on_deadlock,
)
from app.services.forensic_serial_pipeline import StageWaiting
from app.services.forensic_serial_policy import (
    CHUNK_POLICY,
    bounded_map,
    bounded_process_map,
    chunk_policy_accepted_sql,
)

NIL_ID = "00000000-0000-0000-0000-000000000000"
# V1.11.0: the serial parse loop shares the queue with parallel parse shards.
PARSE_NO_PROGRESS_SEC = max(60, int(os.environ.get("PARSE_NO_PROGRESS_SEC", "600") or 600))
PARSE_SHARD_WAIT_SEC = max(1.0, float(os.environ.get("PARSE_SHARD_WAIT_SEC", "3") or 3))


def report_progress(
    db, job_id, stage, *, total, completed, failed=0, skipped=0, label=None
):
    execute(
        db,
        """UPDATE pipeline_stage_runs SET progress_at=CASE WHEN
        (total_items,completed_items,failed_items,skipped_items) IS DISTINCT FROM
        (CAST(:total AS bigint),CAST(:done AS bigint),CAST(:failed AS bigint),CAST(:skipped AS bigint))
        THEN NOW() ELSE progress_at END,
        operation_deadline=CASE WHEN (completed_items,failed_items,skipped_items) IS DISTINCT FROM
        (CAST(:done AS bigint),CAST(:failed AS bigint),CAST(:skipped AS bigint))
        THEN NOW()+INTERVAL '5 minutes' ELSE operation_deadline END,
        total_items=:total,completed_items=:done,
        failed_items=:failed,skipped_items=:skipped,heartbeat_at=NOW(),updated_at=NOW()
        WHERE job_id=:jid AND stage=:stage AND status='running'""",
        {
            "jid": job_id,
            "stage": stage,
            "total": total,
            "done": completed,
            "failed": failed,
            "skipped": skipped,
        },
    )
    patch = {
        "phase": stage,
        "completed": completed,
        "total": total,
        "label": label or stage,
    }
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=COALESCE(pipeline_progress,'{}'::jsonb) || CAST(:pp AS jsonb),
        updated_at=NOW() WHERE id=:jid""",
        {"jid": job_id, "pp": json.dumps(patch)},
    )
    db.commit()


def _index_map(db, job_id):
    from app.services.disk_manifest import build_index_map

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    ds = row.get("disk_source") or {}
    if isinstance(ds, str):
        ds = json.loads(ds)
    return {path.replace("\\", "/"): uri for path, uri in build_index_map(ds).items()}


def prepare_extracted_members(entries: list[dict], manifest: dict) -> list[dict]:
    """Keep every extracted member, including a second copy of the same path.

    The combined index and the per-shard indexes list the same members. Those
    identical lines collapse. A path that was extracted again at a different
    part or offset stays, under an inventory name that does not collide, with
    ``source_path`` set to the archive member name.
    """
    from app.services.disk_manifest import resolve_part_uri
    from app.services.evidence_paths import inventory_path, storage_text

    seen: set[tuple] = set()
    kept: list[dict] = []
    for entry in entries:
        path = storage_text((entry.get("path") or "").replace("\\", "/"))
        if not path:
            raise RuntimeError("Extracted manifest contains an entry without a path")
        part_id = int(entry.get("part_id") or 0)
        try:
            offset = int(entry.get("offset") or 0)
        except (TypeError, ValueError):
            offset = 0
        key = (path, part_id, offset)
        if key in seen:
            continue
        seen.add(key)
        part = resolve_part_uri(manifest, part_id)
        if not part:
            raise RuntimeError(f"Extracted part is missing for {path}")
        kept.append({**entry, "source_path": path, "part_uri": part, "path": path})
    used: dict[str, int] = {}
    for entry in kept:
        source = entry["source_path"]
        ordinal = used.get(source, 0)
        used[source] = ordinal + 1
        entry["path"] = inventory_path(source, ordinal)
        if ordinal:
            entry["copy_ordinal"] = ordinal
    return kept


def _materialize_full(db, job_id):
    from app.services.forensic_shard_overlap import unfinished_shards
    from app.services.forensic_serial_pipeline import StageWaiting
    pending = unfinished_shards(db, job_id)
    if pending:
        raise StageWaiting(f"Waiting for {pending} committed extraction shard writer(s)")
    from psycopg2.extras import execute_values

    from app.services.artifact_materialize import materialize_index_entries
    from app.services.disk_manifest import load_index_entries

    row = fetchone(
        db, "SELECT disk_source,files_extracted FROM jobs WHERE id=:id", {"id": job_id}
    )
    manifest = (
        json.loads(row["disk_source"])
        if isinstance(row["disk_source"], str)
        else row["disk_source"] or {}
    )
    entries = prepare_extracted_members(load_index_entries(manifest), manifest)
    expected = len(entries)
    extracted_count = int(row.get("files_extracted") or 0)
    # The manifest is authoritative for what can actually be registered. A
    # progress counter is NOT proof that its item has a committed index entry.
    # Do not discard registered evidence, and do not force another disk extraction
    # because a progress counter and the committed manifest disagree.
    manifest_gap = extracted_count - expected
    if manifest_gap:
        direction = "missing_manifest_entries" if manifest_gap > 0 else "manifest_exceeds_progress"
        execute(db, """UPDATE jobs SET metadata=coalesce(metadata,'{}'::jsonb) ||
                jsonb_build_object('materialize_manifest_gap', :gap,
                                  'materialize_manifest_entries', :entries,
                                  'materialize_extraction_reported', :reported,
                                  'materialize_coverage_limited', true,
                                  'materialize_reconciliation_status', :direction),
                updated_at=NOW() WHERE id=:jid""",
                {"jid": job_id, "gap": manifest_gap, "entries": expected,
                 "reported": extracted_count, "direction": direction})
        execute(db, """UPDATE pipeline_stage_runs SET details=coalesce(details,'{}'::jsonb) ||
            jsonb_build_object('manifest_count_gap', :gap, 'manifest_entries', :entries,
                               'extraction_reported', :reported, 'coverage_limited', true,
                               'reconciliation_status', :direction),
            updated_at=NOW() WHERE job_id=:jid AND stage='materialize'""",
            {"jid": job_id, "gap": manifest_gap, "entries": expected,
             "reported": extracted_count, "direction": direction})
        db.commit()
    # Every extracted file enters inventory. Unsupported/no-text files are
    # explicit stage exceptions, never discarded by hash or path filters.
    # V1.10.9: one pass. Each row is inserted with its provenance (extracted part)
    # and its parse-queue decision (forensic -> pending; media / noise / oversized
    # EVTX -> skipped, media routed to OCR). Before, every row was inserted, then
    # UPDATEd again for provenance, and native parsing re-filtered all rows.
    def _provenance(entry: dict) -> dict:
        return {
            "serial_materialized": True,
            "extracted_part_uri": entry["part_uri"],
            "extracted_part_id": entry.get("part_id"),
            "extracted_part_offset": entry.get("offset"),
            "source_sha256": entry.get("sha256"),
            "source_path": entry.get("source_path") or entry.get("path"),
            **({"copy_ordinal": int(entry["copy_ordinal"])} if entry.get("copy_ordinal") else {}),
        }

    result = materialize_index_entries(
        db,
        job_id,
        entries,
        update_status=True,
        phase1_filter=False,
        classify_parse_queue=True,
        extra_metadata=_provenance,
    )
    db.commit()
    try:  # bookkeeping only; never fail registration over it
        execute(
            db,
            """UPDATE pipeline_stage_runs SET details=coalesce(details,'{}'::jsonb) ||
               jsonb_build_object('parse_queue_classified', true,
                                  'parse_pending', CAST(:pending AS bigint),
                                  'parse_skipped_at_registration', CAST(:skipped AS bigint)),
               updated_at=NOW() WHERE job_id=:jid AND stage='materialize'""",
            {"jid": job_id, "pending": int(result.get("parse_pending") or 0),
             "skipped": int(result.get("parse_skipped_at_registration") or 0)},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    report_progress(
        db,
        job_id,
        "materialize",
        total=expected,
        completed=expected,
        label="Registering all extracted evidence with provenance",
    )
    from app.services.mobile_forensic.key_intake import capture_registered_keys, is_whatsapp_key_path
    if any(is_whatsapp_key_path(entry.get("source_path") or entry["path"]) for entry in entries):
        capture_registered_keys(db, job_id)
        db.commit()
    # Platform-aware WhatsApp preparation is part of materialization, before
    # native parsers run. The gate is non-fatal when a key is missing: it
    # preserves the encrypted source, reports key_required, and lets unrelated
    # mobile evidence continue.
    from app.services.mobile_forensic.whatsapp_evidence_gate import prepare_whatsapp_evidence
    whatsapp_gate = prepare_whatsapp_evidence(
        db, job_id,
        progress=lambda done, total, details: report_progress(
            db, job_id, "materialize", total=expected + total, completed=expected + done,
            label=(
                f"WhatsApp evidence preparation — {done} / {total}; "
                f"{details.get('blocked_files', 0)} blocked"
            ),
        ),
    )
    whatsapp = whatsapp_gate.get("decryption") or {
        "encrypted_files": int(whatsapp_gate.get("encrypted_files") or 0),
        "decrypted_files": 0,
        "blocked_files": int(whatsapp_gate.get("blocking_whatsapp_only") or 0),
        "derived_artifacts": 0, "cached_files": 0, "partial_files": 0,
        "state": whatsapp_gate.get("state"),
    }
    wa_total = int(whatsapp.get("encrypted_files") or 0)
    return {
        **result,
        "total": expected + wa_total,
        "completed": expected + wa_total,
        "expected_files": expected,
        "manifest_count_gap": manifest_gap,
        "coverage_limited": bool(manifest_gap),
        "whatsapp_evidence_gate": whatsapp_gate,
        "whatsapp_decryption": whatsapp,
    }


def _parse_shards_active(db, job_id) -> bool:
    """True while a V1.11.0 parse shard sidecar is queued or running for the job."""
    try:
        if not (fetchone(db, "SELECT to_regclass('pipeline_sidecar_runs') AS t") or {}).get("t"):
            return False
        row = fetchone(
            db,
            """SELECT count(*) AS c FROM pipeline_sidecar_runs
               WHERE job_id=:jid AND sidecar LIKE 'parse_shard_%' AND status IN ('queued','running')""",
            {"jid": job_id},
        ) or {}
        return int(row.get("c") or 0) > 0
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return True  # unsure: keep live claims rather than risk double parsing


def _parse(db, job_id, schema_name):
    from app.config import get_settings
    from app.services.artifact_parse import parse_job_artifacts_for_paths

    # V57: quality triage is a CPU sidecar. Start it with native parsing so poor
    # images/documents and sampled video frames enter the OCR bucket while parse
    # workers continue. GPU OCR itself is held until recovery starts.
    try:
        from app.tasks import quality_ocr_triage_task
        quality_ocr_triage_task.delay(schema_name, job_id)
        execute(
            db,
            """UPDATE pipeline_stage_runs SET details=coalesce(details,'{}'::jsonb) ||
               jsonb_build_object('quality_triage_started', true), updated_at=NOW()
               WHERE job_id=:jid AND stage='parse'""",
            {"jid": job_id},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    # The execution lock proves no other serial parse runner is alive. Claims
    # left by a killed worker may be reset immediately rather than wait 30 min.
    # V1.11.0: parse shards hold live claims (heartbeated while they work), so
    # while any shard is active only stale claims are returned to the queue;
    # resetting all of them would let two processes parse the same file.
    if _parse_shards_active(db, job_id):
        from app.services.artifact_parse import recover_stale_parsing_claims

        recover_stale_parsing_claims(db, job_id)
    else:
        execute(
            db,
            "UPDATE job_artifacts SET parse_status='pending' WHERE job_id=:jid AND parse_status='parsing'",
            {"jid": job_id},
        )
    db.commit()
    # V58 performance lane: prepare the evidence-focused parse queue once before
    # draining it. All extracted files remain registered/in inventory, but media,
    # cache/vendor noise and unsupported rows do not consume native parser CPU.
    # Quality triage still sees those rows independently and can route poor media
    # into OCR, so this is a scheduling optimisation rather than evidence loss.
    from app.services.artifact_parse import prepare_forensic_parse_queue
    prepare_forensic_parse_queue(db, job_id)
    db.commit()

    index_map = _index_map(db, job_id)
    index_stamp = ""
    total = int(
        fetchone(
            db,
            "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    previous_pending = None
    last_progress_at = time.monotonic()
    while True:
        row = fetchone(
            db,
            """SELECT count(*) FILTER (WHERE parse_status IN ('pending','parsing')) AS pending,
            count(*) FILTER (WHERE parse_status='parsed') AS done,
            count(*) FILTER (WHERE parse_status IN ('skipped','no_parser')) AS skipped,
        count(*) FILTER (WHERE parse_status IN ('failed','error')) AS failed,count(*) AS total
            FROM job_artifacts WHERE job_id=:jid""",
            {"jid": job_id},
        )
        total = int(row["total"])
        stamp_row = fetchone(
            db,
            "SELECT COALESCE(disk_source->>'index_uri','') AS index_uri FROM jobs WHERE id=:jid",
            {"jid": job_id},
        ) or {}
        stamp = str(stamp_row.get("index_uri") or "")
        if stamp and stamp != index_stamp:
            index_map = _index_map(db, job_id)
            index_stamp = stamp
        report_progress(
            db,
            job_id,
            "parse",
            total=total,
            completed=int(row["done"]),
            failed=int(row["failed"]),
            skipped=int(row["skipped"]),
            label="Native forensic parsing",
        )
        if int(row["pending"]) <= 0:
            return {
                "status": "ok",
                "total": total,
                "completed": int(row["done"]),
                "failed": int(row["failed"]),
                "skipped": int(row["skipped"]),
            }
        # V1.11.0: parallel parse shards (sidecars on the idle extraction
        # workers) drain the same queue. While they hold claims this loop may
        # find nothing to claim; that is progress elsewhere, so it waits briefly
        # instead of giving up after one quiet batch. Only a queue that has not
        # moved for PARSE_NO_PROGRESS_SEC becomes a resumable wait.
        pending_now = int(row["pending"])
        now = time.monotonic()
        if previous_pending is None or pending_now < previous_pending:
            previous_pending = pending_now
            last_progress_at = now
        elif now - last_progress_at > PARSE_NO_PROGRESS_SEC:
            raise StageWaiting(
                "Parsing made no progress; remaining evidence claims must finish"
            )
        from app.services.job_control import pipeline_should_stop

        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Parsing paused by user")
        shard_n = 0
        try:
            from app.services.safe_parallel import parse_shard_count

            shard_n = parse_shard_count()
        except Exception:
            shard_n = 0
        leave_parts = shard_n > 1 and _parse_shards_active(db, job_id)
        batch = parse_job_artifacts_for_paths(
            db,
            job_id,
            paths=None,
            index_map=index_map,
            batch_limit=max(100, int(get_settings().parse_drain_batch_limit or 500)),
            update_status=False,
            forensic_only=True,
            queue_prepared=True,
            defer_part_buckets=shard_n if leave_parts else 0,
        ) or {}
        db.commit()
        if not int(batch.get("parsed") or 0) and not int(batch.get("skipped") or 0):
            # Everything still pending is claimed by a parse shard right now.
            time.sleep(PARSE_SHARD_WAIT_SEC)


def _recovery(db, job_id):
    # V57: recovery and GPU OCR are independent resource lanes. Recovery stays
    # CPU/I/O-bound while the dedicated CUDA OCR worker consumes the bucket that
    # quality triage filled during native parsing. This is safe for Disk/Android/iOS
    # because both write idempotent per-artifact state and use separate workers.
    try:
        from app.services.ocr_gpu import count_pending_ocr, dispatch_ocr_agent
        from app.tasks import quality_ocr_triage_task

        quality_ocr_triage_task.delay(str(getattr(db, "info", {}).get("firm_schema") or ""), job_id)
        pending_ocr = int(count_pending_ocr(db, job_id) or 0)
        done_row = fetchone(db, "SELECT count(*)::int AS c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'", {"jid": job_id})
        done_ocr = int((done_row or {}).get("c") or 0)
        execute(
            db,
            """UPDATE pipeline_stage_runs SET details=coalesce(details,'{}'::jsonb) || CAST(:d AS jsonb), updated_at=NOW()
               WHERE job_id=:jid AND stage='ocr'""",
            {"jid": job_id, "d": json.dumps({
                "parallel_active": pending_ocr > 0,
                "parallel_complete": pending_ocr == 0,
                "parallel_with": "recovery",
                "parallel_completed": done_ocr if (done_ocr or pending_ocr) else 1,
                "parallel_total": max(done_ocr + pending_ocr, 1),
                "parallel_label": f"GPU OCR running with recovery — {done_ocr:,} done, {pending_ocr:,} pending" if pending_ocr else "GPU OCR bucket currently empty",
            })},
        )
        db.commit()
        if pending_ocr > 0:
            schema = str(getattr(db, "info", {}).get("firm_schema") or "")
            if schema:
                dispatch_ocr_agent(schema, job_id)
    except Exception as exc:
        try:
            db.rollback()
            from app.services.forensic_serial_pipeline import write_disk_log
            write_disk_log(db, job_id, f"OCR early dispatch deferred: {type(exc).__name__}: {exc}",
                           stage="ocr", level="warning")
            db.commit()
        except Exception:
            db.rollback()
        # The serial OCR stage remains authoritative and will retry eligibility
        # and dispatch. Failure of this speculative sidecar is never completion.

    # Disk filesystem-level recovery remains in the one-time image acquisition.
    # This stage analyzes derived deleted files and preserves those source flags.
    from app.services.deleted_evidence import detect_deleted_path_hint

    from psycopg2.extras import execute_values

    last = NIL_ID
    tagged = total = 0
    recovery_batch = 5000
    while True:
        # V1.11.0: rows registered by the serial registration stage already
        # carry the path-based deleted/trash hint (detect_deleted_path_hint runs
        # for every row while registering), so they are not re-read and
        # re-written here. Only rows registered by older/other paths are analysed.
        rows = fetchall(
            db,
            """SELECT id,file_path,metadata FROM job_artifacts
            WHERE job_id=:jid AND id>:last
              AND coalesce(metadata->>'serial_materialized','false') <> 'true'
            ORDER BY id LIMIT :lim""",
            {"jid": job_id, "last": last, "lim": recovery_batch},
        )
        if not rows:
            break
        updates = []
        for row in rows:
            hint = detect_deleted_path_hint(row["file_path"])
            if hint:
                updates.append((str(row["id"]), json.dumps(hint)))
        if updates:
            ordered_updates = sorted(updates, key=lambda item: item[0])

            def _write_recovery_hints() -> None:
                lock_job_artifacts_in_id_order(db, [item[0] for item in ordered_updates])
                with db.connection().connection.cursor() as cur:
                    execute_values(
                        cur,
                        """UPDATE job_artifacts AS ja
                           SET metadata=v.hint::jsonb || COALESCE(ja.metadata,'{}'::jsonb), updated_at=NOW()
                           FROM (VALUES %s) AS v(id,hint)
                           WHERE ja.id=v.id::uuid""",
                        ordered_updates,
                        page_size=1000,
                    )
                db.commit()

            retry_on_deadlock(db, _write_recovery_hints)
            tagged += len(updates)
        total += len(rows)
        last = str(rows[-1]["id"])
        report_progress(
            db,
            job_id,
            "recovery",
            total=total,
            completed=total,
            label="Analyzing extracted deleted/recovered evidence",
        )
    registered = fetchone(
        db,
        """SELECT count(*) AS total,
                  count(*) FILTER (WHERE coalesce(metadata->>'is_deleted','false')='true') AS deleted
             FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    ) or {}
    all_rows = int(registered.get("total") or 0)
    report_progress(db, job_id, "recovery", total=all_rows, completed=all_rows,
                    label="Deleted / recovery analysis (applied while registering)")
    return {
        "status": "ok",
        "total": all_rows,
        "completed": all_rows,
        "analysed_now": total,
        "analysed_at_registration": max(all_rows - total, 0),
        "deleted_sources_tagged": tagged,
        "deleted_sources_total": int(registered.get("deleted") or 0),
        "scope": "derived_evidence; filesystem recovery is performed during extraction",
    }


def _try_quality_batch(db, job_id, limit: int = 1600):
    """Classify one batch when the quality sidecar is idle.

    A busy sidecar owns the quality lock. Tesseract must keep reading the
    files already marked poor instead of waiting on that lock.
    """
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.mobile_quality_ocr import route_forensic_quality_to_ocr

    try:
        return route_forensic_quality_to_ocr(db, job_id, limit=limit, dispatch=False)
    except StageWaiting:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _quality_unchecked(db, job_id) -> int:
    row = fetchone(
        db,
        """SELECT count(*)::int AS c FROM job_artifacts
           WHERE job_id=:jid
             AND lower(CASE WHEN left(coalesce(extension,''),1)='.' THEN extension
                            ELSE '.'||coalesce(extension,'') END) = ANY(:exts)
             AND coalesce(metadata->>'ocr_quality_checked','false') <> 'true'""",
        {
            "jid": job_id,
            "exts": [
                ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp",
                ".heic", ".heif", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v",
                ".pdf", ".doc", ".docx", ".rtf", ".odt", ".ppt", ".pptx", ".xls", ".xlsx",
            ],
        },
    )
    return int((row or {}).get("c") or 0)


def _ocr(db, job_id, schema_name):
    from app.config import get_settings
    from app.services.ocr_gpu import (
        count_pending_ocr,
        enqueue_eligible_ocr,
        run_ocr_for_job,
        unload_glm_ocr,
    )
    from app.services.tar_cache import read_file_from_part

    if not get_settings().ocr_enabled:
        return {"status": "skipped", "reason": "ocr_disabled"}
    from app.services.ocr_gpu import selected_ocr_engine

    fast_ocr = selected_ocr_engine() == "tesseract"
    if fast_ocr:
        # The quality sidecar already classifies poor files. Waiting on its lock
        # left Tesseract idle at 99% while the bucket sat unread.
        _try_quality_batch(db, job_id)
    else:
        # GLM must not scan every readable photo. Finish the quality gate first.
        try:
            from app.services.mobile_quality_ocr import route_forensic_quality_to_ocr
            while True:
                triage = route_forensic_quality_to_ocr(db, job_id, limit=1600, dispatch=False)
                if int(triage.get("checked") or 0) < 1600:
                    break
        except Exception as exc:
            db.rollback()
            raise StageWaiting("OCR quality triage has not completed: " + str(exc)) from exc
    index_map = _index_map(db, job_id)
    enqueue_eligible_ocr(db, job_id)
    db.commit()
    before = count_pending_ocr(db, job_id)
    if before <= 0 and (not fast_ocr or _quality_unchecked(db, job_id) <= 0):
        return {"status": "ok", "total": 0, "completed": 0}

    def read(path):
        norm = str(path).replace("\\", "/")
        uri = index_map.get(norm) or index_map.get(path)
        if uri:
            return read_file_from_part(uri, norm)
        if "/whatsapp_decrypted/" in ("/" + norm.lower()):
            from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes
            return _read_artifact_bytes(db, job_id, path, max_bytes=768_000_000)
        return None

    def iter_grouped(paths, on_progress=None):
        """One streaming pass per archive part, instead of one pass per file."""
        from collections import defaultdict

        from app.services.tar_cache import iter_files_from_part

        groups = defaultdict(set)
        loose = []
        for path in paths:
            norm = str(path).replace("\\", "/")
            uri = index_map.get(norm) or index_map.get(path)
            if uri:
                groups[uri].add(norm)
            else:
                loose.append(path)
        for uri, wanted in groups.items():
            for norm, content in iter_files_from_part(uri, wanted, on_progress=on_progress):
                yield norm, content
        for path in loose:
            try:
                yield path, read(path)
            except Exception:
                yield path, None

    read.iter_grouped = iter_grouped

    from app.services.embedding_gpu import resolve_device
    from app.services.job_control import pipeline_should_stop
    from app.services.job_locks import gpu_heavy_slot

    _device, gpu = resolve_device("cuda")
    with ExitStack() as stack:
        if gpu and not fast_ocr:
            stack.enter_context(gpu_heavy_slot("serial_ocr", fail_closed=True))
            # Keep one GLM resident across all batches and unload BEFORE returning
            # the GPU permit. Vision review starts after OCR releases its model.
            stack.callback(unload_glm_ocr)
        result = {}
        while True:
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("OCR paused by user")
            pending = count_pending_ocr(db, job_id)
            if pending <= 0:
                if not fast_ocr or _quality_unchecked(db, job_id) <= 0:
                    break
                batch = _try_quality_batch(db, job_id)
                enqueue_eligible_ocr(db, job_id)
                db.commit()
                if count_pending_ocr(db, job_id) > 0:
                    continue
                if batch is None:
                    from app.services.progress_agent import note_operation
                    note_operation(
                        db,
                        job_id,
                        "ocr",
                        "Tesseract OCR is waiting for the next poor-quality batch",
                        advanced=True,
                    )
                    import time
                    time.sleep(2)
                    continue
                if int(batch.get("checked") or 0) == 0 or _quality_unchecked(db, job_id) <= 0:
                    break
                continue
            db.commit()
            result = run_ocr_for_job(
                db,
                job_id,
                schema_name=schema_name,
                read_file_fn=read,
                gpu_permit_owned=gpu,
            )
            after = count_pending_ocr(db, job_id)
            done_n = int(
                (fetchone(
                    db,
                    "SELECT count(*)::int AS c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'",
                    {"jid": job_id},
                ) or {}).get("c") or 0
            )
            report_progress(
                db,
                job_id,
                "ocr",
                total=done_n + after,
                completed=done_n,
                label="Tesseract OCR" if fast_ocr else "OCR on CUDA",
            )
            if after > 0 and int(result.get("ocr_count") or 0) <= 0 and (
                after >= pending or result.get("gpu_deferred")
            ):
                raise StageWaiting(
                    f"OCR barrier: {after:,} documents remaining"
                    + ("; CUDA worker required" if result.get("gpu_deferred") else "")
                )
    counts = fetchone(
        db,
        """SELECT count(*) FILTER (WHERE ocr_status='done') AS done,
        count(*) FILTER (WHERE ocr_status='failed') AS failed,count(*) FILTER (WHERE ocr_status='skipped') AS skipped
        FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    return {
        **result,
        "total": sum(int(v) for v in counts.values()),
        "completed": int(counts["done"]),
        "failed": int(counts["failed"]),
        "skipped": int(counts["skipped"]),
    }


def _full_text_chunks(rows):
    """Chunk full parsed/OCR text, keeping every parser output and source link."""
    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_SIZE, CHUNK_POLICY

    output = []
    for row in rows:
        from app.services.rag_text import extract_text_from_normalized
        norm = row.get("normalized")
        body = extract_text_from_normalized(norm)
        ocr = str(row.get("ocr_text") or "")
        bnorm = " ".join(body.split())
        onorm = " ".join(ocr.split())
        if bnorm and onorm and (onorm in bnorm or bnorm in onorm):
            ocr = ""
        description = json.dumps(row.get("media_review") or {}, ensure_ascii=False) if row.get("media_review") else ""
        review_description = str(row.get('suspicious_activity_description') or '')
        text = (body + "\n" + ocr + "\n" + description+'\n'+review_description).replace("\x00", "").strip()
        if text:
            text = f"Evidence file {row['file_path']}\n{text}"
        for idx, chunk in enumerate(
            _chunk_text(text, CHUNK_SIZE, CHUNK_OVERLAP)
        ):
            output.append(
                (
                    str(row["id"]),
                    row["file_path"],
                    idx,
                    chunk,
                    row.get("encyclopedia_artifact_id"),
                )
            )
    return output


def _chunk(db, job_id, *, mobile=False):
    from psycopg2.extras import execute_values
    from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_SIZE, CHUNK_POLICY

    last = NIL_ID
    total = int(
        fetchone(
            db,
            "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    done = int(
        fetchone(
            db,
            f"""SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunked'='true' AND {chunk_policy_accepted_sql()}""",
            {"jid": job_id},
        )["c"]
    )
    from app.services.job_control import pipeline_should_stop

    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("RAG chunking paused by user")
        rows = fetchall(
            db,
            f"""SELECT ja.id,ja.file_path,ja.encyclopedia_artifact_id,
            apr.normalized,ocr.ocr_text,ja.metadata->'media_review' AS media_review,
            ja.metadata->>'suspicious_activity_description' AS suspicious_activity_description FROM job_artifacts ja
            LEFT JOIN LATERAL (SELECT a.normalized FROM artifact_parse_results a
                WHERE a.job_artifact_id=ja.id ORDER BY a.created_at DESC LIMIT 1) apr ON true
            LEFT JOIN LATERAL (SELECT string_agg(o.text, E'\n' ORDER BY o.page_index) AS ocr_text
                FROM (SELECT DISTINCT ON (o.page_index) o.page_index,o.ocr_text AS text
                      FROM ocr_results o WHERE o.job_artifact_id=ja.id
                      ORDER BY o.page_index,o.created_at DESC) o) ocr ON true
            WHERE ja.job_id=:jid AND ja.id>:last
            AND NOT (COALESCE(ja.metadata->>'serial_chunked','false')='true' AND {chunk_policy_accepted_sql("COALESCE(ja.metadata->>'serial_chunk_policy','')")})
            ORDER BY ja.id LIMIT :rag_batch""",
            {"jid": job_id, "last": last, "rag_batch": RAG_CHUNK_DB_BATCH},
        )
        if not rows:
            break
        rows = [dict(row) for row in rows]
        db.commit()
        paths = [r["file_path"] for r in rows]
        # Pure text chunk generation is CPU-only and carries no DB/CUDA handles.
        # Run it in independent processes while keeping persistence in this one
        # authoritative stage writer so parallel workers cannot interleave DB writes.
        from app.services.forensic_serial_policy import parallelism
        partitions = max(1, min(parallelism(), len(rows)))
        chunks = []
        for out in bounded_process_map(_full_text_chunks, (rows[i::partitions] for i in range(partitions))):
            chunks.extend(out)
        ids = [str(row["id"]) for row in rows]
        with_text = {chunk[0] for chunk in chunks}
        no_text = [artifact_id for artifact_id in ids if artifact_id not in with_text]
        chunk_values = [
            (
                job_id,
                path,
                idx,
                content,
                aid,
                json.dumps(
                    {"job_artifact_id": artifact_id, "serial_pipeline": True, "chunk_policy": CHUNK_POLICY}
                ),
            )
            for artifact_id, path, idx, content, aid in chunks
        ]

        def _persist_chunks() -> None:
            execute(
                db,
                """DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths)
                AND chunk_type IN ('evidence','evidence_skip')""",
                {"jid": job_id, "paths": paths},
            )
            if chunk_values:
                with db.connection().connection.cursor() as cur:
                    execute_values(
                        cur,
                        """INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,artifact_id,chunk_type,metadata)
                        VALUES %s""",
                        chunk_values,
                        template="(%s,%s,%s,%s,%s,'evidence',%s::jsonb)",
                        page_size=500,
                    )
            lock_job_artifacts_in_id_order(db, ids)
            execute(
                db,
                """UPDATE job_artifacts SET metadata=COALESCE(metadata,'{}'::jsonb) ||
                jsonb_build_object('serial_chunked',true,'serial_chunk_policy',CAST(:policy AS text),'serial_chunk_status',
                    CASE WHEN id=ANY(CAST(:no_text AS uuid[])) THEN 'no_text' ELSE 'text' END)
                WHERE id=ANY(CAST(:ids AS uuid[]))""",
                {"ids": ids, "no_text": no_text, "policy": CHUNK_POLICY},
            )
            db.commit()

        retry_on_deadlock(db, _persist_chunks)
        done += len(rows)
        last = str(rows[-1]["id"])
        report_progress(
            db,
            job_id,
            "chunk",
            total=total,
            completed=done,
            label="RAG chunking of complete parsed and OCR evidence",
        )
    if mobile:
        from app.services.mobile_forensic.mobile_rag import (
            index_mobile_artifacts_for_rag,
        )

        mobile_chunks = index_mobile_artifacts_for_rag(
            db, job_id, embed=False, strict=True
        )
        db.commit()
    else:
        mobile_chunks = {}
        from app.services.forensic_profile_index import (
            ensure_os_fact_chunks,
            ensure_profile_fact_chunks,
        )

        # Synthetic facts consume parsed results only, never reopen the source image.
        ensure_profile_fact_chunks(db, job_id, refresh_critical=False)
        ensure_os_fact_chunks(db, job_id, refresh_hives=False)
        db.commit()
    skipped = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunk_status'='no_text'""",
            {"jid": job_id},
        )["c"]
    )
    # Disk priority re-parsing is retired. Native parsing and normal RAG
    # chunks remain the sole mandatory disk text indexing pipeline.
    return {
        "status": "ok",
        "chunk_size": CHUNK_SIZE,
        "chunk_overlap": CHUNK_OVERLAP,
        "embedding_enabled": False,
        "total": total,
        "completed": max(done - skipped, 0),
        "skipped": skipped,
        "skip_reason": "No parsed or OCR text" if skipped else None,
        "mobile": mobile_chunks,
    }


def execute_stage(db, job_id, stage, *, schema_name, stage_run_id):
    from app.forensic_common.job_types import is_mobile_job

    mobile = is_mobile_job(db, job_id)
    if stage == "materialize":
        return _materialize_full(db, job_id)
    if stage == "parse":
        result = _parse(db, job_id, schema_name)
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            execute(
                db,
                "UPDATE pipeline_stage_runs SET details=CAST(:details AS jsonb) WHERE id=:sid",
                {
                    "sid": stage_run_id,
                    "details": json.dumps(
                        {
                            "mobile_work_active": True,
                            "native_total": result["total"],
                            "native_completed": result["completed"]
                            + result["skipped"]
                            + result["failed"],
                        }
                    ),
                },
            )
            db.commit()
            result["mobile"] = run_mobile_stage(
                db, job_id, "parse", schema_name=schema_name, stage_run_id=stage_run_id
            )
            # Keep the stage denominator on the extracted file count. The mobile
            # pass reparses those same files; adding its bundle count doubled the card.
            result["native_total"] = int(result["total"])
            result["mobile_work_active"] = True
        return result
    if stage == "recovery":
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            return run_mobile_stage(
                db,
                job_id,
                "recovery",
                schema_name=schema_name,
                stage_run_id=stage_run_id,
            )
        return _recovery(db, job_id)
    if stage == "ocr":
        return _ocr(db, job_id, schema_name)
    if stage == "inventory":
        from app.services.process_completion import assert_no_active_producers
        assert_no_active_producers(db, job_id, exclude_stage="inventory")
        if mobile:
            from app.services.forensic_serial_mobile import run_mobile_stage

            run_mobile_stage(
                db,
                job_id,
                "normalize",
                schema_name=schema_name,
                stage_run_id=stage_run_id,
            )
        from app.services.catalog_artifact_runner import run_axiom_artifact_inventory

        result = run_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
        from app.services.suspicious_activity import collect_suspicious_activity
        result['suspicious_activity'] = collect_suspicious_activity(db, job_id)
        # Final incremental pass makes leakage artifacts complete after OCR/media
        # outputs arrived.  Earlier sidecar passes are reused via content-version
        # checkpoints, so this normally scans only the delta.
        try:
            from app.services.company_leakage import run_company_leakage_analysis
            result['company_leakage'] = run_company_leakage_analysis(db, job_id, batch_size=1000)
        except Exception as exc:
            result['company_leakage'] = {'status':'deferred','error':str(exc)[:300]}
        return result
    if stage == "chunk":
        from app.services.process_completion import assert_no_active_producers
        assert_no_active_producers(db, job_id, exclude_stage="chunk")
        return _chunk(db, job_id, mobile=mobile)
    if stage == "media_review":
        from app.services.forensic_media_review import run_media_review

        return run_media_review(db, job_id, schema_name=schema_name)
    if stage == "enrichment" and not mobile:
        from app.services.processing_profile import is_standard

        if is_standard(db, job_id):
            # Standard: entity-mention counters are UI statistics only (no report,
            # retrieval or validation consumer) and the full-text regex pass over
            # every parse result costs minutes. Semantic vectors are not built in
            # Standard (lexical/FTS retrieval is deterministic); the limitation is
            # recorded by validation. Ontology mapping is a single indexed count.
            ontology = int((fetchone(
                db,
                """SELECT count(*) AS c FROM job_artifacts
                   WHERE job_id=:jid AND encyclopedia_artifact_id IS NOT NULL""",
                {"jid": job_id},
            ) or {}).get("c") or 0)
            return {
                "status": "ok",
                "total": 1,
                "completed": 1,
                "processing_profile": "standard",
                "ontology_mapped": ontology,
                "entity_statistics": "not computed (Standard profile)",
                "vector_index": {"status": "not_built", "reason": "Standard profile"},
            }
    if stage == "enrichment":
        from app.services.rag_enrich import run_rag_enrichment_until_complete

        def on_batch(stats):
            from app.services.job_control import pipeline_should_stop

            report_progress(
                db,
                job_id,
                "enrichment",
                total=int(stats.get("parse_total") or 0),
                completed=int(stats.get("scanned") or 0),
                label="Full evidence entity / ontology enrichment",
            )
            if pipeline_should_stop(db, job_id):
                raise StageWaiting("Enrichment paused by user")

        result = run_rag_enrichment_until_complete(db, job_id, on_batch=on_batch)
        if not result.get("complete"):
            raise StageWaiting("Enrichment has more evidence batches to process")
        if mobile:
            result = _enrich_mobile(db, job_id, result)
        else:
            result = _enrich_mobile(db, job_id, result, table="forensic_priority_records", prefix="priority")
            # The GPU sidecar updates NULL vectors in-place and never rebuilds
            # or deletes source-linked chunks. Graph CPU work can continue.
            from app.services.disk_vector_sidecar import schedule_disk_vectors
            result["vector_index"] = schedule_disk_vectors(
                db, job_id, schema_name=schema_name)
        return {
            "status": "ok",
            **result,
            "total": result.get("parse_total", 0),
            "completed": result.get("scanned", 0),
        }
    if stage == "graph":
        from app.services.processing_profile import STANDARD_SKIPPED_STAGES, is_standard

        if not mobile and is_standard(db, job_id):
            return {
                "status": "skipped",
                "processing_profile": "standard",
                "reason": STANDARD_SKIPPED_STAGES["graph"],
                "total": 0,
                "completed": 0,
                "skipped": 0,
            }
        from app.services.neo4j_sync import sync_job_graph_serial

        result = sync_job_graph_serial(
            db, job_id, schema_name=schema_name, mobile=mobile
        )
        if result.get("status") != "ok":
            raise StageWaiting(
                "Graph synchronization unavailable; graph barrier remains pending"
            )
        return result
    if stage == "validation":
        result = _validate_complete(db, job_id, mobile=mobile)
        if mobile:
            from app.services.forensic_serial_mobile import complete_mobile_analysis

            complete_mobile_analysis(db, job_id, result)
        return result
    raise ValueError(f"Unknown forensic stage: {stage}")


def _enrich_mobile(db, job_id, stats, *, table="mobile_normalized_artifacts", prefix="mobile"):
    """Scan all normalized mobile records with a resumable keyset cursor."""
    from app.services.job_control import pipeline_should_stop
    from app.services.rag_enrich import _SQL_COUNT_RES, persist_enrichment_stats

    total = int(
        fetchone(
            db,
            f"SELECT count(*) AS c FROM {table} WHERE job_id=:jid",
            {"jid": job_id},
        )["c"]
    )
    stats = dict(stats)
    last = stats.get(prefix+"_last_artifact_id") or ""
    scanned = int(stats.get(prefix+"_scanned") or 0)
    by_type = dict(stats.get(prefix+"_entity_by_type") or {})
    columns = ",".join(
        f"COALESCE(SUM(regexp_count(sample, :{kind}_re, 1, 'i')),0) AS {kind}_n"
        for kind in _SQL_COUNT_RES
    )
    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Mobile enrichment paused by user")
        params = {
            "jid": job_id,
            "last": last,
            **{f"{kind}_re": pattern for kind, pattern in _SQL_COUNT_RES.items()},
        }
        row = fetchone(
            db,
            f"""WITH batch AS (SELECT artifact_id,data::text AS sample
            FROM {table} WHERE job_id=:jid AND artifact_id>:last ORDER BY artifact_id LIMIT 500)
            SELECT (SELECT artifact_id FROM batch ORDER BY artifact_id DESC LIMIT 1) AS last_id,
                count(*) AS scanned,{columns} FROM batch""",
            params,
        )
        count = int(row["scanned"])
        if count:
            last = row["last_id"]
            scanned += count
            for kind in _SQL_COUNT_RES:
                by_type[kind] = int(by_type.get(kind) or 0) + int(row[f"{kind}_n"])
        stats.update(
            {
                prefix+"_scanned": scanned,
                prefix+"_total": total,
                prefix+"_last_artifact_id": last,
                prefix+"_entity_by_type": by_type,
                prefix+"_complete": not count or scanned >= total,
            }
        )
        persist_enrichment_stats(db, job_id, stats)
        report_progress(
            db,
            job_id,
            "enrichment",
            total=int(stats.get("parse_total") or 0) + total,
            completed=int(stats.get("scanned") or 0) + scanned,
            label=f"Full normalized {prefix} evidence enrichment",
        )
        if stats[prefix+"_complete"]:
            return {
                **stats,
                "parse_total": int(stats.get("parse_total") or 0) + total,
                "scanned": int(stats.get("scanned") or 0) + scanned,
            }


def validate_stage_barrier(db, job_id, stage, result, *, stage_run_id):
    if result.get("status") in {"failed", "error"}:
        raise RuntimeError(
            f"{stage} failed: {result.get('reason') or result.get('error') or result['status']}"
        )
    if result.get("status") in {
        "partial",
        "held",
        "deferred",
        "waiting",
        "retry",
        "paused",
        "stopped",
    }:
        raise StageWaiting(
            f"{stage} barrier: {result.get('reason') or result.get('error') or result['status']}"
        )
    total = int(result.get("total") or 0)
    accounted = sum(int(result.get(k) or 0) for k in ("completed", "failed", "skipped"))
    if total < 0 or accounted < 0 or any(int(result.get(k) or 0) < 0 for k in ("completed", "failed", "skipped")):
        raise RuntimeError(f"{stage} returned invalid counters")
    if result.get("status") != "skipped" and accounted != total:
        raise StageWaiting(f"{stage} barrier: {accounted:,} / {total:,} work units accounted for")
    if stage == "media_review" and result.get("status") != "skipped":
        if int(result.get("completed") or 0)+int(result.get("failed") or 0)+int(result.get("skipped") or 0)<int(result.get("total") or 0):
            raise StageWaiting("Media observations have unfinished evidence files")
    if stage == "materialize":
        registered = int(
            fetchone(
                db,
                """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
            AND metadata->>'serial_materialized'='true'""",
                {"jid": job_id},
            )["c"]
        )
        if registered < int(result.get("expected_files") or result.get("total") or 0):
            raise StageWaiting("Materialization has unregistered extracted evidence")
    if stage == "parse":
        pending = fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts
            WHERE job_id=:jid AND parse_status IN ('pending','parsing')""",
            {"jid": job_id},
        )["c"]
        if pending:
            raise StageWaiting(f"Parse barrier: {pending:,} evidence files unfinished")
    if stage == "ocr":
        from app.services.ocr_gpu import count_pending_ocr

        if count_pending_ocr(db, job_id) and result.get("status") != "skipped":
            raise StageWaiting("OCR still has pending evidence")
    if stage == "inventory" and (result.get("company_leakage") or {}).get("status") in {"deferred", "failed", "error"}:
        raise StageWaiting("Company information analysis has not finished; final inventory cannot be sealed")
    if stage == "inventory" and not result.get("done"):
        raise StageWaiting("Artifact inventory is unfinished")
    if stage == "chunk":
        pending = fetchone(
            db,
            f"""SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
            AND NOT (COALESCE(metadata->>'serial_chunked','false')='true' AND {chunk_policy_accepted_sql()})""",
            {"jid": job_id},
        )["c"]
        if pending:
            raise StageWaiting(f"Chunk barrier: {pending:,} evidence files unfinished")
        if result.get("mobile"):
            if result["mobile"].get("status") != "ok":
                raise RuntimeError("Normalized mobile chunking did not complete")
            pending_mobile = int(
                fetchone(
                    db,
                    f"""SELECT count(*) AS c FROM mobile_normalized_artifacts m
                WHERE m.job_id=:jid AND m.artifact_id NOT IN (
                    SELECT rc.metadata->>'mobile_artifact_id' FROM rag_chunks rc
                    WHERE rc.job_id=:jid AND rc.metadata->>'mobile_artifact_id' IS NOT NULL
                      AND rc.metadata->>'serial_pipeline'='true'
                      AND {chunk_policy_accepted_sql("COALESCE(rc.metadata->>'chunk_policy','')")})""",
                    {"jid": job_id},
                )["c"]
            )
            if pending_mobile:
                raise StageWaiting(
                    f"Chunk barrier: {pending_mobile:,} normalized mobile records unfinished"
                )
    pending = fetchone(
        db,
        """SELECT count(*) AS c FROM pipeline_work_items
        WHERE stage_run_id=:sid AND status IN ('pending','running')""",
        {"sid": stage_run_id},
    )["c"]
    if pending:
        raise StageWaiting(f"{stage} barrier: {pending:,} work units unfinished")


def _validate_complete(db, job_id, *, mobile=False):
    from app.services.catalog_artifact_runner import axiom_inventory_progress
    from app.services.forensic_serial_pipeline import (
        TERMINAL,
        extraction_barrier,
        stage_rows,
    )
    from app.services.ocr_gpu import count_pending_ocr

    row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
    ready, reason = extraction_barrier(row)
    if not ready:
        raise StageWaiting(reason)
    from app.services.process_completion import assert_no_active_producers
    assert_no_active_producers(db, job_id)
    registered = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_materialized'='true'""",
            {"jid": job_id},
        )["c"]
    )
    materialized = next(
        (r for r in stage_rows(db, job_id) if r["stage"] == "materialize"), {}
    )
    details = materialized.get("details") or {}
    expected = int(details.get("expected_files") or row.get("files_extracted") or 0)
    if registered < expected:
        raise StageWaiting(
            f"Completeness check found {expected - registered:,} unregistered extracted files"
        )
    if any(
        r["status"] not in TERMINAL
        for r in stage_rows(db, job_id)
        if r["stage"] != "validation"
    ):
        raise StageWaiting("A prior stage has not passed its barrier")
    pending = fetchone(
        db,
        """SELECT count(*) FILTER (WHERE parse_status IN ('pending','parsing')) AS parse_pending,
        count(*) FILTER (WHERE parse_status IN ('failed','error')) AS parse_failed,
        count(*) FILTER (WHERE parse_status IN ('skipped','no_parser')) AS parse_skipped,
        count(*) FILTER (WHERE ocr_status='failed') AS ocr_failed
        FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    ocr_skipped = any(
        r["stage"] == "ocr" and r["status"] == "skipped" for r in stage_rows(db, job_id)
    )
    if (
        pending["parse_pending"]
        or (count_pending_ocr(db, job_id) and not ocr_skipped)
        or not axiom_inventory_progress(db, job_id).get("done")
    ):
        raise StageWaiting(
            "Completeness check found pending parse, OCR or inventory work"
        )
    if mobile:
        missing_mobile = int(
            fetchone(
                db,
                f"""SELECT count(*) AS c FROM mobile_normalized_artifacts m
            WHERE m.job_id=:jid AND m.artifact_id NOT IN (
                SELECT rc.metadata->>'mobile_artifact_id' FROM rag_chunks rc
                WHERE rc.job_id=:jid AND rc.metadata->>'mobile_artifact_id' IS NOT NULL
                  AND rc.metadata->>'serial_pipeline'='true'
                  AND {chunk_policy_accepted_sql("COALESCE(rc.metadata->>'chunk_policy','')")})""",
                {"jid": job_id},
            )["c"]
        )
        if missing_mobile:
            raise StageWaiting(
                f"Completeness check found {missing_mobile:,} mobile records without chunks"
            )
    # Semantic coverage is a real barrier when GPU embeddings were requested.
    # A queued/running task is already covered by assert_no_active_producers;
    # additionally reject silent failed tasks with unembedded evidence rows.
    from app.services.processing_profile import STANDARD_LIMITATIONS, job_processing_profile

    profile = "mobile" if mobile else job_processing_profile(db, job_id)
    if not mobile and profile != "standard" and get_settings().rag_embedding_enabled:
        from app.services.disk_vector_sidecar import count_missing_serial_vectors
        missing_vectors = count_missing_serial_vectors(db, job_id)
        if missing_vectors:
            raise StageWaiting(
                f"Writing in: {missing_vectors:,} RAG chunks still require semantic vectors")
    from app.services.forensic_priority_evidence import priority_record_table
    table = priority_record_table(db, job_id)
    priority_exceptions = 0
    if table:
        priority_exceptions = int(fetchone(db, f"""SELECT count(*) AS c FROM {table} WHERE job_id=:jid
            AND (artifact_type IN ('priority_source_exception','web_storage_source')
                OR data->>'decrypt_failed'='true' OR (artifact_type='app_backup_encrypted' AND data->>'key_available'='false'))""", {"jid":job_id})["c"])
    media_failed = int(fetchone(db,"SELECT count(*) AS c FROM forensic_media_observations WHERE job_id=:jid AND status='failed'",{"jid":job_id})["c"])
    priority_gaps = 0
    coverage_table = fetchone(db,"SELECT to_regclass('mobile_coverage') AS name") if mobile else None
    if coverage_table and coverage_table.get("name"):
        priority_gaps = int(fetchone(db,"""SELECT count(*) AS c FROM mobile_coverage WHERE job_id=:jid
            AND coverage_key LIKE 'priority_%' AND status='acquisition_gap'""",{"jid":job_id})["c"])
    # Failed/skipped evidence is explicitly reported, never silently called complete coverage.
    ds = (
        json.loads(row["disk_source"])
        if isinstance(row.get("disk_source"), str)
        else row.get("disk_source") or {}
    )
    skipped = int(ds.get("files_skipped") or 0)
    work_failed = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM pipeline_work_items w
        JOIN pipeline_stage_runs s ON s.id=w.stage_run_id WHERE s.job_id=:jid AND w.status='failed'""",
            {"jid": job_id},
        )["c"]
    )
    no_text = int(
        fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid
        AND metadata->>'serial_chunk_status'='no_text'""",
            {"jid": job_id},
        )["c"]
    )
    result = {
        "status": "ok",
        "total": 1,
        "completed": 1,
        "exceptions": {
            **dict(pending),
            "mobile_work_failed": work_failed,
            "files_without_text": no_text,
            "media_review_failed":media_failed,
            "priority_source_exceptions":priority_exceptions,
            "priority_acquisition_gaps":priority_gaps,
        },
        "extraction_skipped": skipped,
        "ocr_disabled": ocr_skipped,
        "coverage_complete": not skipped
        and not work_failed
        and not ocr_skipped
        and not no_text
        and not media_failed
        and not priority_exceptions
        and not priority_gaps
        and not any(int(pending[k] or 0) for k in ("parse_failed", "ocr_failed")),
    }
    from app.services.source_coverage import collect_source_coverage
    result["source_coverage"] = collect_source_coverage(db, job_id, row=row,
        validation=result, processing_complete=True)
    result["processing_profile"] = profile
    if profile == "standard":
        result["profile_limitations"] = list(STANDARD_LIMITATIONS)
        result["coverage_complete"] = False
    result["acquired_processing_complete"] = True
    result["acquired_evidence_without_exceptions"] = result["coverage_complete"]
    result["coverage_complete"] = False  # Accessibility of the original device is unverified.
    return result


# V68 SQL contract used by RAG delta finalization:
# SELECT DISTINCT ON (o.page_index) o.page_index,o.text FROM ocr_results o ORDER BY o.page_index,o.created_at DESC
# SELECT a.normalized FROM artifact_parse_results a ORDER BY a.created_at DESC LIMIT 1
