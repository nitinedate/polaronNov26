"""Evidence-quality gate for mobile OCR routing.

Poor-quality images, scanned/poor documents, and poor sampled video frames are
identified while the mobile evidence filter/parse queue is prepared. Evidence
that needs OCR is marked in ``job_artifacts.metadata`` and put on the same
live OCR queue used by the GPU worker. Clear media stays out of OCR.
"""

from __future__ import annotations

import io
import json
import logging
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from app.db.sql_helpers import fetchall, lock_job_artifacts_in_id_order, retry_on_deadlock

log = logging.getLogger("mobile_quality_ocr")
OCR_QUALITY_POLICY = "v68-text-likelihood"

_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp", ".heic"}
_VIDEO_EXT = {".mp4", ".mov", ".m4v", ".3gp", ".avi", ".mkv", ".webm"}
_DOC_EXT = {".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx"}


def _normalized_text_is_usable(metadata: dict[str, Any] | None) -> bool:
    meta=metadata or {}
    text=str(meta.get('text') or meta.get('parsed_text') or meta.get('content') or '')
    text=' '.join(text.split())
    if len(text) < 80: return False
    printable=sum(1 for c in text if c.isprintable())/max(len(text),1)
    alpha=sum(1 for c in text if c.isalnum())/max(len(text),1)
    return printable >= 0.96 and alpha >= 0.35


def _quality_worker(payload: dict[str, Any]) -> dict[str, Any]:
    """Picklable CPU worker for image/document clarity checks."""
    path = str(payload.get("path") or "")
    ext = str(payload.get("ext") or "").lower()
    data = payload.get("data") or b""
    try:
        if ext in _IMAGE_EXT:
            from app.services.forensic_media_review import media_needs_ocr
            from app.services.ocr_gpu import cpu_prepare_ocr_item

            poor, score = media_needs_ocr(data)
            if not poor:
                return {"poor": False, "reason": "clear_image", "score": float(score), "ocr_quality_policy": OCR_QUALITY_POLICY}
            # Blur alone is not enough to justify GPU OCR. A poor photograph with
            # no text remains evidence, but it is not an OCR candidate.
            prep = cpu_prepare_ocr_item(data, path=path, max_pages=1, allow_photos=True)
            needs_text_ocr = str(prep.get("status") or "") == "needs_gpu"
            return {
                "poor": bool(needs_text_ocr),
                "reason": "poor_image" if needs_text_ocr else "poor_nontext_image",
                "score": float(score),
                "ocr_quality_policy": OCR_QUALITY_POLICY,
            }
        if ext in _DOC_EXT:
            from app.services.ocr_gpu import cpu_prepare_ocr_item

            prep = cpu_prepare_ocr_item(data, path=path, max_pages=4, allow_photos=True)
            status = str(prep.get("status") or "skip")
            if status == "needs_gpu":
                return {"poor": True, "reason": "poor_or_scanned_document", "score": None, "ocr_quality_policy": OCR_QUALITY_POLICY}
            return {
                "poor": False,
                "reason": "clear_or_text_document" if status == "cpu_done" else "document_no_ocr_needed",
                "score": None,
            }
    except Exception as exc:
        return {"poor": False, "reason": "quality_check_error", "error": str(exc)[:250], "score": None}
    return {"poor": False, "reason": "unsupported_quality_type", "score": None}


def _open_cpu_pool(workers: int):
    n = max(1, int(workers or 1))
    # Celery prefork workers are daemonic and cannot safely create child
    # processes. Use real processes whenever the host process allows it, and
    # threads as the safe fallback.
    if multiprocessing.current_process().daemon:
        return ThreadPoolExecutor(max_workers=n, thread_name_prefix="mobile-quality")
    try:
        return ProcessPoolExecutor(max_workers=n, mp_context=multiprocessing.get_context("spawn"))
    except Exception:
        return ThreadPoolExecutor(max_workers=n, thread_name_prefix="mobile-quality")


def _quality_workers(candidate_count: int) -> int:
    try:
        from app.services.forensic_serial_policy import parallelism

        requested = int(os.environ.get("MOBILE_QUALITY_CPU_WORKERS", "6") or 6)
        return parallelism(min(requested, max(candidate_count, 1)))
    except Exception:
        return max(1, min(int(os.environ.get("MOBILE_QUALITY_CPU_WORKERS", "6") or 6), max(candidate_count, 1)))


def _video_quality(db, job_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """Sample a bounded number of video frames and identify poor visual quality."""
    temp = None
    try:
        from itertools import islice
        from app.services.artifact_media_properties import _stream_to_temp
        from app.services.forensic_media_review import media_needs_ocr, video_frames

        ext = str(row.get("extension") or Path(str(row.get("file_path") or "")).suffix or ".mp4")
        temp = _stream_to_temp(db, job_id, row, ext, directory="/tmp")
        max_frames = max(1, int(os.environ.get("MOBILE_QUALITY_VIDEO_FRAMES", "4") or 4))
        scores: list[float] = []
        poor_count = 0
        for blob, _timing, _coverage in islice(video_frames(temp), max_frames):
            poor, score = media_needs_ocr(blob)
            scores.append(float(score))
            if poor:
                poor_count += 1
        required = max(1, (len(scores) + 1) // 2)
        poor = poor_count >= required
        return {
            "poor": poor,
            "reason": "poor_video_text_frames" if poor else "clear_video_frames",
            "ocr_quality_policy": OCR_QUALITY_POLICY,
            "score": min(scores) if scores else None,
            "sampled_frames": len(scores),
            "poor_frames": poor_count,
        }
    except Exception as exc:
        return {"poor": False, "reason": "video_quality_check_error", "error": str(exc)[:250], "score": None}
    finally:
        if temp:
            try:
                Path(temp).unlink(missing_ok=True)
            except Exception:
                pass




def _artifact_part_uri(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}
    return str(metadata.get("extracted_part_uri") or "")


def _video_quality_temp(path: str) -> dict[str, Any]:
    """Quality-check an already materialized video path (one shard pass)."""
    try:
        from itertools import islice
        from app.services.forensic_media_review import media_needs_ocr, video_frames

        max_frames = max(1, int(os.environ.get("MOBILE_QUALITY_VIDEO_FRAMES", "4") or 4))
        scores: list[float] = []
        poor_count = 0
        for blob, _timing, _coverage in islice(video_frames(path), max_frames):
            poor, score = media_needs_ocr(blob)
            scores.append(float(score))
            if poor:
                poor_count += 1
        required = max(1, (len(scores) + 1) // 2)
        poor = poor_count >= required
        return {
            "poor": poor,
            "reason": "poor_video_text_frames" if poor else "clear_video_frames",
            "ocr_quality_policy": OCR_QUALITY_POLICY,
            "score": min(scores) if scores else None,
            "sampled_frames": len(scores),
            "poor_frames": poor_count,
        }
    except Exception as exc:
        return {"poor": False, "reason": "video_quality_check_error", "error": str(exc)[:250], "score": None}

def route_forensic_quality_to_ocr(db, job_id, *, limit=None, dispatch=True):
    """Serialize quality producers across synchronous stages and queued sidecars."""
    from app.services.forensic_serial_pipeline import pipeline_execution_lock, StageWaiting
    schema = str(getattr(db, 'info', {}).get('firm_schema') or '')
    if not schema:
        raise StageWaiting('Quality triage requires a firm-scoped session')
    with pipeline_execution_lock(db, schema, 'quality:'+str(job_id)) as acquired:
        if not acquired:
            raise StageWaiting('Quality triage producer is still writing in')
        return _route_forensic_quality_to_ocr_impl(db, job_id, limit=limit, dispatch=dispatch)


def _route_forensic_quality_to_ocr_impl(
    db,
    job_id: str,
    *,
    limit: int | None = None,
    dispatch: bool = True,
) -> dict[str, int]:
    """Quality-check mobile evidence and route poor files to the live OCR bucket.

    The function is idempotent. Each artifact gets ``ocr_quality_checked=true``.
    If new poor files arrive after OCR previously reached 100%, they are changed
    to ``pending``; the existing OCR progress calculation then expands the total
    (done + pending), so percentage automatically falls below 100% until the new
    work finishes.
    """
    from app.services.ocr_gpu import is_ocr_noise_path

    batch = max(25, min(int(limit or os.environ.get("MOBILE_QUALITY_BATCH", "800") or 800), 2000))
    exts = sorted(_IMAGE_EXT | _VIDEO_EXT | _DOC_EXT)
    rows = fetchall(
        db,
        """SELECT ja.id, ja.file_path, ja.extension, ja.size_bytes, ja.sha256, ja.minio_uri, ja.metadata
           FROM job_artifacts ja
           WHERE ja.job_id=:jid
             AND coalesce(ja.ocr_status,'') <> 'done'
             AND lower(CASE WHEN left(coalesce(ja.extension,''),1)='.' THEN ja.extension ELSE '.'||coalesce(ja.extension,'') END) = ANY(:exts)
             AND coalesce(ja.metadata->>'ocr_quality_checked','false') <> 'true'
           ORDER BY coalesce(ja.metadata->>'extracted_part_uri','~'), ja.size_bytes ASC NULLS LAST, ja.id
           LIMIT :lim""",
        {"jid": job_id, "exts": exts, "lim": batch},
    )
    if not rows:
        return {"checked": 0, "queued": 0, "clear": 0, "errors": 0}

    # Remove known cache/vendor noise before spending CPU/GPU on quality checks.
    # Skips are written once, locked in id order. Row-by-row updates in path
    # order deadlocked with parse, which locks the same artifacts by id.
    candidates: list[dict[str, Any]] = []
    skips: list[tuple[str, str, str]] = []
    for row in rows:
        ext = str(row.get("extension") or Path(str(row.get("file_path") or "")).suffix).lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        meta=row.get("metadata") or {}
        if isinstance(meta,str):
            try: meta=json.loads(meta)
            except Exception: meta={}
        artifact_id = str(row["id"])
        if ext in _DOC_EXT and _normalized_text_is_usable(meta):
            skips.append((
                artifact_id,
                json.dumps({"ocr_quality_checked": True, "ocr_quality_bucket": False, "ocr_quality_reason": "native_text_readable"}),
                "native",
            ))
            continue
        if is_ocr_noise_path(str(row.get("file_path") or ""), size_bytes=int(row.get("size_bytes") or 0), extension=ext):
            skips.append((
                artifact_id,
                json.dumps({"ocr_quality_checked": True, "ocr_quality_bucket": False, "ocr_quality_reason": "known_noise"}),
                "noise",
            ))
            continue
        item = dict(row)
        item["_ext"] = ext
        candidates.append(item)

    def _write_quality_skips() -> None:
        if not skips:
            db.commit()
            return
        ordered = sorted(skips, key=lambda item: item[0])
        locked = set(lock_job_artifacts_in_id_order(db, [item[0] for item in ordered], skip_locked=True))
        ordered = [item for item in ordered if item[0] in locked]
        if not ordered:
            db.commit()
            return
        from psycopg2.extras import execute_values

        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """UPDATE job_artifacts AS ja
                   SET metadata=coalesce(ja.metadata,'{}'::jsonb) || v.meta::jsonb,
                       ocr_status=CASE
                           WHEN v.kind='native' AND coalesce(ja.ocr_status,'')='done' THEN ja.ocr_status
                           WHEN v.kind='native' THEN 'skipped'
                           WHEN v.kind='noise' AND ja.ocr_status='pending' THEN 'skipped'
                           ELSE ja.ocr_status
                       END,
                       updated_at=NOW()
                   FROM (VALUES %s) AS v(id, meta, kind)
                   WHERE ja.id=v.id::uuid""",
                ordered,
                page_size=500,
            )
        db.commit()

    retry_on_deadlock(db, _write_quality_skips)

    # V58: coalesce quality reads by extracted tar.zst shard. The old path
    # called _read_artifact_bytes() once per image/document, which can decompress
    # the same multi-GB shard hundreds of times. We now stream each shard once
    # per quality batch and fan the bytes to CPU workers. Videos from the same
    # shard are spilled in the same single pass for native ffmpeg sampling.
    from collections import defaultdict
    from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes
    from app.services.tar_cache import iter_files_from_part, iter_spilled_files_from_part

    cpu_payloads: list[dict[str, Any]] = []
    direct_rows: list[dict[str, Any]] = []
    pre_results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    part_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    max_read = int(os.environ.get("MOBILE_QUALITY_MAX_READ_BYTES", str(128 * 1024 * 1024)) or (128 * 1024 * 1024))

    for row in candidates:
        part_uri = _artifact_part_uri(row)
        if part_uri:
            part_rows[part_uri].append(row)
        else:
            direct_rows.append(row)

    # One decompression pass per shard for image/document quality inputs.
    for part_uri, grouped in part_rows.items():
        byte_rows = [r for r in grouped if r["_ext"] not in _VIDEO_EXT]
        if byte_rows:
            by_path = {str(r.get("file_path") or "").replace("\\", "/"): r for r in byte_rows}
            remaining = set(by_path)
            for norm, data in iter_files_from_part(part_uri, set(remaining), max_bytes=max_read):
                row = by_path.get(norm)
                if not row:
                    continue
                remaining.discard(norm)
                if data:
                    cpu_payloads.append({"row": row, "path": row.get("file_path"), "ext": row["_ext"], "data": data})
                else:
                    pre_results.append((row, {"poor": False, "reason": "unreadable_for_quality", "error": "no bytes"}))
            for norm in remaining:
                pre_results.append((by_path[norm], {"poor": False, "reason": "unreadable_for_quality", "error": "not found in shard"}))

        # One shard pass for all candidate videos in this batch. Each selected
        # member is spilled to a temp file only long enough for frame sampling.
        video_rows = [r for r in grouped if r["_ext"] in _VIDEO_EXT]
        if video_rows:
            by_path = {str(r.get("file_path") or "").replace("\\", "/"): r for r in video_rows}
            seen: set[str] = set()
            for norm, temp_path in iter_spilled_files_from_part(part_uri, set(by_path), directory="/tmp"):
                row = by_path.get(norm)
                if not row:
                    continue
                seen.add(norm)
                if not temp_path:
                    pre_results.append((row, {"poor": False, "reason": "video_quality_read_error", "error": "no bytes"}))
                    continue
                try:
                    pre_results.append((row, _video_quality_temp(temp_path)))
                finally:
                    try:
                        Path(temp_path).unlink(missing_ok=True)
                    except Exception:
                        pass
            for norm, row in by_path.items():
                if norm not in seen:
                    pre_results.append((row, {"poor": False, "reason": "video_quality_read_error", "error": "not found in shard"}))

    # Direct/legacy evidence falls back to the existing reader.
    for row in direct_rows:
        if row["_ext"] in _VIDEO_EXT:
            pre_results.append((row, _video_quality(db, job_id, row)))
            continue
        try:
            data = _read_artifact_bytes(db, job_id, str(row.get("file_path") or ""), max_bytes=max_read)
            if not data:
                pre_results.append((row, {"poor": False, "reason": "unreadable_for_quality", "error": "no bytes"}))
            else:
                cpu_payloads.append({"row": row, "path": row.get("file_path"), "ext": row["_ext"], "data": data})
        except Exception as exc:
            msg = str(exc)[:250]
            stream_candidate = "exceeds" in msg.lower() or "ceiling" in msg.lower()
            pre_results.append((row, {
                "poor": bool(stream_candidate),
                "reason": "quality_requires_streaming_check" if stream_candidate else "quality_read_error",
                "error": msg,
            }))

    results: list[tuple[dict[str, Any], dict[str, Any]]] = list(pre_results)
    if cpu_payloads:
        workers = _quality_workers(len(cpu_payloads))
        with _open_cpu_pool(workers) as pool:
            future_map = {pool.submit(_quality_worker, payload): payload["row"] for payload in cpu_payloads}
            for fut in as_completed(future_map):
                row = future_map[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    result = {"poor": False, "reason": "quality_worker_error", "error": str(exc)[:250]}
                results.append((row, result))

    queued = clear = errors = 0
    updates: list[tuple[str, str, bool]] = []
    for row, result in results:
        poor = bool(result.get("poor"))
        if poor:
            queued += 1
        else:
            clear += 1
        if result.get("error"):
            errors += 1
        meta = {
            "ocr_quality_checked": True,
            "ocr_quality_bucket": poor,
            "ocr_quality_reason": result.get("reason"),
            "ocr_quality_score": result.get("score"),
            "ocr_quality_sampled_frames": result.get("sampled_frames"),
            "ocr_quality_poor_frames": result.get("poor_frames"),
            "ocr_quality_error": result.get("error"),
        }
        updates.append((str(row["id"]), json.dumps(meta), poor))

    # V58: one set-based PostgreSQL write per quality batch instead of one
    # UPDATE statement per evidence item. Lock ids in order so this batch cannot
    # deadlock with parse or OCR updates of the same artifacts.
    def _write_quality_results() -> None:
        if not updates:
            db.commit()
            return
        ordered = sorted(updates, key=lambda item: item[0])
        locked = set(lock_job_artifacts_in_id_order(db, [item[0] for item in ordered], skip_locked=True))
        ordered = [item for item in ordered if item[0] in locked]
        if not ordered:
            db.commit()
            return
        from psycopg2.extras import execute_values

        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """UPDATE job_artifacts AS ja
                   SET metadata=coalesce(ja.metadata,'{}'::jsonb) || v.meta::jsonb,
                       ocr_status=CASE WHEN v.poor THEN 'pending'
                                       WHEN lower(coalesce(ja.ocr_status,'')) IN ('pending','na','') THEN 'skipped'
                                       ELSE ja.ocr_status END,
                       updated_at=NOW()
                   FROM (VALUES %s) AS v(id,meta,poor)
                   WHERE ja.id=v.id::uuid""",
                ordered,
                page_size=500,
            )
        db.commit()

    retry_on_deadlock(db, _write_quality_results)

    if queued:
        try:
            from app.services.ocr_gpu import write_ocr_live_progress

            write_ocr_live_progress(db, job_id, label=f"GPU OCR bucket — {queued:,} new poor-quality file(s)")
            db.commit()
        except Exception:
            pass
        if dispatch:
            try:
                schema = str(getattr(db, "info", {}).get("firm_schema") or "")
                if schema:
                    from app.services.ocr_gpu import dispatch_ocr_agent

                    dispatch_ocr_agent(schema, job_id)
            except Exception as exc:
                log.warning("Could not dispatch OCR immediately for %s: %s", job_id, exc)

    return {"checked": len(rows), "queued": queued, "clear": clear, "errors": errors}


def route_mobile_quality_to_ocr(db, job_id: str, *, limit: int | None = None, dispatch: bool = True) -> dict[str, int]:
    """Backward-compatible mobile entrypoint; V57 quality triage is shared by disk/Android/iOS."""
    return route_forensic_quality_to_ocr(db, job_id, limit=limit, dispatch=dispatch)
