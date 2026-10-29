"""Extract evidence directories one after another.

The directory that is open is the only image in that pass. The next directory
starts after that pass is saved to storage, and the next pipeline stage starts
only after every directory has been saved and combined.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger("next_evidence_directory")

_LOCK_STALE_SEC = 180


def directory_key(path: str) -> str:
    return str(path or "").replace("\\", "/").rstrip("/").lower()


def pending_directories(files: list[dict], segment_paths: list[str] | None) -> list[dict]:
    """Directories registered on the job whose segments were not in the saved extract.

    An empty segment list means no extract has been published yet. Those
    directories belong to the extract that is already running, not to a follow-up.
    """
    from app.services.virtual_disk import list_image_directories

    saved = [str(path) for path in (segment_paths or []) if str(path or "").strip()]
    if not saved:
        return []
    saved_dirs = {directory_key(str(Path(path).parent)) for path in saved}
    return [
        group
        for group in list_image_directories(files)
        if directory_key(group["directory"]) not in saved_dirs
    ]


def restrict_to_next_directory(files: list[dict]) -> tuple[list[dict], str | None]:
    """Keep only the first image directory when several were registered.

    The following directories are extracted after this one is saved.
    """
    from app.services.virtual_disk import _evidence_host_path, list_image_directories

    groups = list_image_directories(files)
    if len(groups) <= 1:
        return files, None
    target = groups[0]
    wanted = {str(path).lower() for path in target["paths"]}
    kept = [row for row in files if _evidence_host_path(row).lower() in wanted]
    message = (
        f"Directory 1 of {len(groups)}: extracting only {target['label']} "
        f"({len(kept)} segment file(s)). The next directory starts after this "
        "extraction is saved, and the file lists are combined before the next stage."
    )
    return kept or files, message


def _manifest_from_row(row: dict) -> dict:
    source = row.get("disk_source") or {}
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except (TypeError, ValueError):
            source = {}
    if not isinstance(source, dict):
        source = {}
    if source.get("segment_paths") or source.get("index_uri") or source.get("parts_map"):
        return source
    uri = str(row.get("extracted_disk_uri") or "")
    if not uri:
        return source
    from app.services.storage import get_bytes

    raw = get_bytes(uri)
    if not raw:
        return source
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError):
        return source
    return loaded if isinstance(loaded, dict) else source


def directory_roster(db, job_id: str, row: dict | None = None) -> list[dict]:
    """One line per registered image directory, for the processing panels.

    A single directory returns an empty list. The panels only need the extra
    directories the examiner added.
    """
    from app.db.sql_helpers import fetchall, fetchone

    row = fetchone(
        db,
        """SELECT disk_source, extracted_disk_uri, files_extracted, bytes_extracted, pipeline_progress
             FROM jobs WHERE id=:id""",
        {"id": job_id},
    ) or row or {}
    manifest = _manifest_from_row(row)
    files = fetchall(
        db,
        "SELECT * FROM evidence_files WHERE job_id=:job_id ORDER BY original_name",
        {"job_id": job_id},
    )
    from app.services.virtual_disk import list_image_directories

    registered = list_image_directories(files)
    if len(registered) <= 1:
        return []
    pending = pending_directories(files, list(manifest.get("segment_paths") or []))
    pending_keys = {directory_key(item["directory"]) for item in pending}
    append = manifest.get("directory_append") if isinstance(manifest.get("directory_append"), dict) else None
    extracting = bool(append and append.get("owner"))
    first_pending = directory_key(pending[0]["directory"]) if pending else ""
    stats = manifest.get("directory_stats") if isinstance(manifest.get("directory_stats"), list) else []
    stats_by_key = {
        directory_key(str(item.get("directory") or "")): item
        for item in stats
        if isinstance(item, dict)
    }
    progress = row.get("pipeline_progress") or {}
    if isinstance(progress, str):
        try:
            progress = json.loads(progress)
        except (TypeError, ValueError):
            progress = {}
    activity = progress.get("extraction_activity") if isinstance(progress, dict) else {}
    if not isinstance(activity, dict):
        activity = {}
    roster: list[dict] = []
    saved_missing: list[dict] = []
    for index, group in enumerate(registered, 1):
        key = directory_key(group["directory"])
        stat = stats_by_key.get(key)
        known_files = int(stat.get("files") or 0) if stat else None
        known_bytes = int(stat.get("bytes") or 0) if stat else None
        if key not in pending_keys:
            state = "saved"
            detail = "Saved and included in the combined file list."
        elif extracting and key == first_pending:
            state = "extracting"
            age = None
            try:
                age = max(0, int(time.time() - float(append.get("heartbeat_at") or 0)))
            except (TypeError, ValueError):
                age = None
            if age is not None and age < _LOCK_STALE_SEC:
                detail = f"Opening this image now. Worker heartbeat {age}s ago."
            else:
                detail = "This image is opening now."
            active_label = str(activity.get("directory_label") or "")
            if active_label and active_label == str(group.get("label") or ""):
                prior = int(manifest.get("files_extracted") or 0)
                packed = activity.get("files_packed", activity.get("files_extracted"))
                try:
                    packed_n = int(packed) if packed is not None else None
                except (TypeError, ValueError):
                    packed_n = None
                known_files = max(0, packed_n - prior) if packed_n is not None and packed_n >= prior else int(activity.get("files_found") or 0)
                known_bytes = 0
            else:
                known_files = 0
                known_bytes = 0
        else:
            state = "waiting"
            detail = "Previous directories are saved. This directory is next."
            known_files = 0
            known_bytes = 0
        entry = {
            "index": index,
            "total": len(registered),
            "label": group["label"],
            "segments": len(group["paths"]),
            "state": state,
            "detail": detail,
            "files": known_files,
            "bytes": known_bytes,
        }
        if state == "saved" and known_files is None:
            saved_missing.append(entry)
        roster.append(entry)
    if len(saved_missing) == 1:
        only = saved_missing[0]
        known_files = sum(int(entry.get("files") or 0) for entry in roster if entry is not only and entry.get("files") is not None)
        known_bytes = sum(int(entry.get("bytes") or 0) for entry in roster if entry is not only and entry.get("bytes") is not None)
        only["files"] = max(0, int(row.get("files_extracted") or manifest.get("files_extracted") or 0) - known_files)
        only["bytes"] = max(0, int(row.get("bytes_extracted") or manifest.get("bytes_extracted") or 0) - known_bytes)
    for entry in roster:
        entry["files"] = int(entry.get("files") or 0)
        entry["bytes"] = int(entry.get("bytes") or 0)
    return roster


def unfinished_directory_reason(db, job_id: str, row: dict | None = None) -> str | None:
    """Why the next pipeline stage must wait, or None when every directory is saved."""
    from app.db.sql_helpers import fetchall, fetchone

    if row is None:
        row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id}) or {}
    manifest = _manifest_from_row(row)
    files = fetchall(
        db,
        "SELECT * FROM evidence_files WHERE job_id=:job_id ORDER BY original_name",
        {"job_id": job_id},
    )
    folders = manifest.get("evidence_folders") if isinstance(manifest.get("evidence_folders"), list) else []
    from app.services.virtual_disk import list_image_directories

    registered = list_image_directories(files)
    if len(folders) > len(registered):
        return "Waiting for every evidence directory to finish registering"
    pending = pending_directories(files, list(manifest.get("segment_paths") or []))
    if not pending:
        return None
    nxt = pending[0]
    return (
        f"Directory {len(registered) - len(pending) + 1} of {len(registered)} "
        f"({nxt['label']}) starts after the current extraction is saved"
    )


def _claim_append(db, job_id: str, owner: str) -> bool:
    from app.db.sql_helpers import fetchone

    payload = json.dumps({"owner": owner, "heartbeat_at": time.time()})
    row = fetchone(
        db,
        """UPDATE jobs
              SET disk_source = jsonb_set(
                    COALESCE(disk_source, '{}'::jsonb),
                    '{directory_append}',
                    CAST(:payload AS jsonb),
                    true
                  ),
                  updated_at = NOW()
            WHERE id = :id
              AND (
                COALESCE(disk_source #>> '{directory_append,owner}', '') = ''
                OR COALESCE(disk_source #>> '{directory_append,heartbeat_at}', '0')::float
                   < :stale
              )
            RETURNING id""",
        {"id": job_id, "payload": payload, "stale": time.time() - _LOCK_STALE_SEC},
    )
    db.commit()
    return row is not None


def _heartbeat(schema_name: str, job_id: str, owner: str, stop: threading.Event) -> None:
    from app.db.session import firm_session
    from app.db.sql_helpers import execute

    while not stop.wait(20):
        payload = json.dumps({"owner": owner, "heartbeat_at": time.time()})
        try:
            with firm_session(schema_name) as db:
                execute(
                    db,
                    """UPDATE jobs
                          SET disk_source = jsonb_set(
                                COALESCE(disk_source, '{}'::jsonb),
                                '{directory_append}',
                                CAST(:payload AS jsonb),
                                true
                              ),
                              updated_at = NOW()
                        WHERE id = :id
                          AND disk_source #>> '{directory_append,owner}' = :owner""",
                    {"id": job_id, "payload": payload, "owner": owner},
                )
                db.commit()
        except Exception:
            log.debug("directory append heartbeat failed job=%s", job_id, exc_info=True)


def _release_append(db, job_id: str, owner: str) -> None:
    from app.db.sql_helpers import execute

    execute(
        db,
        """UPDATE jobs
              SET disk_source = COALESCE(disk_source, '{}'::jsonb) - 'directory_append',
                  updated_at = NOW()
            WHERE id = :id
              AND disk_source #>> '{directory_append,owner}' = :owner""",
        {"id": job_id, "owner": owner},
    )
    db.commit()


def extract_pending_directories(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    """Save every evidence directory that was not part of the published extract.

    The caller runs this after one directory's extraction is saved and before
    the next pipeline stage. A second caller waits; it does not open the image.
    """
    from app.db.sql_helpers import fetchone
    from app.services.disk_build_log import write_disk_log

    reason = unfinished_directory_reason(db, job_id)
    if reason is None:
        return {"status": "none"}
    if reason.startswith("Waiting for every evidence directory"):
        write_disk_log(db, job_id, reason, stage="extract", level="warning")
        db.commit()
        return {"status": "waiting", "reason": reason}

    owner = uuid.uuid4().hex
    if not _claim_append(db, job_id, owner):
        return {"status": "busy", "reason": "The next evidence directory is already being extracted"}

    stop = threading.Event()
    beater = threading.Thread(
        target=_heartbeat,
        args=(schema_name, job_id, owner, stop),
        name=f"dir-append-{job_id[:8]}",
        daemon=True,
    )
    beater.start()
    extracted: list[str] = []
    try:
        while True:
            row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id}) or {}
            manifest = _manifest_from_row(row)
            from app.db.sql_helpers import fetchall

            files = fetchall(
                db,
                "SELECT * FROM evidence_files WHERE job_id=:job_id ORDER BY original_name",
                {"job_id": job_id},
            )
            from app.services.virtual_disk import list_image_directories

            registered = list_image_directories(files)
            pending = pending_directories(files, list(manifest.get("segment_paths") or []))
            if not pending:
                break
            group = pending[0]
            position = len(registered) - len(pending) + 1
            write_disk_log(
                db,
                job_id,
                f"Directory {position} of {len(registered)}: previous extraction is saved. "
                f"Opening only {group['label']} ({len(group['paths'])} segment file(s)).",
                stage="extract",
                metadata={"directory": group["directory"], "segments": len(group["paths"])},
            )
            db.commit()
            manifest = _extract_one_directory(
                db,
                job_id,
                schema_name=schema_name,
                manifest=manifest,
                group=group,
                position=position,
                total=len(registered),
            )
            extracted.append(group["label"])
            if position == len(registered):
                write_disk_log(
                    db,
                    job_id,
                    f"Combined {len(registered)} directories. The same extract filter was applied "
                    "to each directory. Starting the next pipeline stage.",
                    stage="extract",
                    metadata={"directories": [item["label"] for item in registered]},
                )
                db.commit()
        from app.services.pipeline_progress import write_merged_pipeline_progress

        write_merged_pipeline_progress(
            db,
            job_id,
            {
                "extraction_activity": {
                    "next_directory": False,
                    "subphase": "finalizing",
                },
            },
            writer="extract",
        )
        db.commit()
        try:
            _register_appended_files(db, job_id, extracted)
        except Exception:
            log.exception("appended directory files were not registered job=%s", job_id)
        return {"status": "extracted", "directories": extracted}
    except Exception:
        log.exception("next evidence directory failed job=%s", job_id)
        raise
    finally:
        stop.set()
        beater.join(timeout=2)
        try:
            _release_append(db, job_id, owner)
        except Exception:
            log.exception("could not release directory append lock job=%s", job_id)


def _register_appended_files(db, job_id: str, extracted: list[str]) -> None:
    """Register files from a directory that was saved after materialize already ran.

    The running parse keeps going. New files are pending, so that parse — or the
    next one if it already finished — includes them.
    """
    if not extracted:
        return
    from app.db.sql_helpers import execute
    from app.services.artifact_materialize import rematerialize_missing_from_index
    from app.services.disk_build_log import write_disk_log

    filled = rematerialize_missing_from_index(db, job_id, update_status=False)
    added = int(filled.get("added") or 0)
    write_disk_log(
        db,
        job_id,
        f"Registered {added:,} file(s) from {', '.join(extracted)} onto the disk job.",
        stage="materialize",
        metadata={"added": added, "directories": extracted},
    )
    # V1.10.3: reopen parse also when it is waiting or failed after its stage
    # process was cancelled, and reopen every finished stage after parse, so the
    # new directory's files also go through recovery, OCR, inventory, RAG chunking,
    # enrichment, graph and validation. Parse resumes from parse_status rows.
    execute(
        db,
        """UPDATE pipeline_stage_runs
              SET status='waiting', task_id=NULL, completed_at=NULL, error=NULL,
                  cancel_requested_at=NULL, recovery_dispatches=0, updated_at=NOW()
            WHERE job_id=:jid AND stage='parse'
              AND (status IN ('done','skipped')
                   OR (status IN ('failed','waiting')
                       AND (lower(COALESCE(error,'')) LIKE '%progressagent%'
                            OR lower(COALESCE(error,'')) LIKE '%stage process%')))""",
        {"jid": job_id},
    )
    execute(
        db,
        """UPDATE pipeline_stage_runs
              SET status='pending', task_id=NULL, completed_at=NULL, updated_at=NOW()
            WHERE job_id=:jid AND status IN ('done','skipped')
              AND sequence_no > (SELECT sequence_no FROM pipeline_stage_runs
                                  WHERE job_id=:jid AND stage='parse')""",
        {"jid": job_id},
    )
    execute(
        db,
        """UPDATE jobs SET status='indexing', updated_at=NOW()
            WHERE id=:jid AND status IN ('ready','report_ready','parsed','indexed')""",
        {"jid": job_id},
    )
    db.commit()


def _extract_one_directory(
    db,
    job_id: str,
    *,
    schema_name: str,
    manifest: dict,
    group: dict,
    position: int,
    total: int,
) -> dict:
    from app.config import get_settings
    from app.services.disk_build_log import write_disk_log
    from app.services.extracted_disk import (
        _ExtractionProgress,
        _ProgressFlusher,
        _enumerate_mounted_image,
        _filter_nodes,
        _shard_nodes,
    )
    from app.services.extract_shard_v45 import shard_worker_v45
    from app.services.os_detect import detect_os_from_paths
    from app.services.pipeline_progress import write_merged_pipeline_progress
    from app.services.virtual_disk import open_virtual_disk_from_paths
    import zstandard as zstd

    settings = get_settings()
    mode = str(manifest.get("extract_mode") or settings.extract_mode or "forensic").strip().lower()
    saved_os = manifest.get("detected_os") if isinstance(manifest.get("detected_os"), dict) else None
    prior_files = int(manifest.get("files_extracted") or 0)
    prior_bytes = int(manifest.get("bytes_extracted") or 0)
    prior_skipped = int(manifest.get("files_skipped") or 0)

    one = None
    try:
        one = open_virtual_disk_from_paths(
            job_id,
            list(group["paths"]),
            hashes=list(group["hashes"]),
            base_name=group["label"],
            combine_image_sets=False,
        )
        if one._fs_info is None or one.mode not in {"ewf", "raw"}:
            one.close()
            one = None
            raise RuntimeError(
                f"Could not mount {group['label']}. Its segment files were not used as extracted files."
            )
        enumerated = _enumerate_mounted_image(
            one,
            on_progress=lambda message, metadata=None: None,
            schema_name=schema_name,
        )
        os_info = saved_os or detect_os_from_paths(enumerated)
        nodes, filter_stats = _filter_nodes(enumerated, settings, os_info=os_info, mode_override=mode)
        label = str(group["label"])
        for node in nodes:
            rel = str(node.get("path") or "").replace("\\", "/").lstrip("/")
            node["path"] = f"{label}/{rel}" if rel else label
        write_disk_log(
            db,
            job_id,
            f"Directory {position} of {total} listed {len(enumerated):,} files from {label}. "
            f"The same filter kept {len(nodes):,} "
            f"({int(filter_stats.get('filtered_out') or 0):,} pre-filtered).",
            stage="extract",
            metadata={
                "directory": group["directory"],
                "files_enumerated": len(enumerated),
                "files_kept": len(nodes),
                "pre_filtered": int(filter_stats.get("filtered_out") or 0),
            },
        )
        db.commit()
        if not nodes:
            return _publish_directory(
                db,
                job_id,
                manifest=manifest,
                group=group,
                new_entries=[],
                parts_map={},
                files_added=0,
                bytes_added=0,
                skipped_added=int(filter_stats.get("filtered_out") or 0),
                filter_stats=filter_stats,
            )

        worker_count = 1 if len(nodes) < 2 else min(4, len(nodes))
        local_shards = _shard_nodes(nodes, worker_count, strategy="byte_range_v53")
        occupied = [int(key) for key in (manifest.get("parts_map") or {})]
        if not occupied and manifest.get("parts"):
            occupied = list(range(len(manifest.get("parts") or [])))
        base = (max(occupied) + 1) if occupied else 0
        planned_bytes = prior_bytes + sum(int(node.get("size_bytes") or 0) for node in nodes)
        progress = _ExtractionProgress(
            prior_files + len(nodes),
            progress_step=settings.extract_progress_step,
            initial_extracted=prior_files,
            initial_bytes=prior_bytes,
            pre_filtered=prior_skipped + int(filter_stats.get("filtered_out") or 0),
        )
        write_merged_pipeline_progress(
            db,
            job_id,
            {
                "phase": "extract",
                "completed": prior_files,
                "total": prior_files + len(nodes),
                "label": f"Extracting directory {position} of {total}: {label}",
                "extraction_activity": {
                    "subphase": "copying",
                    "next_directory": True,
                    "label": f"Extracting directory {position} of {total}: {label}",
                    "files_extracted": prior_files,
                    "files_packed": prior_files,
                    "files_uploaded": prior_files,
                    "files_total": prior_files + len(nodes),
                    "directory_index": position,
                    "directories": total,
                    "directory_label": label,
                },
            },
            writer="extract",
            # V1.10.3: never pull a job whose later stages are running back to
            # 'processing'; the next directory is extracted beside them.
            extra_sets=("status=CASE WHEN status IN ('indexing','parsed','ready','report_ready','completed','paused') "
                        "THEN status ELSE 'processing' END, files_total=:ft"),
            extra_params={"ft": prior_files + len(nodes)},
        )
        db.commit()
        flusher = _ProgressFlusher(
            schema_name,
            job_id,
            progress,
            shard_count=worker_count,
            total_bytes=planned_bytes,
        )
        flusher.start()
        part_prefix = f"{disk_prefix(job_id)}/directories/{position:02d}"
        new_entries: list[dict] = []
        parts_map: dict[str, str] = {}
        files_added = 0
        bytes_added = 0
        try:
            for local_id in sorted(local_shards):
                shard_nodes = local_shards[local_id]
                if not shard_nodes:
                    continue
                shard_id = base + int(local_id)
                result = shard_worker_v45(
                    {
                        "schema_name": schema_name,
                        "job_id": job_id,
                        "shard_id": shard_id,
                        "nodes": shard_nodes,
                        "zstd_level": settings.extract_zstd_level,
                        "shard_count": base + worker_count,
                        "hash_files": settings.extract_hash_files,
                        "stop_check_interval": settings.extract_stop_check_interval,
                        "tar_bufsize": getattr(settings, "extract_tar_bufsize", 262_144),
                        "part_prefix": part_prefix,
                    },
                    progress,
                    flusher,
                    None,
                    shared_vd=one,
                    event_bus=flusher.event_bus,
                )
                if result.get("part_uri"):
                    parts_map[str(shard_id)] = result["part_uri"]
                new_entries.extend(result.get("index_entries") or [])
                files_added += int(result.get("files_extracted") or 0)
                bytes_added += int(result.get("bytes_extracted") or 0)
                progress.mark_shard_committed(
                    int(result.get("files_extracted") or 0),
                    int(result.get("bytes_extracted") or 0),
                )
                flusher.mark_dirty()
        finally:
            flusher.stop(flush=True)
        return _publish_directory(
            db,
            job_id,
            manifest=manifest,
            group=group,
            new_entries=new_entries,
            parts_map=parts_map,
            files_added=files_added,
            bytes_added=bytes_added,
            skipped_added=int(filter_stats.get("filtered_out") or 0),
            filter_stats=filter_stats,
            compressor=zstd.ZstdCompressor(level=settings.extract_zstd_level),
        )
    finally:
        if one is not None:
            one.close()


def _publish_directory(
    db,
    job_id: str,
    *,
    manifest: dict,
    group: dict,
    new_entries: list[dict],
    parts_map: dict[str, str],
    files_added: int,
    bytes_added: int,
    skipped_added: int,
    filter_stats: dict,
    compressor=None,
) -> dict:
    from app.db.sql_helpers import execute, fetchone
    from app.services.disk_manifest import disk_prefix, load_index_entries
    from app.services.storage import put_bytes

    published = dict(manifest)
    live_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    live = live_row.get("disk_source") or {}
    if isinstance(live, str):
        try:
            live = json.loads(live)
        except (TypeError, ValueError):
            live = {}
    if isinstance(live, dict):
        if live.get("directory_append"):
            published["directory_append"] = live["directory_append"]
        if live.get("evidence_folders") and "evidence_folders" not in published:
            published["evidence_folders"] = live["evidence_folders"]
        # The saved manifest is an older snapshot. Keep the disk identity from
        # the live row so publishing the next directory cannot mark a disk job
        # as Android or iOS.
        for key in ("source_type", "format", "mode", "evidence_platform", "axiom_platform", "detected_os"):
            if key in live:
                published[key] = live[key]
        for key in ("mobile_os", "owner_agent", "owner_agent_label", "os_selection_source", "os_mismatch_warning"):
            if key not in live:
                published.pop(key, None)
    existing_entries = load_index_entries(published) if published.get("index_uri") or published.get("shard_indexes") else []
    seen: set[tuple] = set()
    combined: list[dict] = []
    for entry in list(existing_entries) + list(new_entries):
        key = (str(entry.get("path") or ""), int(entry.get("part_id") or 0), int(entry.get("offset") or 0))
        if key in seen:
            continue
        seen.add(key)
        combined.append(entry)
    if compressor is None:
        import zstandard as zstd

        compressor = zstd.ZstdCompressor(level=1)
    index_lines = "\n".join(json.dumps(entry, separators=(",", ":")) for entry in combined).encode("utf-8")
    index_key = f"{disk_prefix(job_id)}/index.jsonl.zst"
    index_uri = put_bytes(index_key, compressor.compress(index_lines), content_type="application/zstd")

    merged_parts = {str(key): value for key, value in (published.get("parts_map") or {}).items() if value}
    merged_parts.update({str(key): value for key, value in parts_map.items() if value})
    ordered_ids = sorted((int(key) for key in merged_parts), key=int)
    # Keep every previously stored part id. A follow-up directory starts above them.
    parts = [merged_parts[str(part_id)] for part_id in ordered_ids]
    files_total = int(published.get("files_extracted") or 0) + int(files_added)
    bytes_total = int(published.get("bytes_extracted") or 0) + int(bytes_added)
    skipped = int(published.get("files_skipped") or 0) + int(skipped_added)
    directory_stats = [
        item for item in (published.get("directory_stats") or [])
        if isinstance(item, dict) and directory_key(str(item.get("directory") or "")) != directory_key(group["directory"])
    ]
    directory_stats.append(
        {
            "directory": group["directory"],
            "label": group.get("label") or "",
            "files": int(files_added),
            "bytes": int(bytes_added),
            "skipped": int(skipped_added),
        }
    )
    published.update(
        {
            "segment_paths": list(published.get("segment_paths") or []) + list(group["paths"]),
            "segment_hashes": list(published.get("segment_hashes") or []) + list(group["hashes"]),
            "files_total": files_total,
            "files_extracted": files_total,
            "files_skipped": skipped,
            "bytes_extracted": bytes_total,
            "parts_map": merged_parts,
            "parts": parts,
            "index_uri": index_uri,
            "extracted_directories": list(published.get("extracted_directories") or []) + [group["directory"]],
            "directory_stats": directory_stats,
            "filter_stats": {**(published.get("filter_stats") or {}), "next_directory": filter_stats},
        }
    )
    manifest_key = f"{disk_prefix(job_id)}/manifest.json"
    manifest_uri = put_bytes(manifest_key, json.dumps(published, indent=2).encode(), "application/json")
    execute(
        db,
        """UPDATE jobs
              SET extracted_disk_uri=:uri,
                  disk_source=CAST(:ds AS jsonb),
                  files_total=:total,
                  files_extracted=:extracted,
                  bytes_extracted=:bytes,
                  status=CASE
                    WHEN status IN ('indexing','parsed','ready','report_ready','completed') THEN status
                    ELSE 'processing'
                  END,
                  error=NULL,
                  updated_at=NOW()
            WHERE id=:job_id""",
        {
            "uri": manifest_uri,
            "ds": json.dumps(published),
            "total": files_total,
            "extracted": files_total,
            "bytes": bytes_total,
            "job_id": job_id,
        },
    )
    db.commit()
    return published
