"""Source-linked priority evidence for disk and mobile, with text-only RAG."""

from __future__ import annotations

from app.services.mobile_forensic.crypt_formats import is_crypt_file

import json
import re
from pathlib import PurePosixPath

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_POLICY, CHUNK_SIZE
from app.services.mobile_forensic.models import NormalizedArtifact
from app.services.mobile_forensic.storage import _dumps

PRIORITY_FAMILIES = (
    "whatsapp_messages",
    "deleted_whatsapp",
    "browser",
    "pictures",
    "videos",
    "audio",
    "documents",
    "messages", "emails", "binary", "structured_data", "downloads", "applications", "accounts",
)
def bundle_priority(path: str, extension: str | None = None) -> int:
    """Stable claim order. Stored on the work row so the parser does not re-sort JSON."""
    lower = (path or "").lower()
    ext = (extension or "").lower()
    if any(token in lower for token in ("msgstore", "chatstorage", "wa.db")):
        return 0
    if any(token in lower for token in ("history", "places.sqlite", "bookmarks", "browser")):
        return 1
    if "whatsapp" in lower:
        return 2
    if any(token in lower for token in ("dcim", "pictures", "photos", "trash", "deleted")):
        return 3
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".epub", ".rtf"}:
        return 4
    return 5


def ensure_priority_schema(db):
    execute(
        db,
        """CREATE TABLE IF NOT EXISTS forensic_priority_records (
        artifact_id text PRIMARY KEY,job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        job_artifact_id uuid NOT NULL REFERENCES job_artifacts(id) ON DELETE CASCADE,
        artifact_type text NOT NULL,source_domain text NOT NULL,state text NOT NULL,
        timestamp_utc timestamptz,data jsonb NOT NULL,forensic jsonb NOT NULL)""",
    )
    from app.services.evidence_browse_indexes import index_already_present

    index_sql = "CREATE INDEX IF NOT EXISTS ix_priority_job_record ON forensic_priority_records(job_id,artifact_id)"
    if not index_already_present(db, index_sql):
        execute(db, index_sql)


def add_record_links(art):
    data = art.data or {}
    if art.artifact_type in {
        "app_message",
        "recovered_chat_candidate",
        "browser_visit",
        "browser_url",
    }:
        text = " ".join(
            str(data.get(key) or "")
            for key in ("body", "text", "caption", "url", "media_url")
        )
        data["urls"] = list(
            dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", text, re.I))
        )
    return art


def persist_disk_records(db, job_id, file_id, artifacts):
    from psycopg2.extras import execute_values

    records = {art.artifact_id: add_record_links(art) for art in artifacts}
    values = [
        (
            art.artifact_id,
            job_id,
            file_id,
            art.artifact_type,
            art.source_domain,
            art.forensic.get("state") or "allocated",
            art.timestamp_utc,
            _dumps(art.data),
            _dumps(art.forensic),
        )
        for art in records.values()
    ]
    if values:
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """INSERT INTO forensic_priority_records
                (artifact_id,job_id,job_artifact_id,artifact_type,source_domain,state,timestamp_utc,data,forensic)
                VALUES %s ON CONFLICT(artifact_id) DO UPDATE SET data=EXCLUDED.data,forensic=EXCLUDED.forensic""",
                values,
                template="(%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb,%s::jsonb)",
                page_size=500,
            )
    return len(values)


def run_disk_priority_evidence(db, job_id):
    """Source-complete priority parsing with bounded writes and one fallback scan per part.

    The old implementation committed and updated the stage deadline for *every*
    source, then re-opened a multi-GB tar.zst for each unknown binary's 4 KiB
    signature. A 180k-file case could spend longer in this second pass than in
    all of native parsing. Keep identical plugin routing, records and per-source
    exception markers, but stream common header reads once per extracted part.
    """
    import os
    import threading
    import time
    import queue
    import copy
    from collections import defaultdict, OrderedDict

    from psycopg2.extras import execute_values

    from app.services.forensic_serial_mobile import _context, evidence_bundles
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.job_control import pipeline_should_stop
    from app.services.mobile_forensic.discovery import inventory_from_job_artifacts
    from app.services.mobile_forensic.parsers.browser import BrowserHistoryParser
    from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
    from app.services.mobile_forensic.plugins import get_plugin_registry
    from app.services.mobile_forensic.recovery.analyzers import SqliteHistoryAnalyzer
    from app.services.tar_cache import iter_files_from_part

    ensure_priority_schema(db)
    # The independent writer connection must see the table, and the planning
    # transaction must not hold DDL locks while worker reads begin.
    db.commit()
    items = inventory_from_job_artifacts(db, job_id)
    ds = (fetchone(db, "SELECT disk_source FROM jobs WHERE id=:jid", {"jid": job_id}) or {}).get("disk_source") or {}
    if isinstance(ds, str):
        ds = json.loads(ds)
    context = _context(db, job_id, ds, evidence_paths=(it.path for it in items))
    sources = {
        r["file_path"].replace("\\", "/"): r
        for r in fetchall(
            db,
            "SELECT id,file_path,metadata,minio_uri FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )
    }
    browser, whatsapp = BrowserHistoryParser(), WhatsAppParser()
    registry = get_plugin_registry()
    _raw_read = context._read_bytes
    written = errors = processed = 0
    already_done = 0
    pending_records = []
    pending_sources = []
    last_heartbeat = time.monotonic()
    last_progress_reported = (0, 0)
    active_path = ""
    # The caller owns the planning Session. In production, create a separate
    # tenant-scoped Session in the writer thread (SQLAlchemy Sessions cannot be
    # transferred between threads). The lock only guards occasional legacy
    # source reads against one another, never CPU parsing or decompression.
    schema_name = (getattr(db, "info", None) or {}).get("firm_schema")
    writer_db = [db]
    db_lock = threading.RLock()
    read_errors_local = threading.local()
    # A bounded queue prevents a fast 8-way parser from building unbounded
    # normalized-artifact lists while PostgreSQL is backpressured.
    output = queue.Queue(maxsize=16)
    writer_error = []
    writer_finished = threading.Event()
    # Source metadata is registered by acquisition. For well-known OS/runtime
    # binaries, an extra 4 KiB classification read is not evidence extraction.
    # Retain a truthful unclassified record and an explicit deferred-signature
    # marker. Mail, browser, SQLite and extensionless/ambiguous files always
    # retain their full forensic readers.
    from app.services.disk_priority_fastpath import (
        deferred_signature_artifact, can_defer_fallback_signature,
        shard_stream_budget,
    )
    from app.services.disk_slots import DISK_SLOTS, run_bounded
    signature_mode = os.getenv("DISK_PRIORITY_SIGNATURE_MODE", "safe_deferred").strip().lower()
    diagnostic = defaultdict(int)
    time_by_phase = defaultdict(float)

    def measured_read(path, max_bytes=120_000_000):
        started = time.monotonic()
        # `_context` records unreadable acquired paths in a closure-owned set.
        # Transfer those markers into the *calling parser thread's* set so a
        # failed companion read cannot taint another source running in parallel.
        thread_errors = getattr(read_errors_local, "current", None)
        with db_lock:
            original_errors = context.extra["read_errors"]
            original_errors.clear()
            try:
                result = _raw_read(path, max_bytes=max_bytes)
                if thread_errors is not None:
                    thread_errors.update(original_errors)
                    if result is None and path in sources:
                        thread_errors.add(path)
                return result
            except Exception:
                if thread_errors is not None:
                    thread_errors.update(original_errors)
                    thread_errors.add(path)
                raise
            finally:
                original_errors.clear()
                diagnostic["individual_reads"] += 1
                time_by_phase["individual_read"] += time.monotonic() - started

    read_original = measured_read
    # A fresh context per parsing unit owns its read errors, byte-cache and
    # override reader. The routing context is read-only after planning.
    context._read_bytes = measured_read
    flush_sources = 250
    flush_records = 2500

    def flush():
        nonlocal written, last_heartbeat
        with db_lock:
            _flush_locked()

    committed_processed = 0

    def _flush_locked():
        nonlocal written, last_heartbeat, committed_processed
        if not pending_sources and not pending_records:
            return
        if pending_records:
            write_started = time.monotonic()
            # Source ids travel with individual records (not the whole batch).
            unique = {art.artifact_id: (source_id, add_record_links(art))
                      for source_id, art in pending_records}
            values = [
                (art.artifact_id, job_id, source_id, art.artifact_type,
                 art.source_domain, art.forensic.get("state") or "allocated",
                 art.timestamp_utc, _dumps(art.data), _dumps(art.forensic))
                for source_id, art in unique.values()
            ]
            with writer_db[0].connection().connection.cursor() as cur:
                execute_values(
                    cur,
                    """INSERT INTO forensic_priority_records
                       (artifact_id,job_id,job_artifact_id,artifact_type,source_domain,state,timestamp_utc,data,forensic)
                       VALUES %s ON CONFLICT(artifact_id) DO UPDATE
                       SET data=EXCLUDED.data,forensic=EXCLUDED.forensic""",
                    values,
                    template="(%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb,%s::jsonb)",
                    page_size=500,
                )
            written += len(values)
            time_by_phase["db_insert"] += time.monotonic() - write_started
        if pending_sources:
            # One ordered UPDATE per bounded batch instead of 1 UPDATE + COMMIT
            # per media file; deterministic order also prevents lock inversion.
            source_by_id = {str(source_id): (source_id, reason)
                            for source_id, reason in pending_sources}
            values = [source_by_id[key] for key in sorted(source_by_id)]
            with writer_db[0].connection().connection.cursor() as cur:
                execute_values(
                    cur,
                    """UPDATE job_artifacts AS ja SET
                       metadata=COALESCE(ja.metadata,'{}'::jsonb) ||
                         jsonb_build_object('priority_parsed_v4',true,
                                            'priority_parse_exception',v.reason)
                       FROM (VALUES %s) AS v(id,reason)
                       WHERE ja.id=v.id::uuid""",
                    values,
                    template="(%s,%s::text)",
                    page_size=500,
                )
        writer_db[0].commit()
        committed_processed += len(pending_sources)
        diagnostic["flushes"] += 1
        pending_records.clear()
        pending_sources.clear()
        heartbeat()

    def heartbeat() -> None:
        with db_lock:
            _heartbeat_locked()

    def _heartbeat_locked() -> None:
        nonlocal last_heartbeat, last_progress_reported
        now = time.monotonic()
        if now - last_heartbeat < 5:
            return
        # Denominator is the whole priority set, including sources finished on
        # an earlier attempt. Counting only the remainder made the card jump
        # from 74,597 back to 122,038 when a restarted pass published its plan.
        shown = already_done + committed_processed
        leaf = active_path.replace("\\", "/").rsplit("/", 1)[-1][:80]
        line = (f"Priority evidence: {shown:,} / {total_sources:,} sources checked; "
                f"{written:,} records committed · {DISK_SLOTS} slots")
        if leaf:
            line = f"{line} · {leaf}"
        execute(writer_db[0], """UPDATE pipeline_stage_runs SET
            details=COALESCE(details,'{}'::jsonb) - 'parse_io' ||
              jsonb_build_object('priority_sources_completed', CAST(:done AS bigint),
                                 'priority_sources_total', CAST(:total AS bigint),
                                 'priority_records_written', CAST(:records AS bigint),
                                 'priority_read_deferred', CAST(:deferred AS bigint),
                                 'priority_shard_files', CAST(:shardfiles AS bigint),
                                 'priority_shard_opens', CAST(:shardopens AS bigint),
                                 'priority_db_insert_seconds', CAST(:dbsec AS double precision),
                                 'priority_individual_reads', CAST(:indreads AS bigint),
                                 'priority_individual_read_seconds', CAST(:indsec AS double precision),
                                 'priority_current_path', CAST(:path AS text))
            WHERE job_id=:jid AND stage='parse' AND status='running'""",
            {"jid": job_id, "done": already_done + committed_processed, "total": total_sources, "records": written,
             "deferred": diagnostic["deferred"], "shardfiles": diagnostic["shard_files"],
             "shardopens": diagnostic["shard_opens"], "dbsec": round(time_by_phase["db_insert"], 3),
             "indreads": diagnostic["individual_reads"],
             "indsec": round(time_by_phase["individual_read"], 3),
             "path": active_path[:300]})
        from app.services.progress_agent import note_operation
        # A heartbeat alone is NOT evidence progress. Only committed source or
        # record changes may extend the useful-progress deadline.
        progress = (already_done + committed_processed, written)
        changed = progress != last_progress_reported
        note_operation(writer_db[0], job_id, "parse", line, timeout_seconds=900, advanced=changed)
        # Visible liveness even when a very large tar member is still being
        # decoded and no record batch is due to flush.
        writer_db[0].commit()
        last_progress_reported = progress
        last_heartbeat = now

    _not_streamed = object()

    def emit(kind, value):
        """Backpressure to the one DB writer; fail rather than silently drop data."""
        while not writer_finished.is_set():
            if writer_error:
                raise RuntimeError("Priority evidence writer stopped") from writer_error[0]
            try:
                output.put((kind, value), timeout=0.25)
                return
            except queue.Full:
                continue
        raise RuntimeError("Priority evidence writer stopped before processing finished")

    def _local_context(base=None):
        ctx = copy.copy(base or context)
        ctx.extra = dict(ctx.extra)
        ctx.extra["read_errors"] = set()
        read_errors_local.current = ctx.extra["read_errors"]
        ctx._byte_cache = OrderedDict()
        ctx._cache_bytes = 0
        if base is None:
            ctx._read_bytes = read_original
        return ctx

    def process(bundle, parsers, web_text, storage, *, header=_not_streamed,
                deferred=False, work_ctx=None):
        """Parse without taking the database mutex. Only the writer checkpoints."""
        ctx = _local_context(work_ctx)
        item = bundle[0]
        source = sources[item.path]
        emit("active", item.path)
        buffer = []
        reason = None
        errored = False
        base_reader = ctx._read_bytes
        if header is not _not_streamed:
            data_bytes = header
            def read_cached(path, max_bytes=120_000_000):
                # Only a byte-identical full source may satisfy a full-file
                # parser. A short prefix is exclusively for signature readers.
                if path == item.path:
                    if data_bytes is None:
                        ctx.extra["read_errors"].add(path)
                        return None
                    if len(data_bytes) >= max_bytes or (
                        int(item.size or 0) > 0 and len(data_bytes) == int(item.size)
                    ):
                        return data_bytes[:max_bytes]
                return base_reader(path, max_bytes=max_bytes)
        def publish_buffer():
            if buffer:
                emit("records", (source["id"], list(buffer)))
                buffer.clear()
        try:
            if deferred:
                buffer.append(deferred_signature_artifact(item, ctx))
                emit("deferred", None)
                parsers = []
            if web_text:
                blob = ctx.read_artifact_bytes(item.path)
                if blob is None:
                    raise ValueError("Web document could not be read")
                txt = blob.decode("utf-16" if blob.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8", "replace")
                for idx, url in enumerate(dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", txt, re.I))):
                    buffer.append(NormalizedArtifact.create(
                        artifact_type="web_link", source_domain="browser",
                        data={"artifact_family": "browser_document_links", "url": url},
                        state="allocated", source_path=item.path,
                        source_row_id=str(idx), source_sha256=item.sha256,
                        parser="web_document_links", job_id=job_id))
                    if len(buffer) >= 500:
                        publish_buffer()
            for parser in parsers:
                fallback_override = header is not _not_streamed and (
                    parser.name == "forensic_fallback"
                    or (header is not None and int(item.size or 0) > 0
                        and len(header) == int(item.size))
                )
                if fallback_override:
                    ctx._read_bytes = read_cached
                try:
                    for art in parser.parse(item, ctx):
                        if len(bundle) > 1:
                            art.forensic["source_companions"] = [
                                {"path": it.path, "sha256": it.sha256, "size_bytes": it.size}
                                for it in bundle[1:]
                            ]
                        buffer.append(art)
                        if len(buffer) >= 500:
                            publish_buffer()
                finally:
                    ctx._read_bytes = base_reader
                    ctx.clear_byte_cache()
            if any(p.name == whatsapp.name for p in parsers) and not is_crypt_file(item.path):
                for art in SqliteHistoryAnalyzer().analyze(bundle, [], ctx):
                    buffer.append(art)
                    if len(buffer) >= 500:
                        publish_buffer()
            if ctx.extra["read_errors"]:
                raise ValueError("Acquired source/SQLite sidecar was unreadable")
            if storage:
                reason = "Web storage source preserved; native parser/OCR text is indexed separately. Encrypted WhatsApp Web messages require readable records and keys."
        except Exception as exc:
            reason = str(exc)
            errored = True
        finally:
            ctx._read_bytes = base_reader
            ctx.clear_byte_cache()
        if reason:
            buffer.append(NormalizedArtifact.create(
                artifact_type="web_storage_source" if storage else "priority_source_exception",
                source_domain="browser" if storage or any(p.name == browser.name for p in parsers) else "messaging_apps",
                data={"artifact_family": "web_storage_sources" if storage else "priority_exceptions",
                      "path": item.path, "note": reason, "reference_only": True},
                state="unverified", source_path=item.path, source_sha256=item.sha256,
                parser="priority_evidence", job_id=job_id))
        publish_buffer()
        # This event follows every record event for this source in FIFO order.
        # The writer commits all records and the source checkpoint together.
        emit("source", (source["id"], reason, item.path, errored))

    def _drain_writer():
        nonlocal processed, errors, active_path
        while True:
            try:
                kind, value = output.get(timeout=0.5)
            except queue.Empty:
                heartbeat()
                continue
            if kind == "stop":
                flush()
                return
            if kind == "records":
                source_id, arts = value
                pending_records.extend((source_id, art) for art in arts)
            elif kind == "source":
                source_id, reason, path, errored = value
                pending_sources.append((source_id, reason))
                processed += 1
                errors += int(errored)
                active_path = path
                if processed % 250 == 0 and pipeline_should_stop(writer_db[0], job_id):
                    flush()
                    raise StageWaiting("Priority evidence parsing paused by user")
            elif kind == "active":
                active_path = value
            elif kind == "deferred":
                diagnostic["deferred"] += 1
            if len(pending_sources) >= flush_sources or len(pending_records) >= flush_records:
                flush()
            else:
                heartbeat()

    def writer():
        from contextlib import nullcontext

        # A real tenant-scoped connection is opened/closed in this thread. Tests
        # supply an in-memory fake DB without a schema and reuse that object.
        try:
            if schema_name:
                from app.db.session import firm_session
                session_scope = firm_session(schema_name)
            else:
                session_scope = nullcontext(db)
            with session_scope as scoped:
                writer_db[0] = scoped
                _drain_writer()
        except BaseException as exc:
            writer_error.append(exc)
            try:
                writer_db[0].rollback()
            except Exception:
                pass
        finally:
            writer_finished.set()

    # Plan once: avoid routing 180k sources once for scheduling and again for
    # execution. Pictures and documents already have their bytes from acquisition;
    # only sources whose parser must see content are read, and every such source
    # in one compressed shard is read in that single pass. Re-opening the shard
    # per database was a multi-gigabyte decompress for a few kilobytes.
    read_cap = 120_000_000
    part_groups = defaultdict(list)
    metadata_jobs = []
    ordinary = []
    deferred_jobs = []

    def _source_meta(src) -> dict:
        raw = (src or {}).get("metadata") or {}
        if isinstance(raw, str):
            raw = json.loads(raw)
        return raw if isinstance(raw, dict) else {}

    def _content_budget(it, parsers, web_text, *, primary: bool) -> int:
        if not primary:
            size = int(it.size or 0)
            return size if 0 < size <= read_cap else read_cap
        full = shard_stream_budget(it, parsers, web_text=web_text)
        names = {getattr(parser, "name", "") for parser in parsers}
        needs_full = bool(web_text) or not names <= {"forensic_fallback", "files_media_parser"}
        size = int(it.size or 0)
        if full is None and needs_full and 0 < size <= read_cap:
            # Keep the whole source from this pass. A later individual read would
            # decompress the shard again from the first byte.
            full = size
        if full is not None:
            return int(full)
        ext = it.path.rsplit(".", 1)[-1].lower() if "." in it.path else ""
        if ext in {"eml", "emlx", "mbox"} and 0 < size <= 16 * 1024 * 1024:
            return 16 * 1024 * 1024
        return 4096

    for bundle in evidence_bundles(items):
        item = bundle[0]
        source = sources.get(item.path)
        if not source:
            raise RuntimeError(f"Priority evidence missing registered source: {item.path}")
        meta = _source_meta(source)
        if meta.get("priority_parsed_v4"):
            already_done += 1
            continue
        low = item.path.lower()
        parsers = registry.route(item, context)
        web_text = low.endswith((".url", ".webloc", ".html", ".htm"))
        storage = any(x in low for x in ("indexeddb", "local storage", "session storage", "webcachev01.dat"))
        if not parsers and not storage and not web_text:
            continue
        entry = (bundle, parsers, web_text, storage)
        # A metadata-only fallback for known OS binaries avoids re-decompressing
        # a massive archive to collect just four signature bytes. Ambiguous or
        # higher-value files are still content-examined normally.
        if can_defer_fallback_signature(item, parsers, bundle, mode=signature_mode,
                                        web_text=web_text, storage=storage):
            deferred_jobs.append(entry)
            continue
        names = {getattr(parser, "name", "") for parser in parsers}
        if not web_text and not storage and names <= {"files_media_parser"}:
            metadata_jobs.append(entry)
            continue
        member_sources = [sources.get(it.path) or {} for it in bundle]
        member_parts = {str(_source_meta(src).get("extracted_part_uri") or "") for src in member_sources}
        if (len(member_parts) == 1 and "" not in member_parts
                and all(not src.get("minio_uri") for src in member_sources)):
            part_groups[member_parts.pop()].append(entry)
        else:
            ordinary.append(entry)
    total_sources = already_done + (
        len(deferred_jobs) + len(metadata_jobs) + len(ordinary)
        + sum(map(len, part_groups.values()))
    )
    def _parse_deferred(entry):
        process(*entry, deferred=True)

    def _parse_regular(entry):
        process(*entry)

    sink = threading.Thread(target=writer, name="disk-priority-db-writer", daemon=False)
    sink.start()
    try:
        # Independent sources are parsed in eight slots, not under the DB
        # session lock. Every source's records flow through the bounded sink.
        for _ in run_bounded(_parse_deferred, deferred_jobs, slots=DISK_SLOTS):
            pass
        for _ in run_bounded(_parse_regular, metadata_jobs, slots=DISK_SLOTS):
            pass
        def _scan_part(part_entries):
            import copy
            from collections import OrderedDict

            part, entries = part_entries
            # Each shard has a separate cache; parsing never holds the DB lock.
            local = copy.copy(context)
            local.extra = dict(context.extra)
            local.extra["read_errors"] = set()
            local._byte_cache = OrderedDict()
            with db_lock:
                diagnostic["shard_opens"] += 1
            def _tar_name(it) -> str:
                src = sources.get(it.path.replace("\\", "/")) or {}
                meta = _source_meta(src)
                return str(meta.get("source_path") or it.path).replace("\\", "/")

            waiting: dict[str, list[tuple]] = defaultdict(list)
            budgets: dict[str, int] = {}
            hashes: dict[str, str] = {}
            sizes: dict[str, int] = {}
            for entry in entries:
                bundle, parsers, web_text, _storage = entry
                for index, it in enumerate(bundle):
                    path = _tar_name(it)
                    waiting[path].append((entry, it))
                    budget = _content_budget(it, parsers, web_text, primary=index == 0)
                    budgets[path] = max(int(budgets.get(path) or 0), int(budget or 0))
                    if len(waiting[path]) == 1:
                        if it.sha256:
                            hashes[path] = it.sha256
                        if int(it.size or 0) > 0:
                            sizes[path] = int(it.size)
                    else:
                        # Two archive members share this name. One hash cannot
                        # describe both, so each copy is read on its own.
                        hashes.pop(path, None)
                        sizes.pop(path, None)
            cache: dict[str, bytes | None] = {}
            finished: set[int] = set()

            def serve(path, max_bytes=read_cap, _cache=cache, _ctx=local):
                key = path.replace("\\", "/")
                if key in _cache or path in _cache:
                    blob = _cache[key] if key in _cache else _cache[path]
                    if blob is None:
                        _ctx.extra["read_errors"].add(path)
                        active_errors = getattr(read_errors_local, "current", None)
                        if active_errors is not None:
                            active_errors.add(path)
                        return None
                    return blob[:max_bytes]
                return read_original(path, max_bytes)

            def finish(entry, header=_not_streamed):
                bundle = entry[0]
                with db_lock:
                    diagnostic["shard_files"] += 1
                if len(bundle) == 1 and header is not _not_streamed:
                    process(*entry, header=header, work_ctx=local)
                else:
                    previous = local._read_bytes
                    local._read_bytes = serve
                    try:
                        process(*entry, work_ctx=local)
                    finally:
                        local._read_bytes = previous
                for it in bundle:
                    cache.pop(it.path.replace("\\", "/"), None)

            for path, header in iter_files_from_part(
                part, set(waiting), max_bytes_by_path=budgets,
                verify_sha256_by_path=hashes, verify_size_by_path=sizes,
                repeat_by_path={name: len(items) for name, items in waiting.items()},
            ):
                queued = waiting.get(path) or []
                if not queued:
                    continue
                entry, it = queued.pop(0)
                cache[it.path.replace("\\", "/")] = header
                if id(entry) in finished:
                    continue
                if any(member.path.replace("\\", "/") not in cache for member in entry[0]):
                    continue
                finished.add(id(entry))
                finish(entry, header if len(entry[0]) == 1 else _not_streamed)
            for entry in entries:
                if id(entry) in finished:
                    continue
                finished.add(id(entry))
                finish(entry)

        # Different compressed parts are independent. One tar.zst is still read
        # in order; eight parts may be open at once. Writer commits continuously.
        for _ in run_bounded(_scan_part, part_groups.items(), slots=DISK_SLOTS):
            pass
        for _ in run_bounded(_parse_regular, ordinary, slots=DISK_SLOTS):
            pass
    finally:
        # The sentinel is inserted after every submitted record/source event.
        # A failed writer cannot leave us permanently blocked on a full queue.
        if not writer_finished.is_set():
            while not writer_finished.is_set():
                try:
                    output.put(("stop", None), timeout=0.25)
                    break
                except queue.Full:
                    continue
        sink.join()
    if writer_error:
        raise writer_error[0]
    return {"sources_processed": processed, "records_written": written, "errors": errors,
            "deferred_signatures": diagnostic["deferred"],
            "streamed_part_groups": diagnostic["shard_opens"],
            "streamed_source_files": diagnostic["shard_files"],
            "individual_source_reads": diagnostic["individual_reads"],
            "individual_read_seconds": round(time_by_phase["individual_read"], 3),
            "db_insert_seconds": round(time_by_phase["db_insert"], 3),
            "priority_cpu_slots": DISK_SLOTS, "priority_async_writer": True}

def chunk_disk_priority_records(db, job_id):
    from psycopg2.extras import execute_values

    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.job_control import pipeline_should_stop

    last = ""
    count = 0
    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Priority RAG chunking paused by user")
        rows = fetchall(
            db,
            """SELECT * FROM forensic_priority_records p WHERE p.job_id=:jid AND p.artifact_id>:last
            AND NOT EXISTS (SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid AND rc.metadata->>'priority_artifact_id'=p.artifact_id AND rc.metadata->>'chunk_policy'=:policy)
            ORDER BY p.artifact_id LIMIT 128""",
            {"jid": job_id, "last": last, "policy": CHUNK_POLICY},
        )
        if not rows:
            break
        execute(
            db,
            "DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths)",
            {
                "jid": job_id,
                "paths": [f"priority://artifact/{r['artifact_id']}" for r in rows],
            },
        )
        values = []
        for row in rows:
            content = _dumps(
                {
                    "artifact_type": row["artifact_type"],
                    "timestamp_utc": row["timestamp_utc"],
                    "state": row["state"],
                    "data": row["data"],
                    "forensic": row["forensic"],
                }
            ).replace("\x00", "")
            meta = _dumps(
                {
                    "priority_artifact_id": row["artifact_id"],
                    "job_artifact_id": str(row["job_artifact_id"]),
                    "serial_pipeline": True,
                    "chunk_policy": CHUNK_POLICY,
                }
            )
            for idx, chunk in enumerate(
                _chunk_text(content, CHUNK_SIZE, CHUNK_OVERLAP)
            ):
                values.append(
                    (
                        job_id,
                        f"priority://artifact/{row['artifact_id']}",
                        idx,
                        chunk,
                        meta,
                    )
                )
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                "INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,chunk_type,metadata) VALUES %s",
                values,
                template="(%s,%s,%s,%s,'evidence',%s::jsonb)",
                page_size=500,
            )
        count += len(values)
        last = rows[-1]["artifact_id"]
        db.commit()
    return count


def priority_record_table(db, job_id):
    from app.forensic_common.job_types import is_mobile_job

    name = (
        "mobile_normalized_artifacts"
        if is_mobile_job(db, job_id)
        else "forensic_priority_records"
    )
    exists = fetchone(db, "SELECT to_regclass(:name)::text AS name", {"name": name})
    return name if exists and exists["name"] else None


def priority_evidence_page(
    db, job_id, *, family="whatsapp_messages", page=1, page_size=50
):
    from app.forensic_common.job_types import is_mobile_job
    from app.services.mobile_forensic.parsers.files_media import (
        _AUDIO,
        _DOC,
        _IMAGE,
        _VIDEO,
    )

    table = priority_record_table(db, job_id)
    if not table:
        return {
            "items": [],
            "total": 0,
            "page": page,
            "families": {key: 0 for key in PRIORITY_FAMILIES},
        }
    predicates = {
        "whatsapp_messages": "data->>'application'='whatsapp' AND artifact_type IN ('app_message','app_chat') AND state NOT IN ('database_deleted','unverified','freelist_candidate')",
        "deleted_whatsapp": "data->>'artifact_family'='deleted_whatsapp' OR (data->>'application'='whatsapp' AND state IN ('database_deleted','unverified','freelist_candidate') AND artifact_type IN ('app_message','recovered_chat_candidate'))",
        "browser": "source_domain='browser'",
        "pictures": "artifact_type='photo' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'image/%')",
        "videos": "artifact_type='video' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'video/%')",
        "audio": "artifact_type='audio' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'audio/%')",
        "documents": "artifact_type='document'",
        "messages": "artifact_type IN ('app_message','sms','mms','sms_message','mms_message')",
        "emails": "source_domain='email' OR artifact_type IN ('email_message','email_attachment')",
        "binary": "artifact_type IN ('binary_string','binary_field')",
        "structured_data": "artifact_type='structured_record'",
        "downloads": "artifact_type IN ('browser_download','download') OR data->>'is_download'='true' OR data->>'source_bucket'='download'",
        "applications": "artifact_type IN ('installed_app','installed_application','app_install','application','application_record')",
        "accounts": "artifact_type IN ('device_account','device_user')",
    }
    if family not in predicates:
        raise ValueError("Unknown priority evidence category")
    # All category counts in one job-filtered pass, not one round trip per tab.
    count_row=fetchone(db,'SELECT '+','.join(f'count(*) FILTER (WHERE {predicate}) AS {key}'
        for key,predicate in predicates.items())+f' FROM {table} WHERE job_id=:jid',{'jid':job_id})
    families={key:int(count_row.get(key) or 0) for key in predicates}
    disk_files = not is_mobile_job(db, job_id)
    file_categories = {
        "pictures": (_IMAGE, "image"),
        "videos": (_VIDEO, "video"),
        "audio": (_AUDIO, "audio"),
        "documents": (_DOC, "document"),
    }
    file_predicate = """(lower(CASE WHEN left(extension,1)='.' THEN extension ELSE '.'||extension END)=ANY(:extensions)
        OR metadata->>'file_kind'=:kind OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE :mime
        OR (:kind='document' AND (COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE 'text/%'
            OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') IN ('application/pdf','application/msword','application/rtf','application/json','application/xml')
            OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE 'application/vnd.%')))"""
    if disk_files:
        for key, (extensions, kind) in file_categories.items():
            families[key] = int(
                fetchone(
                    db,
                    f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid AND {file_predicate}",
                    {
                        "jid": job_id,
                        "extensions": sorted(extensions),
                        "kind": kind,
                        "mime": kind + "/%",
                    },
                )["c"]
            )
        if family in file_categories:
            extensions, kind = file_categories[family]
            files = fetchall(
                db,
                f"""SELECT id,file_path,file_name,sha256,size_bytes,metadata FROM job_artifacts WHERE job_id=:jid
                AND {file_predicate} ORDER BY file_path,id LIMIT :lim OFFSET :off""",
                {
                    "jid": job_id,
                    "extensions": sorted(extensions),
                    "kind": kind,
                    "mime": kind + "/%",
                    "lim": page_size,
                    "off": (page - 1) * page_size,
                },
            )
            items = []
            for file in files:
                metadata = file.get("metadata") or {}
                state = (
                    "filesystem_recovered"
                    if metadata.get("is_deleted") is True
                    else "allocated"
                )
                items.append(
                    {
                        "artifact_id": str(file["id"]),
                        "job_artifact_id": str(file["id"]),
                        "artifact_type": kind,
                        "timestamp_utc": None,
                        "state": state,
                        "data": {
                            "name": file["file_name"],
                            "path": file["file_path"],
                            "size": file["size_bytes"],
                            "metadata": metadata,
                        },
                        "forensic": {
                            "source_path": file["file_path"],
                            "source_sha256": file["sha256"]
                            or metadata.get("source_sha256"),
                            "state": state,
                        },
                        "linked_media": [],
                    }
                )
            return {
                "items": items,
                "total": families[family],
                "families": families,
                "page": page,
            }
    items = fetchall(
        db,
        f"""SELECT artifact_id,artifact_type,source_domain,timestamp_utc,state,data,forensic
        FROM {table} WHERE job_id=:jid AND ({predicates[family]}) ORDER BY timestamp_utc DESC NULLS LAST,artifact_id
        LIMIT :lim OFFSET :off""",
        {"jid": job_id, "lim": page_size, "off": (page - 1) * page_size},
    )
    for row in items:
        source = row["forensic"].get("source_path")
        file = fetchone(
            db,
            "SELECT id FROM job_artifacts WHERE job_id=:jid AND file_path=:path",
            {"jid": job_id, "path": source},
        )
        row["job_artifact_id"] = str(file["id"]) if file else None
        data = row["data"] or {}
        path = str(
            data.get("media_path")
            or data.get("attachment_path")
            or (data.get("path") if data.get("reference_only") else "")
            or ""
        ).replace("\\", "/")
        name = str(
            data.get("media_name")
            or PurePosixPath(path).name
            or (data.get("name") if data.get("reference_only") else "")
            or ""
        )
        row["linked_media"] = []
        if path or name:
            # Exact path and basename candidates are visibly distinguished.
            row["linked_media"] = [
                dict(
                    file,
                    match_basis="exact_path"
                    if file["file_path"].replace("\\", "/") == path
                    else "filename_candidate",
                )
                for file in fetchall(
                    db,
                    "SELECT id,file_path,sha256 FROM job_artifacts WHERE job_id=:jid AND (file_path=:path OR file_name=:name) ORDER BY file_path",
                    {"jid": job_id, "path": path, "name": name},
                )
            ]
    return {
        "items": items,
        "total": families[family],
        "families": families,
        "page": page,
    }


def mobile_priority_coverage(db, job_id):
    """Zero recovered records describes this acquisition, not absence on a phone."""
    from app.services.mobile_forensic.storage import upsert_coverage

    counts = priority_evidence_page(db, job_id, page_size=1)["families"]
    for family in PRIORITY_FAMILIES:
        count = counts[family]
        upsert_coverage(
            db,
            job_id,
            "priority_" + family,
            discovered=0,
            processed=0,
            artifacts=count,
            recovered=0,
            errors=0,
            status="available" if count else "acquisition_gap",
            details={
                "priority": True,
                "artifact_count": count,
                "note": "Records captured from acquired evidence."
                if count
                else "No readable records in this acquisition. Check private app access, source completeness and encryption keys; deleted data may have been overwritten.",
            },
        )
    return counts
