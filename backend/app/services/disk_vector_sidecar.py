"""Resumable, source-preserving pgvector backfill for the serial disk pipeline.

The serial pipeline already writes complete source-linked chunks. Rebuilding
those chunks using the legacy dual-RAG index would DELETE and recreate them;
instead fill only null embeddings in place. The Celery task runs on the
rag-index GPU worker after enrichment, while the serial CPU graph stage runs.
The Redis/host GPU lease prevents this worker and GPU OCR competing for VRAM.
"""
from __future__ import annotations

import logging

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("forensic.disk_vectors")
_MIN_UUID = "00000000-0000-0000-0000-000000000000"


def count_missing_serial_vectors(db, job_id) -> int:
    row = fetchone(db, """SELECT count(*) AS c FROM rag_chunks
        WHERE job_id=:jid AND embedding_v2 IS NULL AND length(content)>0""",
                   {"jid":job_id}) or {}
    return int(row.get("c") or 0)


def schedule_disk_vectors(db, job_id, *, schema_name):
    """Claim exactly one GPU task once authoritative Disk text is complete."""
    from app.config import get_settings

    if not bool(get_settings().rag_embedding_enabled):
        return {"status":"disabled"}
    missing = count_missing_serial_vectors(db, job_id)
    if not missing:
        return {"status":"up_to_date", "pending":0}

    from app.services.safe_parallel import claim_sidecar, ensure_sidecar_schema

    # A disk job may reach enrichment without an earlier optional sidecar.
    ensure_sidecar_schema(db)
    db.commit()
    name = "disk_vectors"
    previous = fetchone(db,
        "SELECT status FROM pipeline_sidecar_runs WHERE job_id=:jid AND sidecar=:sidecar",
        {"jid":job_id, "sidecar":name}) or {}
    # Controlled restarts may append new text under the same chunk policy.
    # Clear only the completed *derived* worker claim, never RAG rows/evidence.
    if previous.get("status") == "done":
        execute(db, """UPDATE pipeline_sidecar_runs SET status='pending',updated_at=NOW()
                WHERE job_id=:jid AND sidecar=:sidecar AND status='done'""",
                {"jid":job_id,"sidecar":name})
        db.commit()
    tid = claim_sidecar(db, job_id, name,
                        details={"parallel_with":"enrichment", "pending_vectors":missing,
                                 "gpu_slot":"exclusive", "source_preserving":True})
    if not tid:
        return {"status":"already_queued", "pending":missing}
    from app.tasks import disk_vector_sidecar_task
    from app.services.safe_parallel import finish_sidecar
    try:
        disk_vector_sidecar_task.apply_async(
            args=(schema_name, str(job_id), tid), queue="rag-index", task_id=tid)
    except Exception as exc:
        finish_sidecar(db, job_id, name, tid, status="failed",
                       details={"dispatch_error":str(exc)[:500], "pending_vectors":missing})
        raise
    return {"status":"queued", "pending":missing, "task_id":tid}


def embed_missing_disk_vectors(db, job_id, *, on_batch=None) -> dict:
    """Backfill null vectors with one CUDA model and batched transactional writes.

    Each commit is a resumable checkpoint: rows written before interruption
    remain exactly as they were. A mismatched vector dimension fails closed.
    """
    from app.config import get_settings
    from app.services.embedding_gpu import embed_texts, resolve_device, unload_embedder
    from app.services.job_locks import gpu_heavy_slot
    from app.services.job_control import pipeline_should_stop
    from psycopg2.extras import execute_values

    settings = get_settings()
    if not settings.rag_embedding_enabled:
        return {"status":"disabled", "embedded":0}
    expected_dim = int(settings.rag_embedding_dim or 1024)
    per_gpu_batch = max(1, min(64, int(settings.rag_batch_size or 24)))
    fetch_batch = max(per_gpu_batch, min(512, per_gpu_batch * 8))
    device, use_cuda = resolve_device(settings.rag_embedding_device or "cpu")
    last_id = _MIN_UUID
    embedded = 0
    batches = 0
    baseline_missing = count_missing_serial_vectors(db, job_id)
    if not baseline_missing:
        return {"status":"ok", "embedded":0, "pending":0, "device":device}

    from contextlib import nullcontext
    gpu_scope = gpu_heavy_slot("disk_serial_pgvector", fail_closed=True) if use_cuda else nullcontext()
    try:
        with gpu_scope:
            while True:
                if pipeline_should_stop(db, job_id):
                    raise RuntimeError("Disk vector indexing paused; committed vectors are resumable")
                rows = fetchall(db,
                    """SELECT id::text AS id, content FROM rag_chunks
                        WHERE job_id=:jid AND embedding_v2 IS NULL
                          AND length(content)>0 AND id>CAST(:after AS uuid)
                        ORDER BY id LIMIT :lim""",
                    {"jid":job_id, "after":last_id, "lim":fetch_batch})
                if not rows:
                    # Any newly inserted lower UUIDs will be detected by the
                    # final completeness barrier; do not spin forever.
                    break
                texts = [str(r["content"]) for r in rows]
                vectors = []
                for start in range(0, len(texts), per_gpu_batch):
                    segment = texts[start:start+per_gpu_batch]
                    output = embed_texts(segment,
                        model_name=settings.rag_embedding_model,
                        device=settings.rag_embedding_device,
                        batch_size=per_gpu_batch)
                    if len(output or []) != len(segment):
                        raise RuntimeError("CUDA embedding model returned incomplete vector count")
                    for vec in output:
                        if not vec or len(vec) != expected_dim:
                            raise RuntimeError(
                                f"Embedding dimension mismatch: expected {expected_dim}; "
                                f"model returned {len(vec) if vec else 0}")
                    vectors.extend(output)
                values = [
                    (str(row["id"]), "[" + ",".join(f"{float(v):.8f}" for v in vec) + "]", str(job_id))
                    for row, vec in zip(rows, vectors)
                ]
                # The only write is a deterministic, source-preserving UPDATE.
                # Batch update prevents a SQL round-trip for every CUDA vector.
                with db.connection().connection.cursor() as cur:
                    execute_values(cur,
                        """UPDATE rag_chunks AS c SET embedding_v2=CAST(v.emb AS vector)
                            FROM (VALUES %s) AS v(id,emb,jid)
                            WHERE c.id=v.id AND c.job_id=v.jid
                              AND c.embedding_v2 IS NULL""",
                        values,
                        template="(%s::uuid,%s::text,%s::uuid)",
                        page_size=min(512,len(values)))
                db.commit()
                embedded += len(values)
                batches += 1
                last_id = str(rows[-1]["id"])
                if on_batch:
                    on_batch(embedded, baseline_missing, device)
    finally:
        if use_cuda:
            # GLM-OCR and the embedding model occupy the same 12GB GPU.
            unload_embedder()

    pending = count_missing_serial_vectors(db, job_id)
    return {"status":"ok" if not pending else "partial", "embedded":embedded,
            "pending":pending, "initial_pending":baseline_missing,
            "batches":batches, "device":device,
            "resumable":True, "source_chunks_unchanged":True}
