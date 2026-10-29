"""Neo4j GraphRAG sync — encyclopedia + job evidence + parsed artifact edges."""

from __future__ import annotations

import json
import logging
import os
import random
import time
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("neo4j_sync")

_driver = None
_driver_failed = False


def _neo4j_uris() -> list[str]:
    """Host .env uses localhost. A container must use the published bolt port or the Neo4j service."""
    settings = get_settings()
    uri = settings.neo4j_uri
    host = uri.split("://", 1)[-1].split("/")[0]
    name, _, port = host.partition(":")
    port = port or "7687"
    in_container = os.path.exists("/.dockerenv")
    if in_container and name in {"localhost", "127.0.0.1", "::1"}:
        uri = f"bolt://host.docker.internal:{port}"
    candidates = [uri]
    if in_container:
        for extra in (f"bolt://neo4j:{port}", f"bolt://host.docker.internal:{port}"):
            if extra not in candidates:
                candidates.append(extra)
    return candidates


def _get_driver():
    global _driver, _driver_failed
    if _driver_failed:
        return None
    if _driver is not None:
        return _driver
    settings = get_settings()
    last_error = None
    try:
        from neo4j import GraphDatabase
    except Exception as exc:
        log.warning("Neo4j unavailable: %s", exc)
        _driver_failed = True
        return None
    for uri in _neo4j_uris():
        try:
            driver = GraphDatabase.driver(uri, auth=(settings.neo4j_user, settings.neo4j_password))
            driver.verify_connectivity()
            _driver = driver
            return _driver
        except Exception as exc:
            last_error = exc
    log.warning("Neo4j unavailable: %s", last_error)
    _driver_failed = True
    return None


def neo4j_available() -> bool:
    return _get_driver() is not None


# Eight Neo4j sessions at a time. The semaphore caps the queue as well as the runners.
GRAPH_WRITE_SLOTS = max(1, min(8, int(os.getenv("POLARON_GRAPH_WRITE_SLOTS", "8"))))
GRAPH_ROW_BATCH = 2000

# MERGE uses these lookups. A missing index turns every row into a label scan and
# makes parallel sessions block each other.
_GRAPH_INDEXES = (
    (
        "CREATE CONSTRAINT polaron_job_id IF NOT EXISTS FOR (n:Job) REQUIRE n.id IS UNIQUE",
        "CREATE INDEX polaron_job_id IF NOT EXISTS FOR (n:Job) ON (n.id)",
    ),
    (
        "CREATE CONSTRAINT polaron_evidence_file IF NOT EXISTS FOR (n:EvidenceFile) REQUIRE (n.job_id, n.path) IS UNIQUE",
        "CREATE INDEX polaron_evidence_file IF NOT EXISTS FOR (n:EvidenceFile) ON (n.job_id, n.path)",
    ),
    (
        "CREATE CONSTRAINT polaron_evidence_record IF NOT EXISTS FOR (n:EvidenceRecord) REQUIRE (n.job_id, n.id) IS UNIQUE",
        "CREATE INDEX polaron_evidence_record IF NOT EXISTS FOR (n:EvidenceRecord) ON (n.job_id, n.id)",
    ),
    (
        "CREATE CONSTRAINT polaron_mobile_artifact IF NOT EXISTS FOR (n:MobileArtifact) REQUIRE (n.job_id, n.id) IS UNIQUE",
        "CREATE INDEX polaron_mobile_artifact IF NOT EXISTS FOR (n:MobileArtifact) ON (n.job_id, n.id)",
    ),
)


def _ensure_graph_indexes(driver) -> None:
    with driver.session() as session:
        for constraint, index in _GRAPH_INDEXES:
            try:
                session.run(constraint).consume()
            except Exception as exc:
                log.warning("Graph constraint unavailable (%s); creating an index instead", exc)
                try:
                    session.run(index).consume()
                except Exception:
                    log.warning("Graph index unavailable", exc_info=True)


def _mark_graph_phase(driver, job_id: str, flag: str) -> None:
    """Record a finished phase on the job node. Writers do not merge this node."""
    with driver.session() as session:
        session.run(
            f"MATCH (j:Job {{id:$jid}}) SET j.{flag}=true",
            jid=job_id,
        ).consume()


def _partition_by_key(rows: list[dict], slots: int, key: str) -> list[list[dict]]:
    """Keep rows that share a key in one batch so parallel merges do not lock it twice."""
    width = max(1, min(int(slots or 1), GRAPH_WRITE_SLOTS))
    buckets: list[list[dict]] = [[] for _ in range(width)]
    for row in rows:
        token = str(row.get(key) or row.get("id") or "")
        buckets[hash(token) % width].append(row)
    return [bucket for bucket in buckets if bucket]


def _write_graph_batches(driver, batches, write_fn) -> int:
    """Run independent graph batches with at most GRAPH_WRITE_SLOTS sessions."""
    import time
    from concurrent.futures import ThreadPoolExecutor
    from threading import BoundedSemaphore

    pending = [batch for batch in batches if batch]
    if not pending:
        return 0
    slots = min(GRAPH_WRITE_SLOTS, len(pending))
    gate = BoundedSemaphore(GRAPH_WRITE_SLOTS)

    def run(batch):
        with gate:
            for attempt in range(5):
                try:
                    with driver.session() as session:
                        return int(write_fn(session, batch) or 0)
                except Exception as exc:
                    text = str(exc).lower()
                    retryable = "deadlock" in text or "constraint" in text
                    if not retryable or attempt == 4:
                        raise
                    time.sleep(0.25 * (attempt + 1))
            return 0

    with ThreadPoolExecutor(max_workers=slots, thread_name_prefix="graph-write") as pool:
        return sum(pool.map(run, pending))


_UNWIND_CHUNK = 5000

# V1.10.9: one UNWIND statement per relationship type and batch. The previous
# code sent one Cypher statement (one round trip, one transaction) per parsed
# record, so a parsed EVTX with 40,000 events cost 40,000+ round trips.
_PARSED_EDGE_CYPHER = {
    "process": """UNWIND $rows AS r
        MERGE (p:Process {name: r.name, job_id: $jid})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:PROVES_EXECUTION]->(p)""",
    "link": """UNWIND $rows AS r
        MERGE (f:File {path: r.target})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:LINKS_TO]->(f)""",
    "event": """UNWIND $rows AS r
        MERGE (ev:TimelineEvent {event_id: r.eid, job_id: $jid})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:CONTAINS_EVENT]->(ev)""",
    "registry": """UNWIND $rows AS r
        MERGE (rk:RegistryKey {path: r.rkey})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:STORES_KEY]->(rk)""",
    "user": """UNWIND $rows AS r
        MERGE (u:UserAccount {name: r.uname, job_id: $jid})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:BELONGS_TO_USER]->(u)""",
    "table": """UNWIND $rows AS r
        MERGE (db:Database {table: r.tbl, job_id: $jid})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:HAS_TABLE]->(db)""",
    "encyclopedia": """UNWIND $rows AS r
        MERGE (a:Artifact {id: r.aid})
        MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
        MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)""",
}
_EVIDENCE_FILE_CYPHER = """UNWIND $rows AS r
    MERGE (e:EvidenceFile {path: r.path, job_id: $jid})
    SET e.parser = r.parser"""


def _collect_parsed_edges(parsed_rows: list[dict], max_records: int | None) -> tuple[list[dict], dict[str, list[dict]]]:
    """Same records and edge rules as before, grouped by relationship type."""
    files: list[dict] = []
    edges: dict[str, list[dict]] = {key: [] for key in _PARSED_EDGE_CYPHER}
    for row in parsed_rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                norm = [{"text": norm}]
        if not isinstance(norm, list):
            norm = [norm] if norm else []
        path = row.get("file_path", "")
        aid = row.get("encyclopedia_artifact_id")
        files.append({"path": path, "parser": row.get("parser_name", "")})
        for rec in norm if max_records is None else norm[:max_records]:
            if not isinstance(rec, dict):
                continue
            if rec.get("executable") or rec.get("format") == "prefetch_scca":
                edges["process"].append({"name": rec.get("executable", ""), "path": path})
            if rec.get("target") or rec.get("target_paths"):
                target = rec.get("target") or (rec.get("target_paths") or [""])[0]
                edges["link"].append({"target": str(target)[:500], "path": path})
            if rec.get("event_id"):
                edges["event"].append({"eid": str(rec["event_id"]), "path": path})
            if rec.get("registry_key"):
                edges["registry"].append({"rkey": str(rec["registry_key"])[:500], "path": path})
            if rec.get("user_profile"):
                edges["user"].append({"uname": rec["user_profile"], "path": path})
            if rec.get("table"):
                edges["table"].append({"tbl": rec["table"], "path": path})
        if aid:
            edges["encyclopedia"].append({"aid": aid, "path": path})
    return files, edges


def _unwind(session, cypher: str, rows: list[dict], job_id: str) -> None:
    for start in range(0, len(rows), _UNWIND_CHUNK):
        result = session.run(cypher, rows=rows[start:start + _UNWIND_CHUNK], jid=job_id)
        # Consume so a write error surfaces here (and is retried by the caller).
        consume = getattr(result, "consume", None)
        if callable(consume):
            consume()


def _sync_parsed_edges(session, job_id: str, parsed_rows: list[dict], *, max_records: int | None = 20) -> int:
    """Create evidence-derived graph edges from parse results (batched UNWIND)."""
    files, edges = _collect_parsed_edges(parsed_rows, max_records)
    if files:
        _unwind(session, _EVIDENCE_FILE_CYPHER, files, job_id)
    total = 0
    for key, rows in edges.items():
        if rows:
            _unwind(session, _PARSED_EDGE_CYPHER[key], rows, job_id)
            total += len(rows)
    return total


def sync_job_graph(db, job_id: str, *, schema_name: str) -> dict:
    driver = _get_driver()
    if driver is None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, status, error)
               VALUES (:jid, 'skipped', 'Neo4j unavailable')
               ON CONFLICT (job_id) DO UPDATE SET status='skipped', error='Neo4j unavailable'""",
            {"jid": job_id},
        )
        db.commit()
        return {"status": "skipped", "nodes": 0, "edges": 0}

    arts = fetchall(
        db,
        """SELECT encyclopedia_artifact_id, file_path, sha256 FROM job_artifacts
           WHERE job_id=:jid AND encyclopedia_artifact_id IS NOT NULL LIMIT 5000""",
        {"jid": job_id},
    )
    parsed_rows = fetchall(
        db,
        """SELECT ja.file_path, ja.encyclopedia_artifact_id, apr.parser_name, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid LIMIT 5000""",
        {"jid": job_id},
    )
    enc_rels = db.execute(
        __import__("sqlalchemy").text(
            "SELECT from_artifact_id, to_artifact_id, relationship_type FROM public.encyclopedia_relationships LIMIT 5000"
        )
    ).mappings().all()

    nodes = 0
    edges = 0

    def _mark_syncing() -> None:
        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, status, error)
               VALUES (:jid, :n, :e, 'syncing', NULL)
               ON CONFLICT (job_id) DO UPDATE SET
                 nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
                 status='syncing', error=NULL""",
            {"jid": job_id, "n": nodes, "e": edges},
        )
        db.commit()

    _mark_syncing()
    try:
        with driver.session() as session:
            session.run("MERGE (j:Job {id: $jid}) SET j.updated_at = datetime()", jid=job_id)
            nodes += 1

            for i, a in enumerate(arts):
                session.run(
                    """
                    MERGE (e:EvidenceFile {path: $path, job_id: $jid})
                    SET e.sha256 = $sha, e.artifact_id = $aid
                    WITH e
                    MERGE (a:Artifact {id: $aid})
                    MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a)
                    MERGE (j:Job {id: $jid})-[:CONTAINS]->(e)
                    """,
                    path=a["file_path"],
                    jid=job_id,
                    sha=a.get("sha256"),
                    aid=a["encyclopedia_artifact_id"],
                )
                nodes += 2
                edges += 2
                if (i + 1) % 200 == 0:
                    _mark_syncing()

            for r in enc_rels:
                session.run(
                    """
                    MERGE (a:Artifact {id: $from})
                    MERGE (b:Artifact {id: $to})
                    MERGE (a)-[:RELATED_TO {type: $typ}]->(b)
                    """,
                    **{"from": r["from_artifact_id"], "to": r["to_artifact_id"], "typ": r["relationship_type"]},
                )
                edges += 1

            edges += _sync_parsed_edges(session, job_id, [dict(r) for r in parsed_rows])
    except Exception as exc:
        msg = str(exc).lower()
        if any(tok in msg for tok in ("unavailable", "refused", "connection", "timeout", "auth")):
            execute(
                db,
                """INSERT INTO graph_sync_state (job_id, status, error)
                   VALUES (:jid, 'skipped', :err)
                   ON CONFLICT (job_id) DO UPDATE SET status='skipped', error=:err""",
                {"jid": job_id, "err": f"Neo4j unavailable: {exc}"[:400]},
            )
            db.commit()
            return {"status": "skipped", "nodes": nodes, "edges": edges}
        raise

    execute(
        db,
        """INSERT INTO graph_sync_state (job_id, nodes_synced, edges_synced, last_sync_at, status, error)
           VALUES (:jid, :n, :e, NOW(), 'ok', NULL)
           ON CONFLICT (job_id) DO UPDATE SET
             nodes_synced=EXCLUDED.nodes_synced, edges_synced=EXCLUDED.edges_synced,
             last_sync_at=NOW(), status='ok', error=NULL""",
        {"jid": job_id, "n": nodes, "e": edges},
    )
    db.commit()
    from app.services.forensic_serial_policy import current_stage

    if current_stage() is not None:
        return {"status": "ok", "nodes": nodes, "edges": edges}
    # Kick entity/annotation/ontology immediately — do not wait for full corpus RAG.
    try:
        from app.services.pipeline_orchestrator import _rag_enrich_status

        enrich_done, enrich_busy = _rag_enrich_status(db, job_id)
        if not enrich_done and not enrich_busy:
            from app.tasks import rag_enrich_task

            rag_enrich_task.delay(schema_name, job_id)
    except Exception:
        pass
    return {"status": "ok", "nodes": nodes, "edges": edges}


def sync_graph_files_phase(db, job_id: str, *, driver, total: int, stop=None, stage: str = "graph") -> int:
    """EvidenceFile nodes for every registered file, then mark graph_files_done.

    V1.11.0: this phase needs only the registered files, which are final once
    registration ends. The graph_files sidecar runs it while native parsing and
    the later stages are still busy; the serial graph stage then finds it done.
    MERGE makes a repeated or concurrent run harmless.
    """
    from app.services.forensic_serial_stages import report_progress
    from app.services.progress_agent import note_operation

    last = "00000000-0000-0000-0000-000000000000"
    scanned = 0

    # Shared Artifact nodes can be referenced from many EvidenceFile rows. Parallel
    # relationship-group updates against those shared nodes caused Neo4j deadlocks.
    # Keep this phase's writes serialized and bounded, while letting independent
    # PostgreSQL parsing/OCR tasks run concurrently.
    def write_files_batch(rows):
        payload = [
            {"path": r["file_path"], "sha": r["sha256"], "aid": r["encyclopedia_artifact_id"]}
            for r in rows
        ]
        payload.sort(key=lambda r: (str(r["aid"] or ""), str(r["path"] or "")))

        def transact(tx):
            tx.run("""UNWIND $rows AS r
                MERGE (e:EvidenceFile {path:r.path,job_id:$jid})
                SET e.sha256=r.sha,e.artifact_id=r.aid
                FOREACH (aid IN CASE WHEN r.aid IS NULL THEN [] ELSE [r.aid] END |
                    MERGE (a:Artifact {id:aid})
                    MERGE (e)-[:MAPS_TO_ENCYCLOPEDIA]->(a))""",
                rows=payload, jid=job_id).consume()
            return len(payload)

        # Transaction functions are replay-safe because graph writes use MERGE.
        # Neo4j's managed transactions retry transient failures. A bounded outer
        # retry handles exhausted transient retries without replaying completed
        # chunks or silently claiming success.
        for attempt in range(5):
            try:
                with driver.session() as session:
                    return int(session.execute_write(transact))
            except Exception as exc:
                code = str(getattr(exc, "code", ""))
                retryable = (
                    code.startswith("Neo.TransientError.")
                    or "deadlock" in str(exc).lower()
                )
                if not retryable or attempt == 4:
                    raise
                delay = min(5.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.1)
                log.warning("Neo4j graph_files transient failure, retry %d/5 in %.2fs: %s", attempt+1, delay, exc)
                time.sleep(delay)
        raise RuntimeError("graph_files retries exhausted")

    while True:
        if stop is not None:
            stop()
        wave = []
        for _ in range(GRAPH_WRITE_SLOTS):
            rows = fetchall(db, """SELECT id,file_path,sha256,encyclopedia_artifact_id FROM job_artifacts
                WHERE job_id=:jid AND id>:last ORDER BY id LIMIT 500""", {"jid": job_id, "last": last})
            db.commit()
            if not rows:
                break
            last = str(rows[-1]["id"])
            wave.append([dict(row) for row in rows])
        if not wave:
            break
        note_operation(db, job_id, stage, "Graph synchronization of extracted evidence", advanced=True, timeout_seconds=900)
        # A wave is fetched in cursor order; each subset commits independently.
        # 100-row transactions reduce shared relationship-group lock duration.
        for group in wave:
            for i in range(0, len(group), 100):
                scanned += write_files_batch(group[i:i + 100])
        if stage == "graph":
            report_progress(db, job_id, "graph", total=total, completed=scanned, label="Graph synchronization of extracted evidence")
    _mark_graph_phase(driver, job_id, "graph_files_done")
    return scanned


def run_graph_files_sidecar(db, job_id: str) -> dict:
    """Graph files phase beside the running stages (disk jobs, after registration)."""
    driver = _get_driver()
    if driver is None:
        return {"status": "deferred", "reason": "neo4j_unavailable"}
    _ensure_graph_indexes(driver)
    with driver.session() as session:
        session.run("MERGE (j:Job {id:$jid}) SET j.updated_at=datetime()", jid=job_id).consume()
        flag = session.run(
            "MATCH (j:Job {id:$jid}) RETURN coalesce(j.graph_files_done,false) AS files", jid=job_id
        ).single() or {}
    if bool(flag.get("files")):
        return {"status": "ok", "already_done": True}
    total = int(fetchone(db, "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})["c"])
    written = sync_graph_files_phase(db, job_id, driver=driver, total=total, stage="graph_files")
    return {"status": "ok", "evidence_files": written, "total": total}


def sync_job_graph_serial(db, job_id: str, *, schema_name: str, mobile: bool = False) -> dict:
    """Keyset graph construction after enrichment, with no 5,000-file/20-record cap."""
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.forensic_serial_stages import report_progress
    from app.services.job_control import pipeline_should_stop

    global _driver_failed
    _driver_failed = False  # Allow the watchdog to recover after a transient outage.
    driver = _get_driver()
    if driver is None:
        raise StageWaiting("Neo4j unavailable; graph synchronization remains pending")
    total = int(fetchone(db, "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})["c"])
    nodes = edges = scanned = 0
    from app.services.progress_agent import note_operation

    def stop():
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Graph synchronization paused by user")

    note_operation(
        db, job_id, "graph", "Preparing graph indexes for parallel writers",
        advanced=True, timeout_seconds=900,
    )
    _ensure_graph_indexes(driver)
    with driver.session() as session:
        session.run("MERGE (j:Job {id:$jid}) SET j.updated_at=datetime()", jid=job_id).consume()
        flags = session.run(
            """MATCH (j:Job {id:$jid})
               RETURN coalesce(j.graph_files_done, false) AS files,
                      coalesce(j.graph_parsed_done, false) AS parsed,
                      coalesce(j.graph_encyclopedia_done, false) AS encyclopedia""",
            jid=job_id,
        ).single() or {}
        files_done = bool(flags.get("files"))
        parsed_done = bool(flags.get("parsed"))
        encyclopedia_done = bool(flags.get("encyclopedia"))
        if not files_done and total > 0:
            present = session.run(
                "MATCH (e:EvidenceFile {job_id:$jid}) RETURN count(e) AS c", jid=job_id
            ).single()
            if int((present or {}).get("c") or 0) >= total:
                session.run("MATCH (j:Job {id:$jid}) SET j.graph_files_done=true", jid=job_id).consume()
                files_done = True
    if files_done:
        scanned = total
        nodes = total
        edges = total
    else:
        written = sync_graph_files_phase(db, job_id, driver=driver, total=total, stop=stop)
        scanned += written
        nodes += written
        edges += written

    if not parsed_done:
        last = "00000000-0000-0000-0000-000000000000"

        def write_parsed(session, rows):
            count = _sync_parsed_edges(session, job_id, rows, max_records=None)
            session.run("RETURN 1").consume()
            return count

        while True:
            stop()
            wave = []
            for _ in range(GRAPH_WRITE_SLOTS):
                rows = fetchall(db, """SELECT apr.id,ja.file_path,ja.encyclopedia_artifact_id,apr.parser_name,apr.normalized
                    FROM artifact_parse_results apr JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
                    WHERE ja.job_id=:jid AND apr.id>:last ORDER BY apr.id LIMIT 100""", {"jid": job_id, "last": last})
                db.commit()
                if not rows:
                    break
                last = str(rows[-1]["id"])
                wave.append([dict(row) for row in rows])
            if not wave:
                break
            note_operation(db, job_id, "graph", "Graph synchronization of parsed records", advanced=True, timeout_seconds=900)
            edges += _write_graph_batches(driver, wave, write_parsed)
        _mark_graph_phase(driver, job_id, "graph_parsed_done")

    if not encyclopedia_done:
        last = "00000000-0000-0000-0000-000000000000"

        def write_encyclopedia(session, rows):
            session.run("""UNWIND $rows AS r MERGE (a:Artifact {id:r.from_artifact_id})
                MERGE (b:Artifact {id:r.to_artifact_id})
                MERGE (a)-[:RELATED_TO {type:r.relationship_type}]->(b)""", rows=rows).consume()
            return len(rows)

        while True:
            stop()
            wave = []
            for _ in range(GRAPH_WRITE_SLOTS):
                rows = fetchall(db, """SELECT id,from_artifact_id,to_artifact_id,relationship_type
                    FROM public.encyclopedia_relationships WHERE id>:last ORDER BY id LIMIT 500""", {"last": last})
                db.commit()
                if not rows:
                    break
                last = str(rows[-1]["id"])
                wave.append([dict(row) for row in rows])
            if not wave:
                break
            edges += _write_graph_batches(driver, wave, write_encyclopedia)
        _mark_graph_phase(driver, job_id, "graph_encyclopedia_done")

    table = "mobile_normalized_artifacts" if mobile else "forensic_priority_records"
    if fetchone(db, "SELECT to_regclass(:name) AS name", {"name": table}).get("name"):
        key_index = (
            "ix_mobile_artifacts_job_artifact"
            if table == "mobile_normalized_artifacts"
            else "ix_priority_job_artifact_key"
        )
        if not fetchone(
            db,
            """SELECT 1 AS ok FROM pg_indexes
               WHERE schemaname = current_schema() AND indexname = :name""",
            {"name": key_index},
        ):
            execute(db, f"CREATE INDEX IF NOT EXISTS {key_index} ON {table} (job_id, artifact_id)")
            db.commit()
        mobile_total = int(fetchone(db, f"SELECT count(*) AS c FROM {table} WHERE job_id=:jid", {"jid": job_id})["c"] or 0)
        mobile_done = 0
        last = ""

        def write_records(session, rows):
            session.run("""UNWIND $rows AS r
                MERGE (m:EvidenceRecord {id:r.id,job_id:$jid})
                SET m.artifact_type=r.type,m.evidence_state=r.state
                FOREACH (_ IN CASE WHEN $mobile THEN [1] ELSE [] END | SET m:MobileArtifact)""",
                rows=rows, jid=job_id, mobile=mobile).consume()
            return len(rows)

        def write_record_links(session, rows):
            session.run("""UNWIND $rows AS r
                MATCH (m:EvidenceRecord {id:r.id,job_id:$jid})
                MATCH (e:EvidenceFile {path:r.path,job_id:$jid})
                MERGE (m)-[:DERIVED_FROM]->(e)""",
                rows=rows, jid=job_id).consume()
            return len(rows)

        while True:
            stop()
            rows = fetchall(
                db,
                f"""SELECT artifact_id,artifact_type,state,
                           coalesce(forensic->>'source_path','') AS source_path
                    FROM {table}
                    WHERE job_id=:jid AND artifact_id>:last
                    ORDER BY artifact_id LIMIT :lim""",
                {"jid": job_id, "last": last, "lim": GRAPH_ROW_BATCH},
            )
            db.commit()
            if not rows:
                break
            last = str(rows[-1]["artifact_id"])
            payload = [
                {
                    "id": row["artifact_id"],
                    "type": row["artifact_type"],
                    "state": row["state"],
                    "path": row["source_path"] or "",
                }
                for row in rows
            ]
            _write_graph_batches(
                driver, _partition_by_key(payload, GRAPH_WRITE_SLOTS, "id"), write_records
            )
            linked = [row for row in payload if row.get("path")]
            if linked:
                distinct_paths = [{"path": path} for path in {row["path"] for row in linked}]
                with driver.session() as session:
                    session.run(
                        """UNWIND $rows AS r
                           MERGE (e:EvidenceFile {path:r.path,job_id:$jid})""",
                        rows=distinct_paths,
                        jid=job_id,
                    ).consume()
                _write_graph_batches(
                    driver,
                    _partition_by_key(linked, GRAPH_WRITE_SLOTS, "path"),
                    write_record_links,
                )
            mobile_done += len(payload)
            nodes += len(payload)
            edges += 2 * len(linked)
            note_operation(
                db, job_id, "graph",
                f"Graph synchronization of mobile records {min(mobile_done, mobile_total):,} / {mobile_total:,}",
                advanced=True, timeout_seconds=900,
            )
            report_progress(
                db, job_id, "graph", total=mobile_total or total, completed=min(mobile_done, mobile_total or total),
                label="Graph synchronization of normalized mobile records",
            )
    if mobile:
        last_id = 0

        def write_links(session, rows):
            session.run("""UNWIND $rows AS r MERGE (a:MobileArtifact {id:r.from,job_id:$jid})
                MERGE (b:MobileArtifact {id:r.to,job_id:$jid})
                MERGE (a)-[rel:CORRELATED_WITH {type:r.type}]->(b)
                SET rel.confidence=r.confidence,rel.reasons=r.reasons""", rows=rows, jid=job_id).consume()
            return len(rows)

        while True:
            stop()
            rows = fetchall(db, """SELECT id,from_artifact_id,to_artifact_id,rel_type,confidence,reasons
                FROM mobile_artifact_relationships WHERE job_id=:jid AND id>:last ORDER BY id LIMIT :lim""",
                {"jid": job_id, "last": last_id, "lim": GRAPH_ROW_BATCH})
            db.commit()
            if not rows:
                break
            last_id = rows[-1]["id"]
            payload = [{"from": r["from_artifact_id"], "to": r["to_artifact_id"], "type": r["rel_type"],
                        "confidence": json.dumps(r["confidence"]), "reasons": json.dumps(r["reasons"])} for r in rows]
            edges += _write_graph_batches(
                driver, _partition_by_key(payload, GRAPH_WRITE_SLOTS, "from"), write_links
            )
    execute(db, """INSERT INTO graph_sync_state(job_id,nodes_synced,edges_synced,last_sync_at,status,error)
        VALUES (:jid,:nodes,:edges,NOW(),'ok',NULL) ON CONFLICT(job_id) DO UPDATE
        SET nodes_synced=:nodes,edges_synced=:edges,last_sync_at=NOW(),status='ok',error=NULL""",
        {"jid": job_id, "nodes": nodes, "edges": edges})
    db.commit()
    return {"status": "ok", "nodes": nodes, "edges": edges, "total": total, "completed": scanned}


def graph_expand(driver, artifact_ids: list[str], *, job_id: str | None = None, hops: int = 2) -> list[dict[str, Any]]:
    """Expand only case-owned evidence paths, never through shared taxonomy nodes."""
    if not driver or not artifact_ids or not job_id:
        return []
    hops = max(1, min(int(hops), 3))
    with driver.session() as session:
        result = session.run(
            f"""
            MATCH (a:EvidenceFile {{job_id:$jid}})
            WHERE a.artifact_id IN $ids
            MATCH path = (a)-[*1..{hops}]-(related)
            WHERE all(n IN nodes(path) WHERE n.job_id=$jid OR (n:Job AND n.id=$jid))
            RETURN DISTINCT coalesce(related.id,related.path) AS id, labels(related) AS labels,
                related.path AS file_path
            LIMIT 50
            """, ids=artifact_ids, jid=job_id)
        return [{"id": r["id"], "labels": r["labels"], "file_path":r["file_path"],
            "job_id":job_id} for r in result if r.get("id")]
