# Neo4j `graph_files` deadlock mitigation

## Applied
- Serializes only the `graph_files` Neo4j writes, rather than disabling parallel processing across the forensic pipeline.
- Uses ordered 100-row transactions for shared `Artifact`/`EvidenceFile` relationship updates.
- Uses Neo4j managed retryable `session.execute_write` transactions with an additional bounded transient/deadlock retry and jitter.
- Reuses MERGE-based idempotent records, so repeating the sidecar does not require extraction or parsing again.
- Does not change job stage claims, PostgreSQL tables, ingestion or other graph phases.

## Scope / caveats
- Patch addresses confirmed `graph_files` race among its own concurrent batch writers; concurrent graph jobs or other phases can still conflict.
- Neo4j driver version must support `execute_write` (Neo4j Python driver 5+).
- This is not a full schema or concurrency audit and has not been verified on a running Neo4j deployment.
- Apply to the SAME backend version as the attached `polaron2(5).zip` or review merge conflicts with newer source changes.

## Validate
- Rebuild the worker/API image containing `backend/app/services/neo4j_sync.py`.
- Check graph-sidecar retry logs and confirm source `Job.graph_files_done` becomes true.
- Compare `MATCH (e:EvidenceFile {job_id:$jid}) RETURN count(e)` to PostgreSQL `job_artifacts` count.
- Capture graph-stage errors and verify stage claims are safely re-enqueued, not discarded.
- Run a stress test with shared `encyclopedia_artifact_id` values and simultaneous other graph writers before production roll-out.
