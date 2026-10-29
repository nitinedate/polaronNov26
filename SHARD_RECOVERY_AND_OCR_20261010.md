# Shard recovery and extraction-time OCR candidate scheduling

## Code changes
- `backend/app/services/forensic_shard_overlap.py`: schema-tolerant claim token and heartbeat tracking for committed shard parsing.
- Completion barrier periodically identifies stale pending and running claims; redispatches bounded attempts; exhausted sidecars are marked failed and left to authoritative final parsing.
- Each shard sidecar runs a heartbeat using a separate tenant-scoped DB session. Terminal updates are fenced by attempt token.
- Committed shard parsing may quality-triage OCR candidates and dispatch the existing OCR drain. Final OCR remains authoritative; dispatch exceptions are logged and left for reconciliation.

## Configuration (staging ONLY)
`FORENSIC_STREAM_SHARD_OVERLAP=true`
`FORENSIC_SHARD_LEASE_SECONDS=300`
`FORENSIC_SHARD_HEARTBEAT_SECONDS=20`
`FORENSIC_SHARD_MAX_ATTEMPTS=4`

## Limitations and required live checks
- These changes do **not** prove exactly-once processing: an isolated worker still doing work after its lease expires could race its replacement. Parser idempotency and transaction isolation must be exercised in live PostgreSQL tests.
- Recovery runs when final materialization checks the shard barrier, not through an independent background monitoring service. It requires regular stage retries to make forward progress.
- The final authoritative parsing and OCR stages remain essential; automated OCR scheduling is best-effort, not full extraction-time OCR completion.
- Integration tests with Redis/Celery, PostgreSQL, evidence object storage, crash/restart/resume, worker SIGKILL, key provision, and exact count reconciliation are **not run** in this environment.
- Do **not** enable the overlap flag in production until these tests pass. No 85 GB / 90-minute SLA has been established.
