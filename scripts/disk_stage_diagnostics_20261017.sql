-- Run inside the relevant forensic tenant's schema (set search_path first).
-- Replace :job_uuid with the actual job UUID in a psql session.
-- Never change evidence rows during diagnostics.
SELECT stage, status, total_items, completed_items, skipped_items, failed_items,
       started_at, completed_at,
       EXTRACT(EPOCH FROM (COALESCE(completed_at,NOW())-started_at))::integer AS wall_sec,
       operation, heartbeat_at, progress_at,
       details->>'priority_sources_completed' AS priority_done
FROM pipeline_stage_runs
WHERE job_id=:'job_uuid'::uuid ORDER BY started_at NULLS LAST, stage;

SELECT parse_status, count(*) AS files
FROM job_artifacts WHERE job_id=:'job_uuid'::uuid
GROUP BY parse_status ORDER BY parse_status;

SELECT count(*) AS source_rows,
       count(*) FILTER (WHERE metadata->>'priority_parsed_v4'='true') AS priority_checkpointed,
       count(*) FILTER (WHERE metadata->>'priority_parse_exception' IS NOT NULL) AS priority_exception_sources
FROM job_artifacts WHERE job_id=:'job_uuid'::uuid;

SELECT artifact_type, count(*) AS records
FROM forensic_priority_records WHERE job_id=:'job_uuid'::uuid
GROUP BY artifact_type ORDER BY records DESC;

SELECT wait_event_type, wait_event, state, count(*) AS sessions
FROM pg_stat_activity
WHERE datname = current_database()
GROUP BY wait_event_type, wait_event, state ORDER BY sessions DESC;
