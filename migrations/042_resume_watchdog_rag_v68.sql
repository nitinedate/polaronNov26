-- V68 hot indexes
CREATE INDEX IF NOT EXISTS ix_jobs_progress_watch ON jobs(status,updated_at,id) WHERE stop_requested=FALSE;
CREATE INDEX IF NOT EXISTS ix_job_artifacts_ocr_bucket_pending ON job_artifacts(job_id,id) WHERE ocr_status='pending' AND coalesce(metadata->>'ocr_quality_bucket','false')='true';
CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_stable_pending ON job_artifacts(job_id,id) WHERE parse_status='done' AND coalesce(stage_status,'') <> 'rag_done';
CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_path_type_idx ON rag_chunks(job_id,source_path,chunk_type,id);
