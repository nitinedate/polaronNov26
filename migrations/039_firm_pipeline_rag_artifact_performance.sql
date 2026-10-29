-- V68: hot-path indexes for resumable pipeline, OCR triage, RAG and artifact browsing.
-- Idempotent and safe across all firm schemas.
DO $$
DECLARE s record;
BEGIN
  FOR s IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
    IF to_regclass(format('%I.job_artifacts', s.schema_name)) IS NOT NULL THEN
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_status_id ON %I.job_artifacts(job_id, parse_status, id)', s.schema_name);
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ocr_status_id ON %I.job_artifacts(job_id, ocr_status, id)', s.schema_name);
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_stage_status_id ON %I.job_artifacts(job_id, stage_status, id)', s.schema_name);
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_quality_unchecked ON %I.job_artifacts(job_id, id) WHERE coalesce(metadata->>''ocr_quality_checked'',''false'') <> ''true''', s.schema_name);
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_ready ON %I.job_artifacts(job_id, id) WHERE parse_status=''parsed'' OR ocr_status=''done''', s.schema_name);
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_company_leakage ON %I.job_artifacts(job_id, id) WHERE coalesce(metadata->>''company_leakage_candidate'',''false'') = ''true''', s.schema_name);
    END IF;
    IF to_regclass(format('%I.rag_chunks', s.schema_name)) IS NOT NULL THEN
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_path_type_idx ON %I.rag_chunks(job_id, file_path, chunk_type, chunk_index)', s.schema_name);
    END IF;
    IF to_regclass(format('%I.artifact_parse_results', s.schema_name)) IS NOT NULL THEN
      EXECUTE format('CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created ON %I.artifact_parse_results(job_artifact_id, created_at DESC)', s.schema_name);
    END IF;
  END LOOP;
END $$;
