-- V48 mobile quality/OCR queue indexes.
-- Speeds the continuous poor-media/document quality gate and GPU OCR wake-up.

CREATE OR REPLACE FUNCTION public.apply_mobile_quality_ocr_indexes_v48(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
  BEGIN
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS ix_job_artifacts_mobile_quality_unchecked
       ON %I.job_artifacts (job_id, lower(coalesce(extension, '''')), size_bytes, id)
       WHERE coalesce(metadata->>''ocr_quality_checked'', ''false'') <> ''true''',
      p_schema
    );
  EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;

  BEGIN
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS ix_job_artifacts_ocr_quality_pending
       ON %I.job_artifacts (job_id, updated_at)
       WHERE ocr_status = ''pending'' AND coalesce(metadata->>''ocr_quality_bucket'', ''false'') = ''true''',
      p_schema
    );
  EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;

  BEGIN EXECUTE format('ANALYZE %I.job_artifacts', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
END;
$fn$;

DO $$
DECLARE rec record;
BEGIN
  FOR rec IN SELECT schema_name FROM public.firms WHERE lower(coalesce(status, '')) = 'active' LOOP
    BEGIN
      PERFORM public.apply_mobile_quality_ocr_indexes_v48(rec.schema_name);
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'mobile quality OCR index apply skipped for %: %', rec.schema_name, SQLERRM;
    END;
  END LOOP;
END $$;
