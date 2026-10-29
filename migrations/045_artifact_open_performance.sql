-- 045 (2026-10-22): artifact open performance.
--
-- * job_artifact_locations: (job_id, path) -> shard URI.  Replaces downloading
--   and decompressing the whole extraction index on every artifact click.
--   Rows are filled lazily (first open of a job) by
--   app/services/artifact_locator.py; this migration only creates the tables.
-- * Re-asserts the preview hot-path indexes.  Earlier index migrations
--   (037/039/043) were optional and scripts/apply_migrations.* stops at 037,
--   so they may be missing on a live server.
--
-- Idempotent; touches no evidence rows; safe to re-run.  The API also creates
-- the two tables on first use, so new tenants need no manual step.

CREATE OR REPLACE FUNCTION public.apply_firm_artifact_open_v1(p_schema text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
  IF to_regclass(format('%I.jobs', p_schema)) IS NULL THEN
    RETURN;
  END IF;

  EXECUTE format(
    'CREATE TABLE IF NOT EXISTS %I.job_artifact_locations (
       job_id UUID NOT NULL,
       path TEXT NOT NULL,
       part_uri TEXT NOT NULL,
       part_id INTEGER,
       data_offset BIGINT,
       size_bytes BIGINT,
       sha256 TEXT,
       PRIMARY KEY (job_id, path)
     )', p_schema);

  EXECUTE format(
    'CREATE TABLE IF NOT EXISTS %I.job_artifact_location_builds (
       job_id UUID PRIMARY KEY,
       fingerprint TEXT NOT NULL,
       entry_count INTEGER NOT NULL DEFAULT 0,
       built_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
     )', p_schema);

  IF to_regclass(format('%I.artifact_parse_results', p_schema)) IS NOT NULL THEN
    -- latest_parse_meta(): WHERE job_artifact_id = ? ORDER BY created_at DESC LIMIT 5
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created
                    ON %I.artifact_parse_results (job_artifact_id, created_at DESC)', p_schema);
  END IF;

  IF to_regclass(format('%I.job_artifacts', p_schema)) IS NOT NULL THEN
    -- resolve-path / attachment linking / family open.
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path
                    ON %I.job_artifacts (job_id, file_path)', p_schema);
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path_lower
                    ON %I.job_artifacts (job_id, lower(file_path))', p_schema);
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name_lower
                    ON %I.job_artifacts (job_id, lower(file_name))', p_schema);
    -- Parsed-record view: artifacts still waiting for MinIO persistence.
    EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_no_object
                    ON %I.job_artifacts (job_id, id) WHERE minio_uri IS NULL', p_schema);
    EXECUTE format('ANALYZE %I.job_artifacts', p_schema);
  END IF;
END;
$fn$;

DO $$
DECLARE rec record;
BEGIN
  FOR rec IN SELECT schema_name FROM public.firms WHERE schema_name IS NOT NULL LOOP
    BEGIN
      PERFORM public.apply_firm_artifact_open_v1(rec.schema_name);
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'artifact open performance migration skipped for %: %', rec.schema_name, SQLERRM;
    END;
  END LOOP;
END $$;
