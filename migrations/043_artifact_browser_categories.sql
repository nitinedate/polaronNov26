-- Optional one-time migration; run during deployment, never inside a GET request.
-- The category UI groups by a normalized file extension scoped to one job.
-- Apply to each tenant schema that owns job_artifacts; no evidence data is changed.
DO $migration$
DECLARE
  s record;
BEGIN
  FOR s IN
    SELECT table_schema
    FROM information_schema.tables
    WHERE table_name='job_artifacts' AND table_type='BASE TABLE'
      AND table_schema NOT IN ('pg_catalog','information_schema')
  LOOP
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_extension_browser ON %I.job_artifacts (job_id, lower(ltrim(coalesce(extension, ''''), ''.'')))',
      s.table_schema
    );
  END LOOP;
END
$migration$;
