-- Optional, explicit DB backfill for stored vulnerability severity labels.
-- Run after a database backup; this never changes CVSS scores, finding IDs,
-- weighted enterprise Risk Number, or risk_band. API queries already apply
-- the custom classification dynamically, even before this backfill.
-- Use only when using the V1.6.4 default thresholds (8.0 / 6.0 / 4.0 / 0.1).
DO $body$
DECLARE target record;
BEGIN
  FOR target IN
    SELECT nspname AS name FROM pg_namespace
     WHERE nspname = 'public' OR nspname LIKE 'firm\_%' ESCAPE '\'
  LOOP
    IF to_regclass(format('%I.vuln_findings', target.name)) IS NOT NULL THEN
      EXECUTE format($update$
        UPDATE %I.vuln_findings
           SET severity = CASE
                  WHEN cvss >= 8.0 THEN 'critical'
                  WHEN cvss >= 6.0 THEN 'high'
                  WHEN cvss >= 4.0 THEN 'medium'
                  WHEN cvss >= 0.1 THEN 'low'
                  ELSE 'info' END,
               updated_at = NOW()
         WHERE cvss IS NOT NULL
           AND lower(COALESCE(severity, '')) IS DISTINCT FROM CASE
                  WHEN cvss >= 8.0 THEN 'critical'
                  WHEN cvss >= 6.0 THEN 'high'
                  WHEN cvss >= 4.0 THEN 'medium'
                  WHEN cvss >= 0.1 THEN 'low'
                  ELSE 'info' END
      $update$, target.name);
    END IF;
  END LOOP;
END
$body$;
