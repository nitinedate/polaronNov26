-- V1.8.0: built-in (Nexpose / Nessus equivalent) scan policies.
--
-- Adds two columns to every firm's vuln_scan_policies table and a partial
-- unique index so each template is seeded at most once per tenant. The rows
-- themselves are created by the API on first use (GET /api/scan-policies),
-- from backend/app/services/scan_templates.json, so a template change ships
-- with the code and needs no further migration.
--
-- Also activates existing 'draft' policies: the UI has no activation step,
-- and central (premise) scans refused any policy that was not 'active'.
-- Idempotent; safe to re-run. The API applies the same column change at
-- runtime if this file has not been run.
DO $body$
DECLARE target record;
BEGIN
  FOR target IN
    SELECT nspname AS name FROM pg_namespace
     WHERE nspname LIKE 'firm\_%' ESCAPE '\'
  LOOP
    IF to_regclass(format('%I.vuln_scan_policies', target.name)) IS NOT NULL THEN
      EXECUTE format(
        'ALTER TABLE %I.vuln_scan_policies
           ADD COLUMN IF NOT EXISTS is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
           ADD COLUMN IF NOT EXISTS builtin_key TEXT',
        target.name);
      EXECUTE format(
        'CREATE UNIQUE INDEX IF NOT EXISTS ux_vuln_scan_policies_builtin_key
           ON %I.vuln_scan_policies (builtin_key) WHERE builtin_key IS NOT NULL',
        target.name);
      EXECUTE format(
        'UPDATE %I.vuln_scan_policies SET lifecycle_state = ''active'', updated_at = NOW()
          WHERE lifecycle_state = ''draft''',
        target.name);
    END IF;
  END LOOP;
END
$body$;
