# V62 - Greenbone one-shot feed lifecycle fix

## Symptom
Startup stopped at:

`Greenbone feed/init: gpg-data (attempt 1/2)`

with:

`STARTUP ERROR: Container aetheris-vuln-gpg-data-1 Stopping`

## Root cause
The Windows launcher uses `$ErrorActionPreference = 'Stop'`. Docker Compose writes normal container lifecycle progress such as `Stopping` to stderr. In Windows PowerShell 5.1, native stderr can be surfaced as PowerShell error records, so ordinary Docker progress could terminate the launcher before Docker returned the real process exit code.

An interrupted previous launch could also leave a disposable Greenbone feed-loader container in `created`, `restarting`, or `stopping` state.

## V62 behavior
- Never uses `docker compose rm` for the sequential Greenbone feed loaders.
- Finds stale one-shot service containers by Compose project/service labels.
- Disables restart policy on the disposable stale container.
- Force-removes only that container by container ID.
- Waits until Docker confirms the container is gone.
- Preserves all named Greenbone feed volumes.
- Runs the initializer with `docker compose run --rm --no-deps`.
- Temporarily treats Docker stderr as normal output and trusts the native Docker exit code.
- Exit code 0 means the feed initializer completed successfully.
- Non-zero exit codes are logged and retried according to the existing retry policy.

## Safety
No Greenbone feed volumes, PostgreSQL data, Redis data, forensic evidence, mobile evidence, or case data are deleted by this fix.
