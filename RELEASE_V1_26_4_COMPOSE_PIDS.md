# Polaron V1.26.4: Malware Detection Compose file valid again

`services.clamav-scan: can't set distinct values on 'pids_limit' and 'deploy.resources.limits.pids'` stopped
startup. Cause: V1.25.0/V1.26.0 set process limits with `pids_limit` on services that also have a
`deploy.resources.limits` block (memory). Current Docker Compose treats an unset `limits.pids` as a different value
and rejects the service. `clamav-scan` was reported first; `worker-static` had the same problem.

## Fix
Process limits now live inside `deploy.resources.limits.pids` (the Compose-spec form, applied as the container's
process limit): `worker-static` 1024, `clamav-update` 64, `clamav-scan` 256. Same values, same protection.

## Verification (real Docker Compose v2.39.2 this time)
- The shipped V1.26.3 file reproduces the error; the fixed file validates.
- Every stack validated exactly as `start_docker` builds it, with drive overlays like the startup scan writes:
  common, forensic, mobile-android, mobile-ios, mobile-malware (also with `--profile gpu`), vuln, gateway (local and
  public HTTPS), and the root `docker-compose.yml` used by `startup.cmd`.
- New tests in `backend/tests/test_malware_antivirus_v1_25.py`: no service may set the process limit twice; every
  stack must pass `docker compose config` (runs when a Compose binary is available, `COMPOSE_BIN`). Both fail on the
  V1.26.3 file with the exact error and pass on the fix.

Earlier checks only parsed the YAML, which cannot catch Compose's own rules; the new test closes that gap.
