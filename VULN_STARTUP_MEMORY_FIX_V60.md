# V60 Vulnerability Scanner Startup / Memory Fix

## Symptom
Windows startup failed readiness because many `aetheris-vuln-*` containers exited together. A large group exited with code 137 while Greenbone feed/data containers, PostgreSQL, Redis, GVMD, OpenVAS, ZAP and Trivy were initializing concurrently.

## Root causes fixed
1. Greenbone feed/data images were forced to stay alive with `KEEP_ALIVE=1`, retaining memory after their volume population job.
2. Heavy feed loaders could initialize together and create a large Docker Desktop memory spike.
3. The global Polaron readiness gate treated scanner feed warm-up and optional sidecars as fatal to the entire Disk/Mobile platform.
4. Runtime OpenVAS configuration used fixed `max_hosts=16` and `max_checks=24` even when the configured scanner limits were smaller.

## V60 behavior
- Disk, Android and iPhone product stacks start first.
- Vulnerability API starts independently as a lightweight control plane.
- Greenbone feed loaders run sequentially as disposable one-shot containers and release RAM after each loader exits.
- Each one-shot loader is retried once after a short memory-settle delay.
- Greenbone runtime starts in dependency order: Redis/PostgreSQL -> OpenVAS/openvasd/OSPd -> GVMD/GVM tools -> Nessus/OpenVAS worker.
- Trivy and ZAP start last and are optional for global startup readiness.
- Scanner services that are still warming/degraded are surfaced as warnings and no longer take down the entire Polaron startup.
- Feed/data volumes are preserved; only disposable loader containers are removed/recreated.
- OpenVAS `max_hosts` and `max_checks` now follow `GVM_MAX_HOSTS` / `GVM_MAX_CHECKS` defaults instead of the previous hard-coded higher values.

## Exit-code handling
- Exit 0 from Greenbone one-shot loaders is expected/completed.
- Running scanner services with health `starting` are allowed to continue warming without blocking overall application readiness.
- Optional scanner failures are reported separately.
- Core Polaron application/API failures remain fatal.

## Validation
- YAML parsing passed for `docker-compose.gvm.yml`, `docker-compose.vuln-scanners.yml`, and `services/vuln/docker-compose.yml`.
- V60 scanner-startup tests plus Redis-startup regression tests: 10/10 passed.

## Deployment
Replace the V60 updated files and run the normal launcher. No Greenbone/PostgreSQL forensic evidence volumes are deleted by this change.
