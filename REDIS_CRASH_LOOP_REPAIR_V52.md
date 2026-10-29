# Redis crash-loop recovery V52

## Failure fixed

Observed Redis log:

`Bad file format reading the append only file: appendonly.aof.3.incr.aof`

The V51 recovery correctly backed up the named Redis volume, but then used `docker compose stop redis`. On Windows Docker Desktop a service already crash-looping can remain in `Stopping`; PowerShell then aborted the launcher before AOF repair/recreation finished.

## V52 behavior

1. Capture Redis logs and resolve the `/data` named volume.
2. Clone that volume to a timestamped backup volume before changing anything.
3. Disable the Redis container restart policy.
4. Force-remove only the Redis container. The named `/data` volume remains intact.
5. Repair Redis 7 multi-part AOF from `appendonly.aof.manifest` (or legacy `appendonly.aof`).
6. Recreate Redis and wait for the healthcheck / `redis-cli ping` path to become healthy.
7. If the repaired persistence still crash-loops, force-remove the failed Redis container again before touching the volume.
8. Move the damaged persistence into `/data/recovery-<timestamp>` and start Redis with clean persistence.
9. Keep the full pre-repair backup Docker volume for later examination/restoration.
10. Only after Redis is healthy are product stacks started.

No PostgreSQL, MinIO, evidence, case files, or source evidence are deleted by this recovery.

## Important

The old HTTPS/router guidance is now conditional. A Redis startup failure is reported as a Redis/container problem rather than implying that port forwarding caused it.
