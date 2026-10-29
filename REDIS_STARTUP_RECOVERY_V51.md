# Redis startup recovery V51

## Problem fixed
The Windows launcher could continue starting all product stacks while `aetheris-common-redis-1` was restarting/unhealthy (exit 1). Readiness then aborted the whole launch with a generic public HTTPS troubleshooting message even though HTTPS was not the cause.

## New startup order
1. Build images.
2. Validate/start public HTTPS edge when configured.
3. Start shared `aetheris-common` infrastructure.
4. Require Redis to become healthy before product stacks start.
5. If Redis is unhealthy/restarting:
   - print the last 120 Redis log lines;
   - identify the Docker volume mounted at `/data`;
   - clone that volume to a timestamped Docker backup volume;
   - normalize Redis data ownership;
   - attempt Redis AOF repair for Redis 7 multi-part AOF or legacy AOF;
   - force-recreate Redis and wait for health.
6. If Redis still cannot boot, preserve the backup and quarantine AOF/RDB persistence inside the active volume, then start Redis with clean persistence.
7. Only after Redis is healthy start forensic, Android, iOS and vulnerability stacks.

The fallback reset affects Redis queue/cache persistence only. The complete pre-repair Redis volume is retained under a name such as:

`aetheris-common_redis_data_backup_20261008T083000Z`

PostgreSQL, MinIO evidence, source evidence directories and case evidence are not removed by this recovery.

## Also retained
The duplicate `NoCache` alias declaration is removed so `-NoCache` remains a normal switch without PowerShell metadata conflicts.
