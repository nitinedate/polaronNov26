# Secondary-stack api startup timeout fix (mobile-ios / mobile-android / vuln) — 2026-10-22

> Update: the same lock-storm timeout then hit the **vuln** stack
> (`aetheris-vuln-api-1 health=unhealthy`). The fix below is generalized: the
> **forensic** stack owns the shared PostgreSQL and is the only one that applies
> firm migrations at boot; **every other stack (mobile-android, mobile-ios,
> mobile-extract, vuln)** skips them. The real per-stack compose files are
> `services/<name>/docker-compose.yml`; each secondary stack now also sets
> `AETHERIS_SKIP_BOOT_MIGRATIONS: "1"` and a 420s api `start_period` explicitly.


Base: cumulative change set. Source + compose patch; no DB migration, no evidence
change.

## 1. Symptom

```
Start mobile-ios
 ✘ Container aetheris-mobile-ios-api-1  Error dependency api failed to start  293.8s
```

## 2. Diagnosis (from the container log)

The api did **not** crash — it started healthy, just too late:

```
08:22:55  container start (CUDA banner, alembic begins)
08:22:56  alembic 001 fails (relation "firms" already exists) -> WARN, continues
08:23:12 … 08:25:58  warn: 006…037: canceling statement due to statement timeout
08:26:03 … 08:27:52  firm apply skipped …: LockNotAvailable: lock timeout
08:27:53  Application startup complete. Uvicorn running on 0.0.0.0:8080
08:27:57  GET /health 200 OK   (and every 10s after)
```

The api healthcheck (`start_period: 180s`, `retries: 12`, `interval: 10s`) gives
~300s; the api reported healthy at ~298s — it crossed the line a few seconds after
Compose stopped waiting, so dependents saw "dependency api failed to start."

**Root cause:** the mobile-ios stack shares one PostgreSQL with the already-running
mobile-android (and/or forensic) stack. On boot the ios api re-runs the idempotent
firm DDL (`ALTER TABLE firm_p.jobs ADD COLUMN IF NOT EXISTS …`, all guarded by
`IF NOT EXISTS`). Because the other stack's workers hold locks/open transactions on
those shared tables, every ALTER waits out its `statement_timeout` (15s) or
`lock_timeout` (5s) and is skipped. ~15 statement-timeout files + ~9 lock-timeout
calls ≈ **~4 minutes** of doomed work before uvicorn even starts. The schema was
already current — none of that work was needed.

This is not caused by the earlier patches; the alembic `001` "already exists" and
the fail-open skips are the project's normal shared-DB behaviour. It is purely a
startup-time race.

## 3. Fix

Three independent changes (any one resolves it; together they are robust):

1. **Only the forensic stack runs boot firm migrations; all others skip**
   (`backend/app/services/firm_migrations.py`). New `boot_migrations_disabled()`
   returns True whenever `current_service()` is not `forensic` (i.e. mobile-android,
   mobile-ios, mobile-extract, vuln). `apply_all_firm_migrations()` returns 0
   immediately when skipped — no Firm query, no ALTERs. Override with
   `AETHERIS_SKIP_BOOT_MIGRATIONS=1` (force skip) or `=0` (force run) on any stack,
   e.g. to run a non-forensic stack standalone against its own database.

2. **Start-script honours the skip and fails fast otherwise**
   (`scripts/ensure_sql_functions.py`). The SQL-helper loop is skipped on secondary
   stacks; when it does run, the per-statement timeout is configurable via
   `AETHERIS_MIGRATION_STATEMENT_TIMEOUT` (default unchanged at 15s) so a doomed
   ALTER on a locked table can be made to fail in ~2s instead of 15s if desired.

3. **Secondary stacks set the skip flag + longer api healthcheck explicitly**
   (`services/{mobile-android,mobile-ios,mobile-extract,vuln}/docker-compose.yml`):
   each env anchor adds `AETHERIS_SKIP_BOOT_MIGRATIONS: "1"`, and the api
   healthcheck is raised to `start_period: 420s`, `retries: 18`. The forensic
   stack's api healthcheck (via the base `docker-compose.yml` it includes) gets the
   same 420s/18 grace as a backstop, since it is the one that still runs migrations.

Net effect: every non-forensic api skips the ~4-minute lock storm and reports
healthy within seconds of uvicorn starting; the forensic stack still applies the
schema and has enough grace for a shared-DB cold start.

## 4. Verification

- `backend/tests/test_boot_migration_skip.py` (8): mobile services skip, forensic
  runs, env flag overrides both ways, `apply_all_firm_migrations` short-circuits to
  0 without touching the DB on a skipped stack, unknown env value falls back to the
  service default.
- `docker-compose.yml` parses as valid YAML with the new healthcheck values.
- Full backend + root suites, clean upload vs modified tree: no test that passes on
  the original fails on the modified tree.

**Not verified here:** a live two-stack Docker bring-up. The timing math and the
skip logic are covered by the log analysis and the tests above.

## 5. Deploy / how to run two stacks

Preferred: **bring the mobile stacks up with the fix in place** — the ios/android
api now skips boot migrations automatically and starts promptly, so
`docker compose up` for mobile-ios succeeds even while mobile-android is running.

Rebuild api + frontend (workers reuse the api image):
```
docker compose build --no-cache api frontend
docker compose up -d --no-build --force-recreate api frontend
```

If you ever need a mobile stack to apply migrations itself (e.g. running it
standalone with no forensic stack), set on that stack's api:
```
AETHERIS_SKIP_BOOT_MIGRATIONS=0
```

Note: the mobile-android and mobile-ios api containers both inherit the base
`127.0.0.1:8083:8080` host-port mapping. Running both plus forensic simultaneously
still needs distinct host ports per stack; that is a separate, pre-existing concern
and is not required to fix this startup timeout.
