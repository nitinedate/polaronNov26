# Greenbone task cancellation / GMP timeout repair V1.5.9 (2026-10-13)

## Observed log

- `POST /api/scanner-agent/jobs/.../results` returned HTTP 200.
- The same job reported `complete=True`, `vulns=9`, `hosts_assessed=1`, `skipped=0`.
- A later `gmp.stop_task(...)` timed out with `TimeoutError`.

The timeout is a task-control error, **not proof** that previously uploaded results were lost, and the logs alone do not establish which job issued the stop request.

## Source changes

1. `scanner-agent/agent/gmp_local.py`: after terminal GMP task polling, cache terminal IDs. `stop()` skips known terminal tasks and queries live gvmd state before any other stop request. No duplicate stop request for tasks already Done/Stopped/Failed/Stop requested. Timeout is classified as **unconfirmed** and logged in one line without a large traceback or blind retry. `GVM_STOP_TIMEOUT_SEC` is configurable (default 8, bounded 2-30 seconds).
2. `scanner-agent/agent/main.py`: no `stop_task` after a completed task solely because a degraded-coverage retry is requested. A transient GMP polling error is retained as `running` and retried rather than immediately cancelling the task. The configured per-IP scan time budget is still enforced; reports and findings are preserved.
3. `scanner-agent/agent/__init__.py`: build stamp `1.5.9-v47.2`.
4. Added regression tests covering state handling, terminal result cache, timeouts, and transient polling failures.

These changes do not mark any incomplete scan clean or fabricate vulnerability findings. Native report integrity and coverage checks remain in place.

## Safe deployment (Windows laptop)

Wait for running scan jobs to upload their results before replacing agent code. Back up the installation directory and keep your own `.env`, tokens, certificates, and volumes. Extract this archive into `C:\Users\Public`, merging the `laptop-scanner` folder.

```powershell
cd C:\Users\Public\laptop-scanner
# Optional value in .env: GVM_STOP_TIMEOUT_SEC=8
docker compose config --quiet
docker compose build scanner-agent
docker compose up -d --no-deps scanner-agent
docker compose logs --tail 100 scanner-agent
```

No `docker compose down -v`, `docker volume prune`, or Greenbone feed reinitialization is required.

## Follow-up on busy gvmd

If active-task stop requests still time out, collect `docker compose logs --tail 150 gvmd` and `docker stats --no-stream`, and compare the task state in gvmd. An unconfirmed cancellation may have reached gvmd; do not automatically send it repeatedly. Check for ongoing tasks before scheduling a new scan. If a scan has completed and 9 findings were uploaded, the cleanup warning does not invalidate the stored report.

## Validation limits

Source compilation, pytest regression checks, Compose YAML parsing, and ZIP archive integrity were verified in the packaging environment. The live Windows Docker engine and GMP server were not available for an end-to-end integration test.
