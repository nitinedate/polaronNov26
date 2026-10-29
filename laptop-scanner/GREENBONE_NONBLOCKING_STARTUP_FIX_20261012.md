# Greenbone startup and feed readiness fix (2026-10-12)

This is the **complete laptop-scanner project**, not the Polaron central-server project.

## Changed
- `scripts/Repair-Greenbone-Feed-v1.4.1.ps1`: the initial VT/NVT wait now respects `FeedLoadWaitMinutes` instead of silently extending to 180 minutes.
- The optional feed-container `--force-recreate` runs **only** with explicit `-RefreshFeedContainers`; missing feed files trigger a warning, not a destructive or repeating action.
- On timeout, reports container status, restart/OOM information, and recent OSPd/GVMD logs; exits with code 10 without deleting volumes or restarting OSPd.
- `scripts/start-laptop.ps1`: defaults to a 2-minute Greenbone readiness budget; scanner-agent stays online while loading.
- `.env` and `.env.example`: `GVM_FEED_LOAD_WAIT_MIN=2` defaults; existing local override values still take priority.

## Windows PowerShell
```powershell
cd D:\laptop-scanner
.\Start-Laptop.cmd
# For an explicitly longer diagnostic wait, rather than blocking every startup:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-Greenbone-Feed-v1.4.1.ps1 -Root (Get-Location).Path -FeedLoadWaitMinutes 10
docker compose ps
docker compose logs --tail 100 ospd-openvas gvmd
```

Do not run `docker compose down -v`. The missing `Full and fast` scan configuration may also require a correct Feed Import Owner, GVMD data import, and functional OSPd inventory; timeouts alone do not fix a broken feed. Greenbone is **not** considered ready until the readiness probe succeeds.

Validation performed: Python files compile and ZIP integrity check. Docker engine and live feed import cannot run in the packaging environment.
