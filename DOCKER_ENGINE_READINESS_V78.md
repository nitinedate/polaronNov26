# Docker Desktop startup fix (v78)

The v77 launcher could terminate on native stderr under Windows PowerShell 5.1 before checking the Docker exit code. Its opt-in recovery path executed a file containing function definitions without calling the engine restart function.

The updated local/nitin/prod launcher, sequential startup, and direct stack startup share a readiness check. It captures native errors, waits up to 120 seconds for the engine, requires Linux containers and Compose v2, and reports the last Docker response. When a forced DOCKER_API_VERSION fails, it tries normal negotiation; it keeps the process override removed only if that retry succeeds. It never hardcodes an older API version or changes persistent environment settings.

If -AutoRecoverEngine is supplied and the readiness checks fail, it calls the existing Docker Desktop restart function. This stops Docker Desktop and runs wsl --shutdown, interrupting all WSL distributions and running containers. Normal startup does not restart the engine automatically.

## First try on Windows PowerShell

Restart Docker Desktop using Troubleshoot > Restart, wait until the engine is running, then run these commands in the extracted project folder:

```powershell
Remove-Item Env:DOCKER_API_VERSION -ErrorAction SilentlyContinue
docker version
docker info
```

Continue only when docker info succeeds. Run your usual launcher, for example:

```powershell
.\script_docker\start_docker_local.cmd
```

For explicit automated engine recovery with the updated launcher:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\script_docker\start_docker.ps1 -Profile local -AutoRecoverEngine
```

Use -Profile nitin or -Profile prod for your existing public deployment profile. Retain your existing .env, host settings, and certificates when applying the update.

If Docker still returns 500, collect docker version, docker context show, wsl --status, and wsl --list --verbose. The error alone does not establish an API mismatch; the Docker Desktop Linux backend may be unavailable. Rebuilding application images cannot repair an unavailable engine.

## Validation

Archive integrity, unchanged-file byte comparison, and startup integration checks were run in Linux. Windows PowerShell and Docker Desktop are unavailable in this environment, so live Windows readiness/restart behavior has not been tested.
