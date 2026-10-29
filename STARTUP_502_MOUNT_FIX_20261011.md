# Polaron startup + 502 readiness fix

Three existing launchers (`script_docker/start_docker_local.cmd`, `_nitin.cmd`, `_prod.cmd`) all call `start_docker.ps1`.

Changes in the shared launcher:
- Before stopping any containers, checks configuration, gateway assets and Compose, and refreshes drive mount overrides.
- Stops *only* Compose-managed projects owned by Polaron (`aetheris-*`), preserving named volumes, case evidence and unrelated Docker containers. This is intentional rather than stopping every Docker container on the host.
- Runs the existing build/up sequence and checks the gateway, API service health, generated mount override and Android API's real `/health` endpoint.
- Returns a nonzero exit code rather than saying READY if a required API is unreachable (the cause of a 502 from nginx).
- Restores gateway Compose/Nginx templates omitted from the V82 distribution using earlier project sources.

**Limits**: No active Docker Desktop daemon on this testing host. Actual bind-mount visibility from each worker, browser folder listing and Nginx end-to-end 502 fix must be checked on Windows staging. Existing job processing should be checkpointed before the launcher stops the project containers. The launcher does not stop other users' containers.

## Windows verification

From the extracted project root:
```powershell
.\script_docker\start_docker_local.cmd
# Or use start_docker_nitin.cmd / start_docker_prod.cmd

docker compose -p aetheris-mobile-android -f services/mobile-android/docker-compose.yml ps
docker logs --tail 100 aetheris-mobile-android-api-1
```

Use your exact Compose project/container names if they differ. Confirm new case paths are visible through the browser and both Android/Forensic API health endpoints return HTTP 200. The build has not been live tested here.
