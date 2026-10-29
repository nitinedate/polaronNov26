# Polaron2 Windows Docker Desktop drive-mount startup repair

**Issue:** `Start forensic` fails with `invalid mount config for type "bind": stat /run/desktop/mnt/host/g: no such device`.

## Verified source-level cause

`script_docker/start_docker.ps1` previously refreshed only `docker-compose.drives.generated.yml`, while `Get-StackComposeArgs` includes the **product-specific** `docker-compose.drives.forensic.yml`, `docker-compose.drives.mobile-android.yml`, or `docker-compose.drives.mobile-ios.yml`. The shipped split-stack override contained a stale `G:/` bind. Separately, the generator retained previously mapped drives when Docker probe timed out, and the startup launcher reused stale YAML on a scan failure. Windows may report a letter even when Docker Desktop cannot mount its device.

**Redis/PostgreSQL healthy** is unrelated. The network warning (`aetheris-common` already exists) is also informational and is not the blocking error.

## Changes made

1. `scripts/generate-drive-mounts.ps1` accepts `-WriteStartupStackOverrides`. One drive discovery produces the generic plus all three split-stack overrides with **identical, currently verified** drive sources. Writes occur via temporary sibling YAML files, not partially written output.
2. Docker drive probing now uses `--mount type=bind,...` rather than `-v`, so the probe cannot create a missing evidence directory. An unavailable/no-image/timed-out probe is **not** treated as a mounted drive just because a previous YAML contained it.
3. A user-specified `-RequireDrive G` refuses an inaccessible drive rather than silently skipping it. Optional drives can be omitted so **other evidence disks** and services still start.
4. `script_docker/start_docker.ps1` refreshes all four YAML files *before* Compose preflight, checks timestamps and required contents, and **fails safely** if a scan cannot complete (does not restart containers using stale mounts).
5. Startup-generated bootstrap override files ship with only `C:/`, not drive letters copied from somebody else's workstation. The actual connected drives are populated at launch.
6. `scripts/Repair-MissingDriveMount.ps1` provides a non-destructive, Windows PowerShell 5.1-compatible repair and Compose configuration check.

## Apply the ZIP patch into the existing optimized project

**Back up** the original `script_docker/start_docker.ps1`, `scripts/generate-drive-mounts.ps1`, drive overrides, and running PostgreSQL/MinIO data first. Run PowerShell in the project root:

```powershell
# Extract the downloaded changes-only ZIP into the project root (not into script_docker/).
Expand-Archive -Path .\polaron2_drive_mount_hotfix.zip -DestinationPath . -Force

# Only if G: is not your evidence source, force it out of the current mapping:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-MissingDriveMount.ps1 -ExcludeDrive G

# If G: actually contains case evidence, require Docker access instead:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-MissingDriveMount.ps1 -RequireDrive G
```

The last two repair commands are **alternatives**, not sequential steps. Either way, normal startup automatically detects and verifies available drives:

```powershell
.\script_docker\start_docker_local.cmd
# Or start_docker_nitin.cmd / start_docker_prod.cmd for your configured profile.
```

You should now see:

```text
Refresh Windows drive/evidence mount configuration
[drive scan] Docker can read G: no           # only when Windows reported but Docker rejected G:
[drive scan] Excluding G: Docker probe returned no
Current forensic drive mounts: C, D, E, F   # example, actual letters vary
Generic, forensic, Android and iOS drive overlays refreshed from one verified scan.
Start shared infrastructure ...
Start product stacks
```

### Verify the generated forensic Compose mapping

```powershell
Select-String -Path .\docker-compose.drives.forensic.yml -Pattern "source:|target:"
docker compose --project-directory . --project-name aetheris-forensic `
  -f services/forensic/docker-compose.yml `
  -f docker-compose.drives.forensic.yml config --quiet
```

**If the actual evidence resides on G:** reconnect the USB/HDD and check:

```powershell
Test-Path 'G:\'
Get-Volume -DriveLetter G
# Use an available small Linux image such as alpine:
docker run --rm --mount "type=bind,source=G:/,target=/probe,readonly" alpine:3.20 ls -la /probe
```

If the Windows path is readable but Docker bind is not, do **not** treat this as successful acquisition. Use the existing HostDrive selected-folder mount/WSL bridge resolution flow, or repair Docker Desktop drive sharing and revalidate the selected evidence path inside the forensic API/worker before processing. Do not create an empty replacement `G:` directory or falsely mark missing source artifacts as completed.

## Scope and validation

- Includes current Disk8/CUDA performance updates unchanged.
- No change to evidence bytes, PostgreSQL tables, MinIO buckets, RAG records, credentials, `*.env`, or stored checkpoints.
- `backend/tests/test_drive_mount_startup_failsafe_20261018.py` covers source contracts, selected service mapping, and safe defaults; the existing disk-quality and drive-discovery regressions were run together (29 passing in this execution).
- **Limitations:** Windows PowerShell 5.1, actual Docker Desktop bind access, and a physical G: disk were **not available in the test container**. Run the in-place repair and startup validation above on the target PC before treating this as production-verified. The existing `backend/tests/test_dynamic_drive_compose.py` contains 6 pre-existing legacy assertions that fail equally on the input and modified projects; this fix does not claim to correct those unrelated assertions.

No need to remove Docker volumes, reset Redis or PostgreSQL, prune Docker images, copy evidence, or disable CUDA.
