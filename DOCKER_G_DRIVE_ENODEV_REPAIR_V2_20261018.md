# Polaron2 Docker Desktop `G:` no-such-device repair, v2 (2026-10-18)

## Failure

`invalid mount config for type "bind": stat /run/desktop/mnt/host/g: no such device`

Old HostDrive resolver additionally attempted direct `G:\`, `/mnt/host/g`, `/run/desktop/mnt/host/g`, `/host_mnt/g`, and `/g`; some daemon-Linux paths were tested through temporary `aetheris_drive_probe_<hex>` local volumes and all hit the *same* unavailable Docker Desktop Windows share.

**This is a Docker Desktop Windows-drive accessibility failure, not PostgreSQL, Redis, CUDA, or the disk parsing semaphore.** The code cannot make a physically disconnected/locked/unshared Windows disk accessible. Do not continue extraction until Docker sees the actual evidence path.

## Code fixes

1. `scripts/resolve-docker-drive-source.ps1`: direct Windows source `G:/` is tested once, followed by the existing *verified* WSL2 integration route when available. It no longer loops through aliases that lead to the same `G:` share or creates daemon-local probe volumes. Old unsafe Docker Desktop *internal* 9p-remount methods removed. Image lookup now prefers a locally cached Python-based project image when the API has not started; probes do not pull images. Root-only probes reject empty stub directories. Failures are summarized instead of emitting pages of duplicate daemon errors.
2. `scripts/generate-drive-mounts.ps1`: old JSON source-map entries never suppress a fresh **Windows** bind test. WSL mappings are accepted only in WSL execution mode used by the refresh job after its own source check. Supports `AETHERIS_EXCLUDED_DRIVES` (for unused optional drives) and `AETHERIS_REQUIRED_DRIVES` (strict check for required evidence); specifying the same letter in both fails safely. Existing split forensic/Android/iOS Compose override refresh is preserved.
3. `scripts/Repair-DockerEvidenceDrive.ps1`: read-only Windows/Docker diagnostic, optional cleanup of *only unused legacy temporary* probe volumes (never `docker volume prune`), verified direct-mount regeneration, and clear handling of WSL/exact-folder sources. Uses the existing HostDrive activation route for verified WSL and selected-folder mounts.
4. No changes to 8-way CPU parsing, CUDA jobs, PostgreSQL, MinIO, evidence hashes, case records, checkpoints, or actual evidence files.

## Before applying

Back up project scripts, selected current Compose YAML files, running-case metadata, and your PostgreSQL/MinIO data. Checkpoint active forensic jobs before restarting Docker Desktop, because restarting stops running containers. Never run `docker compose down -v`, `docker volume prune`, or wipe Docker Desktop's WSL storage for this error.

## Apply hotfix in Windows PowerShell (project root)

```powershell
# Place the hotfix ZIP in the root of the EXISTING Polaron2 project.
Expand-Archive -LiteralPath .\polaron2_gdrive_enodev_hotfix_v2.zip -DestinationPath . -Force
```

### Path A: G: has actual evidence and must work

```powershell
Test-Path 'G:\'
Get-Volume -DriveLetter G | Format-List DriveLetter, FileSystem, HealthStatus, OperationalStatus
# Replace the example with the exact E01/E02 folder/file you selected.
Test-Path 'G:\Cases\Case001\image.E01'

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 `
    -DriveLetter G -RequiredPath 'G:\Cases\Case001\image.E01'
```

If Windows returns `False`, reconnect the disk, unlock BitLocker if applicable, inspect Disk Management, and ensure the expected drive letter exists. Do not format or initialize the evidence disk. If Windows returns `True` but Docker still reports ENODEV, **after all running forensic jobs are checkpointed**, close Docker Desktop, unplug/replug the external disk, start Docker Desktop again and re-run the diagnostic. You may also check `wsl --list --verbose`; if a user WSL2 distribution exists, enable **Docker Desktop > Settings > Resources > WSL Integration** for it. A verified WSL source must be activated through **HostDrive > Select disk folder / Refresh drive mounts**, not pasted as a Windows `G:/` bind.

If recovery is still unsuccessful, the diagnostic exits nonzero and the required G: path remains **unavailable**. This is safer than adding a false/empty bind and reporting evidence as processed.

For a strict required-drive startup check after the repair:

```powershell
Remove-Item Env:AETHERIS_EXCLUDED_DRIVES -ErrorAction SilentlyContinue
$env:AETHERIS_REQUIRED_DRIVES = 'G'
.\script_docker\start_docker_local.cmd
```

Use `start_docker_nitin.cmd` or `start_docker_prod.cmd` for your actual profile.

### Path B: G: is an unused/disconnected OPTIONAL drive

Do not use this option if case data is on G:. To start forensic services without a broken optional G: bind:

```powershell
Remove-Item Env:AETHERIS_REQUIRED_DRIVES -ErrorAction SilentlyContinue
$env:AETHERIS_EXCLUDED_DRIVES = 'G'
.\script_docker\start_docker_local.cmd
```

The main launcher regenerates forensic, Android and iOS mount overrides before Docker Compose preflight; G: is omitted and other verified drives remain available. You can separately regenerate the current files:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 -DriveLetter G -ExcludeIfOptional
```

The environment variable persists only in the current PowerShell session; don't set the exclusion permanently when you later need evidence from G:.

### Optional: clean up unused legacy probe volumes

Only after case jobs have checkpointed, and only if you want to remove these particular temporary volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 -DriveLetter G -CleanUnusedProbeVolumes
```

The script only matches names `aetheris_drive_probe_<32 hex chars>` and calls `docker volume rm` **without** `-f`. Docker refuses a volume in use. This has no bearing on whether G: becomes readable. If the probe itself still fails, it returns an error despite any cleanup.

## Inspect effective mount configurations

```powershell
Select-String -Path .\docker-compose.drives.forensic.yml -Pattern 'source:|target:'
docker compose --project-directory . --project-name aetheris-forensic `
  -f services/forensic/docker-compose.yml `
  -f docker-compose.drives.forensic.yml config --quiet

# To check whether the running helper is actually from this project:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\hostdrive-doctor.ps1
# If it reports a stale helper/version, after jobs checkpoint:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\hostdrive-doctor.ps1 -Fix
```

`config --quiet` verifies YAML structure only. A real evidence proof requires a read-only mount of the actual selected path inside the Docker forensic API/worker; the new resolver performs that check. Checkpoint/completeness status must not move to completed when this source is inaccessible.

## Validation and limitations

The source-level regression suite includes `test_g_drive_enodev_failclosed_20261018.py` and `test_drive_mount_startup_failsafe_20261018.py`, as well as existing forensic drive tests. Windows PowerShell 5.1 and Docker Desktop G: hardware were **not** available in this environment. The 8 failures from several older drive/UI assertion tests exist in the unmodified prior package as well (legacy test expectations) and were not introduced by this patch. A Windows runtime test on your machine is still required.
