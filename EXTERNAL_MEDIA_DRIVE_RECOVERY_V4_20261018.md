# Polaron2 external HDD / SSD / USB evidence access — V4

## Incident

The Windows host can read `G:\DISK2\DataExtration\SegerEx-1` while Docker Desktop's Linux VM returns **ENODEV** for `G:/`. This is a Docker Desktop file sharing problem; replacing `G:/` with `/mnt/host/g`, `/host_mnt/g`, etc. addresses the same unavailable device and does not repair it.

## Implementation

1. Windows HostDrive lists attached filesystem volumes of any storage bus: internal/external HDD, USB SATA SSD, USB NVMe SSD and USB flash drive. Devices with `DriveType=Fixed` are **not** rejected as internal.
2. The browser uses HostDrive's native Windows folder listing to let an examiner select an exact E01/E02/E99 segment folder even before it has a Docker mount. No root bind is attempted from the drive tile.
3. For extraction, a verified read-only mount is mandatory. The resolver tests a native Windows drive bind ONCE, then an exact selected-folder bind (not another equivalent internal alias). If neither works, the resolver tests the drive using the same Docker Desktop-integrated WSL2 distribution used for the Compose launch, including a DrvFs bridge if necessary.
4. Generated forensic, Android and iOS Docker Compose drive overrides use verified mappings; disconnected optional media are omitted and required evidence is never silently substituted.
5. A Windows listing and Docker listing of the selected source are compared by name/type/file length (including beginning and ending segments); a stale mount after swapping a USB disk does not mean the original evidence is still present. Original evidence remains read-only.
6. `scripts/Test-ForensicMedia.ps1` reports Windows media/bus/readiness and verifies the *selected* folder using the resolver. The HostDrive drive watcher sees newly inserted letters without restarting active cases.

## Install hotfix without replacing your .env or PostgreSQL

From the **existing Polaron2 project root** (stop active case work before changing scripts):

```powershell
Expand-Archive -LiteralPath .\polaron2_external_media_hotfix_v4.zip -DestinationPath . -Force
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ensure-host-drive-helper.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ForensicMedia.ps1 -EvidencePath 'G:\DISK2\DataExtration\SegerEx-1'
```

If direct and exact-folder probes fail, install a user WSL2 distro *if not already present* and enable Docker Desktop WSL Integration. This is a prerequisite, **not** something the patch can bypass:

```powershell
wsl --list --verbose
# Only if an Ubuntu WSL2 distro is absent:
wsl --install -d Ubuntu
# Then launch Ubuntu once to finish account setup.
```

Docker Desktop > Settings > Resources > WSL Integration > enable Ubuntu > Apply. Then, with the USB drive connected and an installed Ubuntu distro, run:

```powershell
wsl -d Ubuntu --exec sh -lc 'ls -lah /mnt/g/DISK2/DataExtration/SegerEx-1'
wsl -d Ubuntu --exec docker info
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ForensicMedia.ps1 -EvidencePath 'G:\DISK2\DataExtration\SegerEx-1'
```

The resolver can attempt a DrvFs mount in WSL when normal `/mnt/g` is absent. **Do not** use `wsl --mount` to attach a Windows-mounted USB flash drive, and **do not** initialize/format the evidence disk.

When the diagnostic reports `docker_readable = True`, restart your normal launcher:

```powershell
.\script_docker\start_docker_local.cmd
```

If the diagnostic returns `docker_readable = False`, do **not** mark the case processed. The Windows host can read the drive but the Docker engine still cannot. Check WSL integration, external disk health, and Docker Desktop host file sharing. This hotfix does not include an unverified HTTP/FUSE virtual-filesystem bridge, nor does it copy a 100 GB image just to make the error disappear.

## Safeguards / limitations

- No writes to source drive; no full-image copy; no destructive docker volume commands; no PostgreSQL reset.
- Support means **Windows-mounted readable filesystem volumes** regardless of HDD/SSD/USB bus. For a raw device without a volume/drive letter, imaging/acquisition must occur first.
- Windows may expose a volume while Docker Desktop cannot access it. An examiner must make one verified direct/WSL read-only bind path available before EWF/TSK can process the case.
- Source verification compares sampled metadata; full cryptographic validation is handled independently by the forensic ingestion pipeline. It cannot prove completeness or substitute for hashes of actual evidence bytes.
- Python/backend and source-regression tests can run in Linux CI; physical-drive verification must run on your Windows workstation.
