# USB/External evidence drives: ENODEV remediation and limits

## Verified root cause
Windows recognizes the G: USB NTFS filesystem, but the Docker Desktop Linux daemon cannot bind it (ENODEV). E01 parsing and React are not responsible. Rewriting Compose paths cannot create a missing Docker device.

## What this release adds
`scripts/Watch-EvidenceDriveMounts.ps1` continuously rechecks the exact selected path through the existing resolver, recording machine-readable state in `logs/evidence-drive-mount-watch.json`. It neither restarts active jobs nor claims that verification alone activates a worker mount. This is a diagnostic and safe recovery component, **not an unconditional ENODEV cure**.

Start in elevated or normal Windows PowerShell **as the same account that runs Docker Desktop**:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Watch-EvidenceDriveMounts.ps1 -EvidencePath 'G:\2026SEP-11\E-Drive\data\Image of Ex-5 Histotechlab1 512GB.E01' -Once
```

To watch for reattachments, omit `-Once`.

## Required one-time host fix (local AND production Windows Docker Desktop hosts)
1. Verify Docker is using Linux containers and WSL2 backend: `docker info`, `wsl -l -v`, `wsl --status`.
2. Install a normal WSL2 Ubuntu distro (`wsl --install -d Ubuntu`) if absent, complete first-run setup, enable **Settings > Resources > WSL Integration > Ubuntu** in Docker Desktop and Apply & Restart *when no cases are processing*.
3. Check evidence in WSL: `wsl -d Ubuntu --exec sh -lc "ls -l '/mnt/g/2026SEP-11/E-Drive/data/Image of Ex-5 Histotechlab1 512GB.E01'"`.
4. Invoke `scripts/Repair-DockerEvidenceDrive.ps1 -DriveLetter G -RequiredPath 'G:\2026SEP-11\E-Drive\data\Image of Ex-5 Histotechlab1 512GB.E01'`.
5. If read-only Docker probe succeeds, refresh the actual HostDrive worker mount and validate the **same image size and segment inventory from inside that worker** before resuming.
6. If both native and WSL binds return ENODEV, Docker Desktop's engine/file-sharing layer needs administrator remediation, not another Compose edit. After checkpointing all cases, update/restart Docker Desktop + WSL. For a genuinely permanent cross-device solution, implement an authenticated Windows-host evidence reader with random-access reads, immutable source identity and hashing, plus a Linux-compatible virtual block/file adapter; that transport is not implemented by this patch.

## Forensic safety
- Never silently ignore missing E01 segments.
- Never mark 100% extraction after a mount failure.
- A successfully verified file is not evidence identity verification; drive letters can be reassigned.
- No automatic disruptive Docker restart during processing.
- Do not rely on direct raw USB passthrough for E01 files; they are regular files on Windows NTFS.
- Do not expose the host-side evidence reader publicly or grant write access to source disks.
