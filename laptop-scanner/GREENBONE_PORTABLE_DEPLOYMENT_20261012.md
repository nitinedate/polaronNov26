# Portable laptop scanner startup

Extract this complete project anywhere (including C:, D:, E:, network paths supported by Docker Desktop file sharing), preserving the project folder layout. Run `Start-Laptop.cmd` from the extracted folder. The launcher determines its root using `%~dp0`; PowerShell obtains its root via `$PSScriptRoot`. Repair commands also resolve their root from the launcher location.

No startup launcher falls back to a separate drive. Agent tokens are written **only** to the active project instance, never copied to an unrelated installation on D: or E:. The existing `.env` remains the authoritative runtime settings source. Do not run multiple copies using the same Compose project name concurrently; stop the older one first. Verify Docker Desktop has permission to share the selected drive/directory when bind mounts are used.

From any PowerShell working directory run `& 'C:\some folder\laptop-scanner\Start-Laptop.cmd'` (replace with the actual location), or change into your project folder and run `.\Start-Laptop.cmd`. Diagnose Greenbone with `.\Repair-Greenbone-Feed.cmd`. No persistent Docker volumes are removed.

Validation here covers packaging and static checks, not live Windows Docker operation.
