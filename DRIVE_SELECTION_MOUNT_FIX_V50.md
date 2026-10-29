# Drive Selection / Mount Fix V50

## Problem
The evidence folder dialog detected Windows drive letters through HostDrive, but opening a drive could trigger Docker mount recovery first. A newly attached HDD/SSD/USB could therefore be visible in the UI but not browsable when Docker Desktop had not yet exposed the drive under `/host/<letter>`.

## V50 flow
1. HostDrive enumerates Windows drives.
2. Clicking a drive lists directories directly from the Windows HostDrive helper when Docker does not already have that drive mounted.
3. Browsing never restarts/recreates Docker services.
4. `Use this directory` records the selected Windows path.
5. When extraction starts, `ensureOfficePathMounted()` mounts the exact selected directory read-only.
6. The existing zero-copy pipeline then lists/registers/processes evidence in place.

## Files changed
- `backend/app/services/hostdrive_agent.py`
- `frontend/src/components/forensic/BrowseFolderDialog.tsx`
- `scripts/host-drive-helper.ps1`
- `scripts/ensure-host-drive-helper.ps1`
- `backend/tests/test_drive_browser_mount_decoupling_v50.py`

## HostDrive helper version
The helper version is bumped to 5.50 so `ensure-host-drive-helper.ps1` replaces an older running helper automatically.

## Validation
Focused regression tests: 35 passed.
`backend/app/services/hostdrive_agent.py` also passes Python byte-code compilation.
