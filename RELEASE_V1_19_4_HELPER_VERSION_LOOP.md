# Polaron V1.19.4: fix the "workstation helper needs a restart" loop

The page said the helper is v5.36 and keeps asking for a restart, and the restart does not stick. The cause: the
helper is restarted from the host-drive-helper.ps1 in the Polaron folder, so if THAT folder was not updated to the
current release, the restart just relaunches the same old helper. The scripts reported success anyway, so the UI
asked for a restart forever.

## Fixed
- **The restart is verified.** After the helper comes online, ensure-host-drive-helper.ps1 now checks it actually
  reports the expected version. If it is still old, it says exactly why and what to do, and exits non-zero instead of
  claiming success:
  - the Polaron folder it runs from is stale (overlay the latest patch onto THAT folder), or
  - another Polaron folder on the workstation is running the helper (close it or restart the workstation).
- **start_docker says the same.** The deployment helper step now reports a version mismatch and the stale-folder
  cause, rather than just "run -ForceRestart".

## What to do on your workstation (helper stuck at v5.36)
1. Find the Polaron folder the helper runs from (the path printed by the scripts; likely where you run start_docker).
2. Overlay the latest patch onto THAT exact folder, so scripts\host-drive-helper.ps1 becomes the current version.
3. Run: scripts\ensure-host-drive-helper.ps1 -ForceRestart
   It will now confirm the helper is v5.55. If it still reports an old version, another Polaron folder is running the
   helper - close that one (or restart the workstation) and run step 3 again.

No Docker rebuild is needed for this; it is a workstation-script fix.
