# Polaron V1.26.1: the antivirus starts with the stack

V1.25.0 added the ClamAV containers (`clamav-update`, `clamav-scan`) to the Malware Detection compose file, but one
of the two startup paths never started them.

## Startup paths
- **`script_docker/start_docker_local.cmd`, `start_docker_nitin.cmd`, `start_docker_prod.cmd`** (`start_docker.ps1`):
  already covered. They build every service that has a build section and run `docker compose up -d` without a
  service list, so both ClamAV containers are built and started. Change: the two ClamAV files are now in
  `start_docker.required-files.json`, so an incomplete copy stops at the pre-flight check with a clear message.
- **`startup.cmd` / `scripts/start-stack.ps1`**: fixed. This path starts named services in waves, and the ClamAV
  containers were not named, so they never started. Now:
  1. `clamav-update` starts first, without waiting, so the definitions download runs while the API and workers start.
     Its image is always allowed to build (even with `-NoBuild`), because a missing local image cannot be pulled.
  2. API and workers start as before.
  3. `clamav-scan` starts last, without waiting: it turns healthy only after the first definitions are loaded,
     which on a first install can take longer than the startup wait.
  Neither ever stops the stack: if they cannot start (for example Docker Hub is unreachable for the ClamAV base
  image), startup prints a warning and Malware Detection runs; scans record that the antivirus was unavailable.
- **`scripts/check-malware-stack.ps1`**: new "Antivirus (ClamAV)" section - updater and scanner state, the last
  definitions check and its result, and what to do; `-Fix` starts the antivirus too.

## Verification
`start-stack.ps1 -Service mobile-malware` run under PowerShell 7 with a recording stand-in for `docker`: commands in
the intended order (updater, API wave, worker wave, scanner); with `-NoBuild` the updater can still build; with the
ClamAV commands failing, startup warns and finishes. The diagnostic's antivirus section checked against faked
container state. Both scripts pass the PowerShell parser.

## Not verified here
Real Docker on Windows. After the next start: `.\scripts\check-malware-stack.ps1` should show both containers and
"last definitions check ... up_to_date" (or "updated").

## Noticed, not changed
`start_docker.required-files.json` lists `tools/host-python-requirements.txt`, which is not in the uploaded project
(it was already listed and missing in V1.20.1). Keep `tools/` from your server copy when deploying from this zip.
