# Polaron V1.25.0: antivirus (ClamAV) for Malware Detection, isolated from the PC and server

## What was already there (unchanged)
- Malware Detection never executes a sample: engines (hashes, IOC, YARA, static, behaviour, ML) read evidence as data.
- Sample export is an AES-encrypted ZIP (password "infected"), audited, with a reason.
- **Removal from the phone** (Android): "Remediate" on a scan removes flagged apps from the connected phone through the
  workstation helper. It needs the `malware:remediate` permission and a written consent record, is audited, and
  starts a confirming re-scan. iOS removal is not available.
- Threat-intel feeds update at fixed daily times (11:30 and 15:30 IST by default) and catch up after downtime.

## New: antivirus engine (ClamAV)
A new scan stage **Antivirus (ClamAV)** runs after hashing in **every profile** (including Quick). It checks apps and
every file type that can carry malware, including Windows payloads stored on a phone (`.exe`, scripts, macro
documents, archives), because a phone used as a USB carrier is how a PC gets infected. Deep scans check every file.
Archives (APK, ZIP) are unpacked by the scanner. Detections become findings attributed to the app, with the
signature, engine version and definitions version; `PUA.*` and heuristic hits are graded lower than malware, and the
EICAR test file is marked as a test.

### Isolation: why a malicious file cannot reach the PC or the server
- **Nothing is executed.** File bytes are read from the read-only evidence store and streamed to the scanner over a
  socket; no sample is written to disk on the worker or the scanner.
- **The scanner lives in its own box** (`clamav-scan`): an `internal` Docker network (no internet and no route to the
  Windows host), read-only file system, read-only definitions, all Linux capabilities dropped, no privilege
  escalation, non-root user, memory and process limits. Even a file that exploited the antivirus engine itself
  would land in a container with nowhere to go.
- **The updater never sees samples** (`clamav-update`): it has internet access only to download definitions.
- **Baseline hardening for every Malware Detection container:** no privilege escalation and no raw sockets, device
  nodes, chroot or capability changes; process limit on the static-analysis worker.

### Definitions: at every start and daily
- `clamav-update` downloads definitions **when it starts** (so at every server start) and **daily** at
  `CLAMAV_UPDATE_TIME` (default 11:00, time zone `CLAMAV_TZ`, default IST). After a failure it retries after an hour
  (5 minutes while no definitions exist yet). The scanner reloads new definitions by itself within 10 minutes.
- Threat-intel feeds now also refresh **at every start** (`MALWARE_INTEL_SYNC_ON_STARTUP`, default on), in addition
  to their daily times.
- Labs without internet: `CLAMAV_PRIVATE_MIRROR` (a cvdupdate mirror); behind a proxy: `CLAMAV_PROXY_SERVER/PORT`.
- **Threat intelligence page:** a new card shows the engine and definitions version in use, their age, the last update
  check and its result, and the next check. It warns when the scanner is down or definitions are older than
  `MALWARE_AV_MAX_DEFINITION_AGE_HOURS` (48 h). A scan run without the scanner says so in its notes; it is not silent.

## Install
`docker compose -f services/mobile-malware/docker-compose.yml --project-directory . up -d --build`
(builds `aetheris-mobile-malware-clamav` from the official ClamAV 1.4 LTS image). The first definitions download
takes a few minutes; the scanner waits for it. Allow about 3 GB of memory for the scanner.

## Verification
- `backend/tests/test_malware_antivirus_v1_25.py` (15 tests) uses a **real clamd** with test signatures: EICAR and a
  "stalkerware" marker hidden in the compressed DEX of an APK (found inside the archive); the antivirus stage flags
  the app and a Windows payload in `Download`, leaves a camera photo alone, and treats an unreachable scanner as a
  noted limitation. The container entrypoint runs under busybox (as in the Alpine-based image): daily schedule in
  IST, start-up update with version recording, failure keeps the last success and retries, scanner waits for
  definitions. Compose isolation is checked by test.
- Frontend: type-check; antivirus card tests; existing tests unchanged.

## Not verified here, and recommended next steps
- **Real definitions and the real image:** this sandbox cannot reach the ClamAV mirror or run Docker. On first start,
  check the Threat intelligence card shows definitions and "up to date".
- **Removal does not check that the app's APK was captured first.** Recommended: refuse removal of an app whose APK is
  not in the scan evidence, so evidence is never lost by remediating.
- **Live triage on the examiner PC** pulls APKs into a temporary folder before bundling. Android malware cannot run on
  Windows, but Windows Defender may quarantine files mid-collection. Recommended: stream directly into an encrypted
  bundle. Meanwhile, connect phones in ADB mode only (no MTP / AutoPlay) and never open files from a phone on the PC.
- **The existing analysis engines** (androguard, LIEF, YARA, apkid) still parse hostile files inside their worker
  (now hardened, but with network access to the database and storage). Recommended: move them into a no-network
  sandbox container like the antivirus scanner.
