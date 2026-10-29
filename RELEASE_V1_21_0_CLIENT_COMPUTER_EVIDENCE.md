# Polaron V1.21.0: process evidence that stays on the examiner's computer

Until now a disk image or mobile extraction had to sit on a drive attached to the forensic server. Examiners working
from their own PC first had to carry the drive to the server. Now every evidence picker asks **Where is the
evidence?**

- **Forensic server** — unchanged: a drive attached to the server, processed in place.
- **This computer** — a folder on the PC the examiner is using. The image stays there. The forensic server reads it
  over the network while it processes it, and makes no copy of the image.

Processing still happens on the server (CPU/GPU, workers, database). After registration, a client-computer job runs
through exactly the same List folder → register → extract → parse → RAG → report pipeline as a server drive.

## Where the choice appears
- **Disk job → Select evidence directory** (Image 1). "Browse drives" becomes "Browse this computer"; the inline
  "Server evidence browser" becomes the "Client evidence browser".
- **Mobile job detail → Select mobile evidence directory.**
- **Mobile job → Select the mobile image folder** (Image 3). "Select extraction directory…" opens the matching dialog
  for the chosen location; the "This computer" choice also shows an inline browser.

The choice is remembered per job. A job registered from "This computer" shows an "Evidence directory ready on
<computer>" card with a live connection check every 30 s while the pipeline runs.

## The drive popup no longer opens by itself (Image 2)
Opening a new mobile job used to pop the "Select evidence directory" dialog open immediately, before the examiner had
chosen anything. Mobile jobs now behave like disk jobs: the page scrolls to the evidence panel and the dialog opens
only when the examiner clicks **Select folder & start** / **Select extraction directory…**.

## How it works
1. **Polaron Client Evidence Agent** (one-time install on each examiner PC). A single PowerShell file with an embedded
   HTTP server, run at logon in the examiner's own session so it sees their USB and mapped drives. TCP 9877.
2. The browser asks the agent (on `127.0.0.1` only) to publish the selected folder as a read-only share. The agent
   records the frozen file list (name, size, modified time) and returns a share id and a random token.
3. The browser gives these to the server: `POST /api/jobs/{id}/evidence/client-source`. The server connects to the
   agent **over the LAN**, verifies the file list digest and stores the token encrypted in the job.
4. Each processing container mounts the share read-only with FUSE at `/client-evidence/<share>` the first time it
   needs it (API on registration; workers just before each job task runs). No container restart and no Docker
   bind-mount change is needed, unlike server drive letters.
5. The job records the folder as `client-evidence://<share>` and the normal list-folder / ingest-path calls run with
   it. Evidence rows point at the mount path, so pyewf/pytsk3, ZIP/UFDR parsing and hashing read it like a local file.

## Forensic safety
- **Read-only end to end.** The agent opens files with read access only; the mount refuses every write, create,
  rename and delete (`EROFS`). The evidence-manifest side-car that mobile registration writes beside server evidence
  cannot be written there (it fails harmlessly on the read-only mount); the manifest is still stored in the job.
- **Tamper detection.** Every read is checked against the size/modified-time recorded at selection. If a file changes
  on the client during processing, reads fail immediately with `EIO`, the job log says which file changed, and the
  agent's audit log records it. Old and new bytes are never mixed.
- **Never deleted.** `cleanup_policy=never_delete_source`. Deleting a job revokes the share on the agent and unmounts
  it; the files on the client are untouched.
- **No upload path.** A client-computer job can never be switched to the browser-upload (Download Agent) flow.

## Security
- Folder browsing and share creation answer only to requests from the PC itself, only from the Polaron console
  address(es) given at install (`-ConsoleOrigin`), and only with a JSON body (blocks plain form posts). The agent
  checks the Host header too, which defeats DNS-rebinding pages.
- Evidence bytes are served only with the per-share token (stored on the agent only as a SHA-256 hash), never to a
  web browser, and optionally only to the server address given with `-AllowedServer`.
- The server only contacts agents on LAN ranges (`CLIENT_EVIDENCE_ALLOWED_NETWORKS`; loopback, link-local, public
  and the server's own Docker networks are refused), so the endpoint cannot be used to probe internal services.
- Shares expire after 30 days without use. The agent keeps an audit log of shares, revocations and the first read of
  each file in `%LOCALAPPDATA%\Polaron\ClientEvidenceAgent\access.log`.

## Resilience
- Reads use 4 MiB blocks with a 256 MiB cache per mount and sequential read-ahead.
- If the PC drops off the network (Wi-Fi roam, sleep, cable), reads wait and retry every known address of the agent
  for up to 10 minutes before failing, so short outages pause extraction instead of failing it.
- If Redis is flushed, the share is rebuilt from the job record the next time the evidence is resolved.

Throughput is limited by the network (gigabit Ethernet carries at most about 110 MB/s) and was not benchmarked in
this release. Very large images will process faster from a drive attached to the server.

## Install
### Server
Rebuild the backend image and recreate the containers (all three stacks):
- `backend/Dockerfile`: `fuse3 libfuse2t64`; `backend/requirements.txt`: `fusepy==3.0.1`.
- Every processing container gets `/dev/fuse`, `cap_add: SYS_ADMIN` and `security_opt: apparmor:unconfined`
  (`x-client-evidence-fuse` in `docker-compose.yml`, `x-app-common` in the Android/iOS compose files).
- Optional `.env` settings are listed in `.env.example` (`CLIENT_EVIDENCE_*`). `CLIENT_EVIDENCE_ENABLED=false`
  switches the feature off.

### Each examiner PC (Windows 10/11; Chrome, Edge or Firefox)
When "This computer" is chosen and the agent is missing, Polaron shows the steps and download links:
1. Download `Install-PolaronClientEvidenceAgent.cmd` and `polaron-client-evidence-agent.ps1` into one folder.
2. Run the `.cmd`, approve the administrator prompt once, and enter the Polaron console address.
3. Polaron connects automatically.

Or paste the one-line PowerShell command Polaron shows. The installer reserves the port, adds an inbound firewall
rule for TCP 9877 (local subnet, or only `-AllowedServer`), and registers a logon task. Check it with
`polaron-client-evidence-agent.ps1 -Status`; remove it with `-Uninstall`.

## Verification
- Agent C# compiled under C# 5 rules (Windows PowerShell 5.1 `Add-Type`) and run under Mono: every endpoint and
  security rule exercised; Python and C# manifest digests identical (including non-ASCII names). The script passes
  the PowerShell 7.4 parser.
- Real end-to-end on Linux FUSE: byte-identical SHA-256 for every file, 300 random-offset reads identical, writes
  refused; agent stopped mid-read → read paused 7.7 s and completed; file modified → `EIO` at once; share revoked →
  mount removed itself in ~30 s.
- `backend/tests/test_client_evidence_v1_21.py`: 33 tests, including a real FUSE mount and `register_segments` from a
  client folder. Frontend: type-check, production build, 31/31 vitest (9 new, including the full "This computer"
  flow and the compact mobile view).
- Fixed during testing: nested folders (e.g. `05_Exports/<run>/`) were missing from the mounted listing.

## Not verified here
The Windows-only installer steps (port reservation, firewall rule, logon task, elevation round trip) and a run
inside Docker Desktop. See "First-run checklist" below.

## First-run checklist
1. Server: rebuild/recreate; then `docker compose exec api ls -l /dev/fuse` shows the device.
2. Examiner PC: install the agent; `-Status` shows `LAN=True` and the PC's address.
3. From the server: `docker compose exec api python -c "import httpx;print(httpx.get('http://<PC-IP>:9877/health').json())"`.
4. Create a disk job → **This computer** → select a small E01 set → extraction starts; the job card shows
   "Connected to <PC>".
5. While extracting, unplug the PC's network for under a minute → the card shows "Waiting for <PC>…", then
   extraction continues.
6. Delete the job → `-Status` on the PC shows one share fewer; the image is still on the PC.
