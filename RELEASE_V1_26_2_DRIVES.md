# Polaron V1.26.2: clear error for data on a disconnected drive; drive detection on a fresh machine

## The startup error
`STARTUP ERROR: Cannot find drive. A drive with the name 'F' does not exist.` was not caused by drive detection.
The drive scan worked (it found C and E). Your `.env` keeps MinIO's data on drive F:

    MINIO_DATA_DIR=F:/aetheris/minio

MinIO holds the extracted evidence and artifacts of every job. With F: disconnected, the bind-mount check tried to
create `F:\aetheris\minio`, and PowerShell failed with its own message. Starting MinIO on an empty folder instead
would hide all existing evidence and write new data to the wrong place, so startup must stop; it now says why:

    Drive F: is not connected, but service 'minio' keeps its data there: F:\aetheris\minio (container path /data),
    set by MINIO_DATA_DIR=F:/aetheris/minio in .env. Startup stops so the service never starts on an empty folder
    and hides the existing data. Connect drive F: and start again, or, if the data has moved to another drive,
    change MINIO_DATA_DIR in .env to the new location.

The same applies to any data folder in `.env` on a disconnected drive. An evidence drive that disappears between
the drive scan and the check gets its own message (reconnect it or start again).

**What to do now:** if F: is the external disk with your MinIO data, connect it and start again. If the data moved,
set `MINIO_DATA_DIR` to the new folder (or remove the line to use `AETHERIS_BACKUP_DIR/minio`, after copying the data
there). Your `.env` was not changed by this update.

## Dynamic drive detection (unchanged design, one gap closed)
Evidence drives are still detected automatically at every start: any number of letters, only connected ones, each
verified by Docker before it is mounted. Gap: on a machine with no Docker image yet (fresh install or after a
prune) nothing could be verified, so every drive except C: and the project drive was left out (D: in your log)
until a later start. The scan now pulls the small `alpine:3` image once and verifies all drives on the first run;
offline it keeps the old behaviour; `AETHERIS_DRIVE_PROBE_PULL=false` turns the pull off.

## Verification
`tests/start_docker_drive_checks.ps1` (PowerShell): simulated host with only C: and E: and MinIO on F: - the error
names `MINIO_DATA_DIR`; commented examples in `.env` are ignored; a vanished evidence drive is explained; UNC and
relative paths are not drive letters; a connected path passes. Probe image: with a stand-in `docker` and no local
images it pulls `alpine:3` and uses it; offline and opted-out cases keep the old behaviour. Scripts pass the parser.

## Not verified here
On Windows with real drives and Docker Desktop.
