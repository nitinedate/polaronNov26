# Polaron V1.26.3: MinIO data on D:/aetheris/minio

MinIO keeps the extracted evidence and artifacts of every job. Its location is one setting, `MINIO_DATA_DIR` in
`.env` (Compose: `${MINIO_DATA_DIR:-./backup/minio}`); no code or script hard-codes a drive for it.

## Changed
- `.env` (full project zip): `MINIO_DATA_DIR=D:/aetheris/minio` (was `F:/aetheris/minio`).
- `script_docker/Set-MinioDataDir.cmd` (new): changes only the `MINIO_DATA_DIR` line of your live `.env`
  (default `D:/aetheris/minio`), keeps a timestamped backup, refuses a drive that is not connected, comments out
  any later duplicate that would override it, keeps line endings, and creates the folder. With
  `-CopyFrom <old folder>` (stack stopped) it first copies the existing MinIO data and verifies file count and
  size before changing `.env`; it refuses to copy into a non-empty folder.
- `.env.example` and `STORAGE_CAPACITY_V80.md`: examples now use `D:/aetheris/minio` and mention the script.

## On your server
1. `script_docker\Set-MinioDataDir.cmd`  (sets `MINIO_DATA_DIR=D:/aetheris/minio`)
2. `script_docker\start_docker_local.cmd`

The patch zip never contains `.env` (your secrets and credentials stay as they are); the script makes the change.

**Existing cases:** if `D:\aetheris\minio` is empty, MinIO starts with an empty store and cases already in the
database open without their stored files. When the old data is available (e.g. drive F: reconnected), stop the
stack and run `script_docker\Set-MinioDataDir.cmd -Path D:/aetheris/minio -CopyFrom F:/aetheris/minio`.

## Verification
`tests/start_docker_drive_checks.ps1` (8 checks) and script runs on a Windows-style `.env`: only the setting
changes, a later conflicting duplicate is neutralised, comments and secrets untouched, CRLF kept, backup identical
to the original; disconnected drive refused; copy verified file-for-file; copy into a non-empty folder refused with
`.env` unchanged. Found and fixed during testing: the first version did not find the existing line in a CRLF file.
