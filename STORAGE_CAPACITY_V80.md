# V80: MinIO storage-full extraction failure

The attached run failed while writing extract-nodes.jsonl.zst for job 60b8461c-6942-4e7b-be58-543234359d10. MinIO returned XMinioStorageFull. The ZIP listing succeeded: 46,731 files from a 91,608,808,684-byte archive. This establishes a storage write refusal, not a corrupt image or successful extraction. No Python stacktrace appears in the supplied log; this release records the actual exception chain for future failures.

Changes: extraction performs a unique one-byte MinIO write probe before enumeration and before plan upload; only its own probe is removed. Worker scratch storage must retain at least 1 GiB or 5% of that filesystem, whichever is larger. A probe establishes current writability; it does not reserve space for the full job or exclude a later capacity failure. Shard/object uploads translate MinIO storage-full and local no-space/quota errors into a typed failure while preserving their original exception chains. Checkpoints and successfully uploaded parts remain intact. Storage failures become failed jobs with actionable messages and a structured job-scoped storage_issue. Successful retry clears this operational blocker. Source limitations remain independently recorded.

Caught extraction exceptions now enter the durable failure-email outbox, including their complete available stacktrace. Disk/mobile Celery tasks request email delivery immediately for failed results; the existing progress dispatcher retries pending delivery. SMTP must be configured for real outbound mail; MailHog alone does not deliver to ndate1976@gmail.com. An unavailable MinIO connection no longer stays permanently cached as unavailable in a worker: initialization retries after 30 seconds.

Routine registered-evidence queueing is logged as info. The ZIP enumeration finish message says 'ZIP member enumeration complete', avoiding a claim that bytes have already been extracted. Authentic errors remain errors.

## Required repair on the deployed Windows machine

Run in PowerShell from the project directory:

```powershell
.\scripts\Test-ForensicStorage.ps1
```

This shows the actual host source of MinIO /data and host drive free space. The source evidence drive E: and the MinIO backing drive can differ. A healthy container or listening S3 port does not establish writable storage.

The supplied common stack already uses a bind-mounted MinIO data directory, configured by MINIO_DATA_DIR (default ./backup/minio). Point it to a sufficiently large drive rather than removing forensic case objects. For a 91.6 GB package, plan capacity for existing cases plus the extracted uncompressed content, derived evidence and operational headroom; the ZIP's compressed size alone cannot give an exact requirement.

To relocate existing MinIO data safely:

1. Stop all product extraction/processing workers using your usual product stop commands. Stop common MinIO with the following command. Keep the existing data directory intact.

```powershell
docker compose -f services/common/docker-compose.yml --project-directory . stop minio
```

2. Copy the complete old MinIO /data directory to a new drive. Include its metadata and hidden files. Set these two paths to the diagnostic's actual source and your chosen destination; they are examples, not auto-detected paths.

```powershell
$oldMinioData = 'E:\polaron-forensic\backup\minio'
$newMinioData = 'F:\forensic-storage\minio'
robocopy $oldMinioData $newMinioData /E /COPY:DAT /DCOPY:DAT /R:2 /W:2
if ($LASTEXITCODE -ge 8) { throw 'Copy failed; keep the original mount and data.' }
```

3. Verify the copy (file inventory and checksums, including metadata) before switching the mount. Set MINIO_DATA_DIR=D:/aetheris/minio in the .env consumed by the common Compose invocation (replace it with the real target), or run script_docker\Set-MinioDataDir.cmd -Path <target> -CopyFrom <old folder>, which copies, verifies and changes only that .env line. Recreate only MinIO using:

```powershell
docker compose -f services/common/docker-compose.yml --project-directory . up -d --force-recreate minio
```

4. Restart the updated Android/Disk/iOS workers. Use Resume on the affected job. The write preflight runs again. Existing checkpoints can resume uploaded shards; this particular run failed before its plan was uploaded, so it must enumerate again. Confirm writable storage, extraction completion and the subsequent stage barriers before generating a report.

Never use docker compose down -v, delete live case objects, or lower MinIO's free-space protection to hide this problem. Leave the old directory intact until the relocated storage and case data have been verified. If your installed stack uses a Docker volume rather than the supplied bind mount, diagnose and migrate that volume instead of copying the example path.

Validation: 121 focused backend regressions passed. Expanded extraction checks: 38 passed and 5 failed; all 5 failures reproduce unchanged on the original uploaded project (outdated capability/filter expectations). The legacy stream-reader test also cannot collect on the original project because _IterFileReader no longer exists. No access to the user's MinIO drive, live SMTP or 91.6 GB evidence ZIP was available. This release includes V78 and V79; a fresh Android production build passed in V79 and no frontend files changed in V80.
