# V72 - WhatsApp External Decryption + Deleted Chat Recovery

## Objective

V72 extends the V71 authorized mobile-decryption pipeline so supported Android WhatsApp CRYPT12/CRYPT14/CRYPT15 backups can fall back to `wtsexporter` and `wadecrypt` when the native authenticated decoder cannot handle a particular supported variant. After plaintext SQLite is available, normal and deleted/residual chat recovery run against the same derived database.

## Decryption order

1. Polaron native authenticated CRYPT-family decoder.
2. `wtsexporter -a -k <private-temp-key-file> -b <private-temp-backup>` fallback.
3. `wadecrypt <private-temp-key-file> <encrypted> <decrypted>` decryption-only fallback.
4. If every authorized-key attempt fails, preserve the encrypted source and report the blocked reason.

The tools are installed in the backend image with:

- `whatsapp-chat-exporter[android_backup]==0.13.0`
- `wa-crypt-tools==0.1.0`

No brute-force mode is invoked. Secret material is placed in mode-0600 temporary files and is not inserted into log messages.

## Deleted chat recovery after decryption

Each plaintext WhatsApp SQLite now receives all applicable recovery passes:

- explicit deleted/revoked rows -> `database_deleted`
- SQLite freelist/unallocated residuals -> `freelist_candidate`
- matching WAL residuals -> candidate evidence with `residual_source_component=wal`
- matching rollback-journal residuals -> candidate evidence with `residual_source_component=journal`
- modern WhatsApp revoked/deleted table handling
- historical encrypted-backup comparison: a message present in an older decrypted backup but absent from the current allocated DB is copied into the Deleted WhatsApp evidence family as a `fragment` / `historical_backup_diff` candidate

Historical backup difference is intentionally not labeled proven deletion. It records the contradiction `absence_does_not_prove_user_deletion` and remains pending examiner review.

## Evidence preservation

Original encrypted CRYPT files remain unchanged. Successful plaintext is stored as a derived working copy in job storage and, when the local case export directory is available, under:

`05_Exports/<run>/decrypted/whatsapp/<source-id>/...`

Derived records keep the encrypted source path/hash, decrypted hash, decryptor, validation state, and recovery provenance.

## Logs

Examples:

- `DECRYPTING msgstore.db.crypt14`
- `DECRYPTING msgstore.db.crypt14 via wtsexporter`
- `DECRYPTED msgstore.db.crypt14 via wadecrypt`

Key values are never logged.

## Runtime controls

- `WHATSAPP_EXTERNAL_TOOLS_ENABLED=1`
- `WHATSAPP_EXTERNAL_TOOL_TIMEOUT_SEC=300`
- `WHATSAPP_DELETED_RECOVERY_ENABLED=1`

## Validation

V72 focused regression set: 48 passed. Python compileall passed. Central, HTTPS, Android and iOS compose YAML parsed successfully. A broader legacy WhatsApp recovery test group contains tests that require `pycryptodome` and `psycopg2` in the host test interpreter; those dependencies were unavailable in the packaging runner, while the Docker image installs project requirements.
