# V73 - WhatsApp multi-path key and backup discovery

## Purpose
Android acquisition layouts differ by Android version, work profile and acquisition/export tool. V73 removes the single-path assumption for WhatsApp key material and encrypted msgstore backups.

## Key discovery priority
Polaron now accepts structurally valid key material from multiple same-acquisition locations and ranks candidates approximately as follows:

1. `data/data/com.whatsapp/files/key`
2. `data/user/0/com.whatsapp/files/key`
3. `data/user/<profile>/com.whatsapp/files/key`
4. `Android/data/com.whatsapp/files/key`
5. other key material below `Android/data/com.whatsapp/`
6. `Android/media/com.whatsapp/` key material when present
7. other `com.whatsapp` app-container key paths
8. `encrypted_backup.key`, `whatsapp.key`, `whatsapp_key.hex`

WhatsApp Business (`com.whatsapp.w4b`) is also supported and remains separate in priority so a consumer WhatsApp backup is not silently paired to a Business key unless the cryptographic validation succeeds.

## Backup discovery
Encrypted `msgstore*.crypt*` files are accepted from any registered evidence path. Common backup locations are preferred for deterministic processing order, including:

- `Android/media/com.whatsapp/WhatsApp/Databases/`
- `WhatsApp/Databases/`
- `Android/data/com.whatsapp/`
- other acquired locations

No candidate is trusted by path alone. All valid key candidates are tried by the existing fail-closed decryption layer and the key that actually authenticates a backup is recorded as the selected source.

## decryption_keys.txt
When no examiner-supplied `WHATSAPP_KEY_HEX` exists, the highest-priority structurally valid acquired key is promoted into:

- `WHATSAPP_KEY_HEX=...`
- `WHATSAPP_KEY_SOURCE_PATH=...`

Every unique binary key material item is still stored with SHA-256 and source path. Duplicate copies of the same key bytes are not duplicated in the manifest; their alternate source paths are recorded as `KEY_DUPLICATE_SOURCE_###`.

## Forensic safeguards
- No brute force or key derivation from ciphertext.
- Original encrypted evidence is never modified.
- Candidate path is not proof of ownership or correctness.
- Successful backup authentication is stronger than path priority and updates the selected key source.
- Secret key bytes are never written to application logs.
