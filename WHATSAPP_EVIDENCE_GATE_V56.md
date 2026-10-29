# V56 — Platform-aware WhatsApp Evidence Preparation / Decryption Gate

## Purpose

WhatsApp evidence preparation now occurs after mobile platform verification and before native WhatsApp parsing.

### Android

1. Verify Android from registered evidence markers.
2. Inventory `msgstore.db`, `wa.db`, CRYPT-family backups and WhatsApp sidecars.
3. Preserve each encrypted CRYPT source byte-for-byte in the case namespace:
   `mobile/android/encrypted/whatsapp/<source-hash>/<filename>`.
4. Discover only captured/case-intake authorized key candidates.
5. Decrypt supported CRYPT-family sources to derived working copies under:
   `derived/mobile/android/whatsapp_decrypted/<source-id>/<payload-hash>/...`.
6. Register the derived working copies before native parsing.
7. Parse active chats and then run WAL/journal/freelist/deleted recovery against plaintext/decrypted databases.
8. If a matching key is absent, preserve the encrypted source, set `key_required`, and continue the rest of the mobile case.

### iPhone / iOS

1. Verify iOS from `ChatStorage.sqlite`, `Manifest.db`, `Manifest.plist`, iOS filesystem/backup markers, etc.
2. Prefer a readable `ChatStorage.sqlite` produced by the authorized acquisition/import layer.
3. Use the authorized iOS backup password/credential during acquisition/import when the backup is protected.
4. Never apply Android CRYPT heuristics to an iOS case.
5. If protected WhatsApp data is present without authorized credential material, set `credential_required`; do not guess keys.
6. Once `ChatStorage.sqlite` is readable, native parsing and deleted-chat recovery include its WAL/journal/freelist sources.

## Stable case-relative paths

Registered WhatsApp sources are stamped with platform-specific canonical paths while source evidence remains untouched:

- Android plaintext DB: `mobile/android/whatsapp/database/...`
- Android encrypted source: `mobile/android/encrypted/whatsapp/...`
- Android decrypted working copy: `derived/mobile/android/whatsapp_decrypted/...`
- iOS WhatsApp DB: `mobile/ios/whatsapp/database/...`
- iOS decrypted/materialized working root: `derived/mobile/ios/whatsapp_decrypted/...`

Legacy `derived/whatsapp_decrypted/...` working copies remain readable for backward compatibility.

## Pipeline placement

`platform verification -> evidence inventory/key intake -> WhatsApp evidence gate -> refreshed inventory -> native parsers -> deleted recovery -> correlation -> RAG/report`

The serial materialization path and the full mobile analysis path both invoke the same gate.

## Safety / forensic integrity

- Original acquisition bytes are never modified.
- Encrypted originals are hash checked before canonical preservation.
- Decrypted bytes are working copies linked to the encrypted source hash.
- Missing key/credential material is a WhatsApp-specific blocked state, not a reason to stop unrelated evidence processing.
- The system does not fabricate, derive by guessing, or brute-force unsupported keys.

## Validation

Focused V56 suite: 62 tests passed.

A broader pre-existing WhatsApp regression run also produced 79 passes; six additional tests were not executable in the local runner because `pycryptodome/Crypto` and `psycopg2` are absent there. Those were environment/import failures, not V56 assertion failures.
