# V70 — Evidence Tree + Existing-Acquisition Decryption Readiness

## Evidence navigation
Mobile Artifacts now has a dedicated **Evidence** workspace organized by source and evidence type rather than one mixed result set. It includes Communications/WhatsApp (chats, deleted chats, images, videos, audio/voice notes, documents), general Media & Files, Email/Attachments, Deleted/Recovered Evidence, Company Information Leakage, and Encryption & Recovery.

WhatsApp image/video/audio/document families have independent backend filters and counts. Package-only inventory also reports these families while inspecting ZIP/PAS/UFD/UFDX evidence, so the tree does not depend on a fully expanded artifact table.

## Decryption readiness
`05_Exports/<run>/decryption_keys.txt` still contains only acquisition-derived or examiner-supplied authorized secret material. V70 adds a presence-only readiness section:

- WHATSAPP_DATABASE_FOUND
- WHATSAPP_WAL_FOUND
- WHATSAPP_ENCRYPTED_BACKUP_FOUND
- WHATSAPP_APP_CONTAINER_FOUND
- WHATSAPP_KEY_FOUND
- IOS_CHATSTORAGE_FOUND
- IOS_CHATSTORAGE_WAL_FOUND
- IOS_APP_CONTAINER_FOUND
- IOS_KEYBAG_MATERIAL_FOUND
- BACKUP_CREDENTIAL_AVAILABLE
- WHATSAPP_DECRYPTION_READY
- REACQUISITION_RECOMMENDED
- MISSING_REQUIREMENTS

The assessment checks the **existing acquisition first**. Android encrypted msgstore evidence is ready when a plaintext DB already exists, or when an encrypted msgstore and authorized WhatsApp key material are both present. iOS is ready when ChatStorage.sqlite is present, or when protected application-container material can be accessed with authorized credential/keybag material.

`REACQUISITION_RECOMMENDED=true` is emitted conservatively only when the current acquisition lacks required protected/private material. No key is invented, brute-forced, or derived from ciphertext.

## Secret handling
The Evidence UI only exposes the **presence and source file** of key material. It does not render raw key bytes. The private TXT sidecar remains mode 0600 where supported and application logs never receive the secret values.
