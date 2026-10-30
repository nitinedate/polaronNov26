# WhatsApp (Android) — getting chats when the key is in the root-only sandbox

## The hard constraint (why "just read root" is not possible)
`/data/data/com.whatsapp/files/key` lives inside WhatsApp's app sandbox. Android
lets **only uid 0 (root)** read it. On a **non-rooted, unmodified** device there is
no software trick that reads it — that is the sandbox working as designed. And
**rooting an unrooted phone writes to the device**, so it is not a defensible
forensic action. You cannot both "make no changes to the phone" **and** gain root
on a phone that isn't already rooted. So the key must come from somewhere that does
not modify the handset.

## The forensically sound ways to get the key (no device modification)
1. **Full file-system / physical extraction with a court-accepted tool.**
   Cellebrite UFED + Physical Analyzer, Oxygen Forensic Detective, MSAB XRY/XAMN,
   Magnet GrayKey, or your own TSK pipeline. These use vendor/bootloader/EDL
   acquisition that preserves integrity and produce an image that *contains*
   `files/key` — without leaving the phone rooted. **This is the primary route.**
2. **If the device is ALREADY rooted / forensically rooted** (adbd as uid 0, or a
   working `su`), read the key read-only with `adb exec-out cat` — this is what the
   Polaron pipeline's `whatsapp_key_capture.py` already does. It never escalates.
3. **Crypt15 e2e-backup route** (only if your authority permits touching the phone):
   turn on Settings ▸ Chats ▸ Chat backup ▸ End-to-end encrypted backup; WhatsApp
   shows a **64-digit key** and future backups become `.crypt15`, which need no root.
4. **Old WhatsApp / old Android only:** `adb backup com.whatsapp` (if
   `allowBackup=true`) or `run-as com.whatsapp` (if the build is debuggable). Modern
   Play-Store builds block both. The Polaron collector already tries these first.

Once you have the key by **any** route, you never need to re-read the phone — you
decrypt the `.crypt14/.crypt15` you already captured, offline.

## Decrypt offline with the included tool (no phone, read-only, no modification)
`whatsapp_offline_extract.py` takes evidence you already have and writes a
plaintext `msgstore.db` (+ optional chats.csv/json) with a SHA-256 custody manifest.

```bash
pip install cryptography            # + pip install pytsk3   (only for --from-image)

# A) From a raw ext4/F2FS partition image (read via The Sleuth Kit, no mount/root):
python whatsapp_offline_extract.py --from-image userdata.img --dump-chats -o wa_out
#    whole-disk image? add --fs-offset <bytes-to-the-partition>

# B) From an extracted file-system tree (mounted image / logical pull):
python whatsapp_offline_extract.py --from-dir  ./extraction --dump-chats -o wa_out

# C) From a tar/tgz of the extraction:
python whatsapp_offline_extract.py --from-tar  extraction.tar.gz --dump-chats -o wa_out

# D) Old-WhatsApp adb backup:
python whatsapp_offline_extract.py --from-ab   whatsapp.ab --dump-chats -o wa_out

# E) You already have the pieces:
#    Crypt14 (needs the 158-byte key file):
python whatsapp_offline_extract.py --backup msgstore.db.crypt14 --key-file key --dump-chats
#    Crypt15 (needs the 64-digit key):
python whatsapp_offline_extract.py --backup msgstore.crypt15 --hex-key "AB12 …64 hex…" --dump-chats
```

Crypt14 is decrypted with the `files/key` file (its last 32 bytes are the AES key).
Crypt15 is decrypted with the 64-digit key via HKDF-SHA256. The tool reads only;
it never writes to or contacts the device, and records `device_modified: false`.

## How this maps to the Polaron codebase (already present)
- No-root ladder + read-only key read: `mobile_acquire/whatsapp_device_driver.py`,
  `mobile_acquire/whatsapp_key_capture.py`.
- Crypt12/14/15 decryption: `mobile_forensic/whatsapp_crypt.py`,
  `malware/whatsapp_crypt.py` (this tool mirrors that logic, standalone).
- Key intake (158-byte file, offset 126): `mobile_forensic/key_intake.py`.
This script is for running the decryption directly on the examiner workstation
against an image, independent of the containers.
