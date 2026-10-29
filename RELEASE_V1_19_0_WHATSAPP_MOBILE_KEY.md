# Polaron V1.19.0: read WhatsApp on a non-rooted Android phone (Mobile key)

WhatsApp's message database is end-to-end encrypted. Even with the phone in hand, it cannot be read without the
phone's 64-digit backup key — not by Polaron, not by WhatsApp, not by anyone. This release adds the supported,
no-root way to read it: the phone's encrypted backup plus that key.

## Mobile key (WhatsApp) menu
A new menu item under Malware Detection:
- Enter the 64-digit backup key (from the phone owner, with their consent: WhatsApp -> Settings -> Chats ->
  Chat backup -> End-to-end encrypted backup), paste in any format (spaces and a 0x prefix are accepted).
- Upload a .crypt15 backup you already have, or let a connected-phone read copy it for you.
- Optionally save the key to a case. A saved key is sealed with AES-GCM under a per-firm key; it is never shown,
  never returned by the API, and a database dump alone does not reveal it.

## During a connected-phone read (Android)
The collector now also copies WhatsApp's encrypted backup (msgstore.db.crypt15) from shared storage over USB.
No root: the backup lives in shared storage, which USB debugging can read. If the phone has no end-to-end encrypted
backup, this step is skipped and noted in Coverage. (iPhone backups are not covered.)

## WhatsApp viewer
Android scans get a WhatsApp tab:
- Enter the key, or pick one saved to the case, to decrypt the captured backup.
- Browse chats (one-to-one and groups), messages in order with sender and time, and contacts. Read-only: the
  evidence database is opened immutable and never written to.

## How the decryption was verified
Polaron's Crypt15 decryptor (HKDF-SHA256 key derivation, AES-GCM) was checked byte-for-byte against the
open-source reference (ElDavoo/wa-crypt-tools) on a real Crypt15 backup: it reproduces the original database exactly
and rejects a wrong key with a clear message. It uses the cryptography library, now pinned in the malware image.

## What it does NOT do
- It cannot bypass WhatsApp encryption: without the key, nothing can be read.
- No scan findings are raised from message content; the viewer is for an examiner to read.
- Media files are not decrypted in this release (text, chats, contacts only).

## Install
Overlay the patch and run script_docker\start_docker_local.cmd (migration 055; the malware image rebuilds to pin
cryptography). Then Malware Detection -> Mobile key (WhatsApp), or open the WhatsApp tab on an Android scan.
