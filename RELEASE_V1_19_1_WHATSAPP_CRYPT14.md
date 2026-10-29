# Polaron V1.19.1: WhatsApp Crypt14 (end-to-end backup off) and the root-only key

V1.19.0 handled only Crypt15 (end-to-end encrypted backups), which need a 64-digit key. Real phones often have
end-to-end encryption OFF, so the backups are **Crypt14** (your screenshot: msgstore.db.crypt14). Crypt14 cannot be
read with a 64-digit key; it needs the phone's **key file** at /data/data/com.whatsapp/files/key, which Android
protects and is readable only with **root**. This release handles that, without ever changing the phone.

## What changed
- **Both formats are recognised.** The decryptor now reads Crypt14 and Crypt15, picking the right key and IV for
  each (Crypt14 reads the IV by its protobuf field number, so it is not confused by the google-id field beside it).
  Verified byte-for-byte against the reference tool on real Crypt14 and Crypt15 backups.
- **The right backup is picked** from the phone: the current msgstore.db.crypt15/14 over dated and increment files,
  Crypt15 over Crypt14.
- **The Crypt14 key file is pulled with root.** During a connected-phone read, if the device is rooted (su is
  present), Polaron copies /data/data/com.whatsapp/files/key over USB and keeps it in the capture. Reading is still
  read-only: it only reads that file. If root is not available, this is stated plainly and the backup is still
  captured, so it can be decrypted later if the key file is obtained another way.
- **WhatsApp tab (Android scan):**
  - Crypt14 with the key file captured -> one click, no key to enter.
  - Crypt14 with no key file -> explains that root is required and why.
  - Crypt15 -> enter the 64-digit key or pick one saved to the case (as before).
- **Mobile key page** now takes a .crypt14 or .crypt15 backup, with a key-file field for Crypt14.

## The hard limit (unchanged, and unavoidable)
A Crypt14 backup cannot be read without the phone's key file, and that file is root-only. This is Android's app
sandbox; no software can bypass it. Polaron pulls the key file when root is available and tells you clearly when it
is not. Nothing is written to the phone in either case.

## Install
Overlay the patch and run script_docker\start_docker_local.cmd, then open the WhatsApp tab on an Android scan, or
Malware Detection -> Mobile key (WhatsApp).
