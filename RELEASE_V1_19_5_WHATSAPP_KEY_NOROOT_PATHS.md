# Polaron V1.19.5: exhaust every no-root way to get the WhatsApp Crypt14 key

On the reported phone the Crypt14 key could not be read: "no root; Crypt14 key file not available". That message is
correct — the key file at /data/data/com.whatsapp/files/key is inside WhatsApp's private storage, which Android lets
only root read. No software can bypass that sandbox. What this release does is make Polaron try every legitimate
no-root path first, so "root required" is only reported once nothing else can work.

## What the collector now tries, in order (all no-root first)
1. **run-as com.whatsapp** — works if WhatsApp is a debuggable build (rare on Play Store builds, free to try).
2. **adb backup com.whatsapp** — on older WhatsApp/Android the backup archive contains files/key; Polaron unpacks it
   and recovers the key. Modern WhatsApp sets allowBackup=false, so this returns empty and is skipped.
3. **su** under each of its known names (su, /system/xbin/su, Magisk path, ...) — standard root.

Only if all of these fail does Polaron report that root is required — and it now says exactly what to do.

## When none works (end-to-end encryption off, phone not rooted — the reported case)
This cannot be fixed in software. The WhatsApp tab and the warning now spell out the three real options:
- **Turn on WhatsApp's end-to-end encrypted backup** on the phone (Settings > Chats > Chat backup). It gives a
  64-digit key and future backups are Crypt15, which need no root. Simplest, if your authority allows touching the phone.
- **Use a rooted / forensically-rooted device**, then read again — the key is pulled automatically.
- **Obtain the key file another way** and upload it on Mobile key (WhatsApp) to decrypt the capture you already have.

The encrypted backup is captured either way, so once you get the key by any route you do not need to re-read the phone.

## Install
Overlay the patch and run script_docker\start_docker_local.cmd, then read the phone again (collector v1.2.0).
