# Polaron V1.19.2: the WhatsApp key fills the box by itself

You no longer type the 64-digit key. Polaron reads it and shows it, from whatever source is available — above all,
from the phone's root key file.

## Where the key comes from
- **From the phone's root directory (primary).** When you read a rooted Android phone, Polaron pulls the key file
  from /data/data/com.whatsapp/files/key. The 64-digit key lives in that file. On the scan's WhatsApp tab, the box is
  now pre-filled with those 64 digits, read-only, and one click decrypts and opens the chats.
- **From an uploaded key file.** On Mobile key (WhatsApp), choosing a key file reads the 64 digits out of it and fills
  the key box.
- **From a key saved to the case.** Picking a saved key reveals its 64 digits into the box before decrypting.

In every case the full 64 digits are shown in the textbox, as requested.

## Notes
- The key is read from the file's last 32 bytes (that is where WhatsApp stores it) and shown as 64 hex digits.
- Revealing a saved key and reading a key out of a file are both audited, since they expose a key to the examiner.
- Nothing about decryption or storage changed; this only fills the box so the key need not be typed.

## Install
Overlay the patch and run script_docker\start_docker_local.cmd.
