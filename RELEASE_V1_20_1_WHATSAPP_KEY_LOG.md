# Polaron V1.20.1: the WhatsApp key log reads as one effort with a clear verdict

"adb shell run-as com.whatsapp cat files/key — WhatsApp is not a debuggable build" looked like an error or the final
result. It is neither: run-as is just the first of three methods Polaron tries to get the Crypt14 key, and that line
only means method 1 did not apply. The log now makes the outcome obvious.

## What changed (display only — no behaviour change)
The three key-retrieval attempts are now shown as sub-steps of one labelled step, with a single verdict:
- "Get the WhatsApp key for the Crypt14 backup (no-root methods first, then root)"
  - method 1 of 3 — run-as (no root): not available (WhatsApp is not a debuggable build)
  - method 2 of 3 — adb backup (no root): not available (WhatsApp blocks backup on this version)
  - method 3 of 3 — su (root): not available (this phone is not rooted)
- Verdict when none works: "Could not get the key: this phone is not rooted and the no-root methods do not apply.
  The WhatsApp chats CANNOT be decrypted without the key. This does NOT affect the rest of the malware scan."
- Verdict on success: "Key found via method 2 (adb backup). Chats can be decrypted."

So "not a debuggable build" is no longer mistakable for a failure of the whole scan — the rest of the scan is
unaffected, and the one real blocker (no key without root, on a non-rooted phone) is stated plainly, with the three
ways to get the key still shown in the WhatsApp tab.

## Install
Overlay the patch and run script_docker\start_docker_local.cmd, then read the phone again (collector v1.2.1).
