# Polaron V1.19.3: a dropped USB connection no longer ruins the read

In the reported read, the phone disconnected partway through copying app packages. adb then reported
"device 'RZ8N21N3AXX' not found" and "device offline" for every remaining command — about 60 of them — and the read
ended with a misleading "no WhatsApp backup found", even though the phone simply wasn't reachable by then.

## Fixed
- **Disconnects are detected and the read stops cleanly.** When adb reports the phone is not found / offline,
  Polaron waits briefly for it to come back (short USB blips are common and now recover on their own). If it stays
  gone, the read stops instead of firing dozens of doomed commands.
- **A partial capture is KEPT, not discarded.** Previously any error deleted the whole bundle. Now a disconnect
  keeps everything collected before it — device posture, logs, and WhatsApp — and marks the capture partial. The
  scan runs on it, and its Coverage tab says the read was incomplete and to reconnect and read again.
- **WhatsApp is copied first.** The encrypted backup (and the root key file) are now pulled before the large,
  low-priority app packages, so a disconnect during app copying does not cost the chat evidence.
- **No more false "no WhatsApp backup".** If the backup check could not run because the phone was offline, that is
  reported as a disconnect, not as "no backup".
- Collector v1.1.0; the host helper carries it. Re-read the phone with this build for the new behaviour.

## For the reported phone
Reconnect it (a different cable/port helps if it keeps dropping), keep it unlocked, and read it again. WhatsApp and
device posture are captured early now, so even if it drops again later you keep the important evidence.
