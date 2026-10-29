# Android WhatsApp key capture (root-present, read-only) — 2026-10-21

Base: `polaron.zip` (2026-10-21), on top of the cumulative change set. Source
patch only; no migration, no evidence/MinIO change. Android only.

## 1. What this does and does NOT do

**Does:** when root is **already present** on the device (adbd runs as uid 0, or
`su -c id` returns uid 0), capture WhatsApp's private key file
(`/data/data/com.whatsapp/files/key`, and `encrypted_backup.key` if present) and,
optionally, the live `msgstore.db` — all **read-only** via `adb exec-out cat` —
and stage them where the decryption ladder and the case gate look. The crypt14
backups you already have then decrypt into chats using the device's own key.

**Does NOT:** gain root. It never runs an exploit, changes the boot image,
`/system` or the data partition, or escalates in any way. Rooting an unrooted
phone writes to the device and is not a defensible forensic action, so it is out
of scope by design. On a non-rooted device the capture records a precise,
actionable coverage gap and stops — it does not modify the evidence.

This matches the earlier read-only ladder: keys are the device's own, never
generated; the device is only modified by the separate, double-authorized
crypt15-backup last resort.

## 2. Why it was needed (your case)

A logical ADB pull reached `/sdcard/Android/media/com.whatsapp/...` (public
storage) but not `/data/data/com.whatsapp/files/key` (the app sandbox). The
captured tree had `msgstore.db.crypt14` under `WhatsApp/Databases` but no
`files/key`, so the crypt14 chat backups could not be decrypted (crypt14 needs the
158-byte `files/key`, not the 64-digit key). This step captures that key whenever
the device already grants root, closing the gap without touching the device.

## 3. How it works

New module `whatsapp_key_capture.py`:
1. `confirm_device()` — device reachable/authorized.
2. `root_mode()` — proceed only if root already exists; otherwise record the gap.
3. Read each key path read-only with `exec-out cat`; validate the size (32–1024 B);
   reject acquisition error text mistaken for a key.
4. Stage each key under `<out>/whatsapp_decrypt_agent/live_private/<source>/key`
   (canonical basename, so the ladder's `rglob("key")` finds it) and mirror to
   `<out>/private_apps/com.whatsapp/files/key` for the materializer.
5. Optionally capture the live `msgstore.db` (already plaintext).
6. Write `whatsapp_key_capture_log.json` and feed all files/gaps to the outcome.

Wired into `AndroidAdbAdapter.acquire()` on **File System / Full File System**
(the methods that already have the privilege), before the WhatsApp decrypt agent
runs — so the agent immediately uses the captured key. An error here never fails
the acquisition.

## 4. Complete logs

Every step is logged three ways, with **no raw key bytes anywhere**:
- Python logger `mobile_acquire.whatsapp_key_capture` (structured line per action:
  `start`, `adb_devices`, `root_check` [`escalation_attempted: false`],
  `read_attempt` [command + target], `read_result` [ok, size, sha256], `done`).
- `result.audit` — the same entries, persisted to
  `whatsapp_decrypt_agent/whatsapp_key_capture_log.json`.
- `result.custody` — chain-of-custody links (who/what/when/where) for each captured
  file, e.g. "Captured WhatsApp key /data/data/com.whatsapp/files/key read-only via
  su (158 bytes, sha256=…)". Keys are identified by length + SHA-256 only.

## 5. Which microservice runs it

ADB/USB is not available inside Docker, so Android acquisition — and therefore this
capture — runs in the **host drive helper** (`scripts/host-drive-helper.ps1`,
port 9876) on the examiner's Windows PC, which executes `AndroidAdbAdapter`
in-process (see `host_bridge.host_run_acquire`). The **`api`** container only
brokers `/api/acquisition/start` and records results; the **`worker-*`** containers
(disk/parse/quality/rag/ocr/report/agent/progress/beat) run the downstream
pipeline and never touch the phone. No host-helper change is needed — the capture
is reached automatically inside the existing acquisition call.

## 6. Verification

`backend/tests/test_whatsapp_key_capture.py` (6):
- captures and stages the key where the ladder looks (+ private-apps mirror);
- **end-to-end**: staged key decrypts a real crypt14 backup into a chat DB
  (rung `existing_backup_plus_extracted_device_key`);
- no root → records the gap, attempts **zero** private reads, no escalation;
- implausible key size rejected; device-unreachable clean skip;
- logs are complete (command/target/size/sha256/outcome) and contain no raw key
  bytes.

Adapter/agent/acceptance suites still pass (25). Full backend + root suites, clean
upload vs modified tree: no test that passes on the original fails on the modified
tree.

**Not verified here:** a real rooted Android phone, live `adb exec-out`, a real
`files/key`/`msgstore.db` read. Behaviour is covered by the fakes and a real
crypt14 round-trip.

## 7. Deploy

Backend rebuild; workers reuse the `api` image. No host-helper change required.
```
docker compose build --no-cache api
docker compose up -d --no-build --force-recreate api worker-disk worker-parse worker-agent
```
Update `tools/platform-tools` ADB on the examiner PC as usual; the capture uses the
same `adb` the adapter already uses.
