# Android WhatsApp decrypt agent — 2026-10-21

Base: `polaron.zip` (2026-10-21), on top of the Standard/Deep + inventory change set.
Source patch only; no database migration, no evidence/MinIO change. Android only.

## 1. What it does

A new acquisition-time agent implements the Monolith Forensics "Android WhatsApp
Data Extraction Process" and hands the result to the project's existing
fail-closed WhatsApp decryptor, producing a plaintext `msgstore.db` during the
Android ADB acquisition. It runs automatically at the end of every completing
Android acquisition (Logical, Advanced Logical, Backup, File System, Full File
System, Physical) and writes everything under
`<acquisition>/whatsapp_decrypt_agent/`.

PDF steps, mapped:

| PDF step | Agent behaviour |
|---|---|
| 1-3 (power on, connect, `adb devices`) | `confirm_device()` — device must be present and authorized. |
| 4-5 (`adb pull /sdcard/Android/media/com.whatsapp`) | `pull_public_tree()` — read-only preservation of the public WhatsApp tree (consumer + Business). |
| 6-15 (generate 64-digit key, create E2E backup **on the device**) | **Opt-in only.** See §2. |
| 16-17 (re-pull, locate `msgstore.db.crypt15`) | Re-pull after an authorized backup; discover `msgstore*.crypt*` in the acquired tree. |
| 18-20 (`wacreatekey` / `wadecrypt` → `msgstore.db`) | `decrypt_with_candidates()` from the existing `whatsapp_crypt` module, using keys already collected/entered. Writes `decrypted/msgstore.db` with source/derived SHA-256. |

The agent never embeds `wa-crypt-tools`; the project already has an authenticated,
tested crypt5-15 decoder. No key is brute-forced or derived from ciphertext.

## 2. Forensic boundary — enforced read-only ladder

The platform acquires **read-only** (it seals originals and never writes to the
device). PDF steps 6-15 *write to the evidence device*. The agent therefore tries
a read-only decryption **ladder first**, and only falls back to the device-writing
step as an explicit, double-gated last resort.

Read-only ladder (in order; every key already exists — none is generated):

1. `existing_backup_plus_supplied_64digit_key` — an existing `.crypt15` backup in
   public storage + the 64-digit key the examiner already holds.
2. `existing_backup_plus_extracted_device_key` — an existing `.crypt12/.crypt14`
   backup + the device's own `files/key`, captured by a rooted / full-file-system
   extraction. The device's own key, not a generated one.
3. `live_private_db_via_existing_root` — the live `/data/data/com.whatsapp/
   databases/msgstore.db` read directly **only when root is already present**. The
   agent never roots, unlocks or escalates; it reads what existing access permits.
4. `already_plaintext_sqlite` — a plaintext `msgstore.db` already on disk (from an
   FFS/physical image).

Each rung and its outcome (decrypted / blocked + reason) is recorded in
`result.ladder` and the manifest. When no rung yields a database, the agent emits
a precise, no-touch gap naming what is missing — never a device write.

**Why you cannot "make the 64-digit key on the laptop" for an existing backup.**
A crypt15 backup is `AES-GCM(plaintext, HKDF(root_key))` where `root_key` is 32
**random** bytes generated on the device *before* encryption. It is an input, not
something derivable from the ciphertext, and AES-GCM authenticates it — a key made
on the laptop produces different bytes and is rejected. This is verified in tests:
crypt15 encrypted with a device root key is **blocked** when only `files/key` is
available, while crypt12/14 (which *do* use `files/key`) decrypt from the extracted
key. So rung 2 works precisely because it uses the device's real key, and rung 1
requires the real 64-digit key; neither generates anything.

Device-modifying last resort (PDF steps 6-15), runs only when **all** hold:
* the read-only ladder produced nothing, **and**
* the request carries **both** `whatsapp_generate_key_and_backup` **and** the
  independent `allow_device_modification` override (two separate checkboxes;
  authorizing the first alone fails closed and stays read-only), **and**
* the examiner supplies the 64-digit key.

Even then the agent does **not** fake the WhatsApp UI taps — there is no
reproducible public API for those screens across versions. It foregrounds the
backup settings, records the exact manual steps and before/after device state to
the chain of custody, and decrypts the freshly created backup through the same
ladder. `result.read_only` is `true` for every non-modifying run.

## 3. Files

New: `backend/app/services/mobile_acquire/whatsapp_device_driver.py`,
`backend/app/services/mobile_acquire/whatsapp_decrypt_agent.py`,
`backend/tests/test_whatsapp_decrypt_agent.py`,
`backend/tests/test_android_adapter_decrypt_agent.py`,
`tests/test_android_whatsapp_decrypt_ui.py`, this file.

Modified: `backend/app/services/mobile_acquire/adapters/android_adb.py` (runs the
agent at the end of `acquire()`; new optional kwargs),
`backend/app/services/mobile_acquire/orchestrator.py` (`AcquisitionRequest` gains
`authorized_actions`, `whatsapp_64_digit_key`, `intake_key_candidates`; passes
them to the real android adapter only, guarded by signature),
`backend/app/routers/acquisition.py` (`/acquisition/start` accepts the new fields;
pulls any Intake WhatsApp key for the case),
`scripts/host-drive-helper.ps1` (forwards the new fields into the host-launched
request), `frontend/src/pages/forensic/MobileAcquisitionPage.tsx` +
`frontend/src/lib/types/forensic.ts` (Android-only WhatsApp decryption block and
payload fields).

## 4. Data flow

1. `/acquisition/start` (or the host helper) builds `AcquisitionRequest` with the
   examiner's authorization + key + any Intake key for the case.
2. The orchestrator runs the normal method; the android adapter finishes its
   collection, then calls the decrypt agent.
3. The agent pulls the public WhatsApp tree and key (read-only), optionally drives
   the authorized on-device backup, discovers `msgstore*.crypt*`, and decrypts
   with collected/entered keys → `decrypted/msgstore.db` + a per-run manifest
   (no raw key bytes).
4. All produced files are registered on the acquisition outcome. The pulled
   `.crypt15`/`.crypt14` is also registered as case evidence, so the existing
   materialization WhatsApp gate re-decrypts it into the pipeline (cached by
   source hash — no double work). An agent error never fails the acquisition.

## 5. Verification

- 17 new focused tests pass: a real crypt15 round-trip to a valid `msgstore.db`
  (read-only pull + decrypt with an Intake key and with a device key file);
  blocked-without-matching-key (never invented); no-device / not-installed clean
  skips; device-modifying path requires authorization; authorized path records
  custody + manual steps and decrypts the freshly created backup; manifest has no
  raw key bytes; adapter runs the agent on every completing method and never fails
  the acquisition on an agent error; orchestrator signature-guard; frontend
  Android-gated controls and payload wiring.
- Full backend + root suites on the clean upload vs the modified tree (same env):
  no test that passes on the original fails on the modified tree.
- Frontend `tsc -b` (strict) passes. The host-helper `/acquisition/run` Python
  snippet was extracted and parsed to confirm the forwarded fields are valid.

**Not verified here:** a connected Android phone, live ADB, real WhatsApp backup
creation/decryption, GPU/Neo4j/MinIO, native Windows host execution. On-device
backup creation and the matching key must be validated on the target device.

## 6. Deploy

Backend + frontend rebuild (Android product). Backend workers reuse the `api`
image (V77):

```powershell
docker compose build --no-cache api frontend
docker compose up -d --no-build --force-recreate api frontend worker-disk worker-parse worker-quality worker-rag-gpu worker-ocr-gpu worker-report worker-agent worker-progress worker-beat worker-rag-prep
```

Update `scripts/host-drive-helper.ps1` on the Windows acquisition host (restart the
helper) so host-run Android acquisitions forward the new fields. Keep all evidence
and database volumes. No migration.
