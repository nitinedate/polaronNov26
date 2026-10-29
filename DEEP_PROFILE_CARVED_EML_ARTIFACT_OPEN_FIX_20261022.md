# Deep examination honoured · carved EML parsed · artifacts open (parsers + index) — 2026-10-22

Base: `polaron.zip` of 2026-10-22. Source patch plus one idempotent SQL migration
(`045`, creates two tables and re-asserts indexes). No evidence, MinIO object or
extracted shard is modified. No re-extraction is needed for the preview fixes.

## 1. Deep examination ran as Standard (Images 1–2)

**Root cause: a stale React closure.**

- In `HostEvidencePanel.tsx`, `confirmStagedBrowseFolders` is `useCallback(..., [])`.
- The Browse-drives dialog therefore always called the *first-render* `registerPickedFolder` → `ingestAtResolvedPath`.
- That function captured `processingProfile` while it was still the initial `"standard"`.
- Selecting Deep examination changed the radio, but the ingest request still sent `processing_profile: "standard"`.
- The backend froze that value into `jobs.disk_source`, and every stage then honoured Standard. The graph card shows this: "Not run: Standard profile …".
- `resolveFolderFromFilenames` had the same missing dependency.

Two backend details made it worse:

- `IngestPathBody.processing_profile` defaulted to `"standard"`, so any call that omitted it overwrote a stored choice.
- The radio always reset to Standard after a reload.

**Fix**

- Frontend:
  - All ingest payloads read `processingProfileRef.current`, which always holds the current choice.
  - The dialog calls the latest `registerPickedFolder` through a ref.
  - Changing the radio saves it immediately via `PUT /api/jobs/{id}/processing-profile`. A failed save reverts the radio and shows the error.
  - The radio is initialised from the job's stored profile.
  - Once extraction has started, the radio is locked and says so.
- Backend:
  - `processing_profile` now defaults to `None`, meaning "keep the stored profile". If nothing is stored, the default is Standard.
  - A new GET/PUT `/jobs/{id}/processing-profile` endpoint, with an atomic `jsonb_set`. It returns 409 once any file has been extracted.
  - The chosen mode is written to the job's extraction log for audit, for example `Examination mode: Deep examination (processing_profile=deep, from examiner selection)`.

**The case in Image 1 was extracted with the Standard scope.** Its extraction mode, media scope and skipped stages cannot be upgraded in place. Create a new job on the same evidence folder, choose Deep examination, then select the folder. The log line above confirms the mode before extraction starts.

## 2. Carved EML showed binary (Image 3)

**Root cause: the earlier fix patched the wrong code path, and the carver over-detects.**

- `Carved EML @ pagefile.sys:<offset>` rows are virtual `carve-*` items.
- They are rendered by `carved_artifact_content.build_carved_preview()`, not by `artifact_preview._apply_email_preview()`, which is where the 2026-10-21 readability check was added.
- Python's MIME parser accepts almost any bytes, so `parse_ok` was true and the raw bytes became the "Plain text" body. The subject fell back to the file name, exactly as in Image 3. This symptom was reproduced on the original code in the tests.
- The carver accepted `From: ` if `to:` appeared anywhere in the next 2 KiB. That matches `proto:`, `photo:` and JSON in Outlook/OWA memory.
- Both the `From: ` and `\nFrom: ` signatures fired on the same header, producing the off-by-one pairs (…912/…911, …674/…673).

**Fix**

- New `parsers/rfc822_validate.py`: strict RFC 5322 header-block validation.
  - Every line must be a header field or a folded continuation.
  - The block must end with an empty line.
  - It needs at least 3 known headers, including an originator header and an identity header.
  - Header values may not contain control bytes.
- Carver changes:
  - The hit must be at a line start.
  - The carver walks back to the start of the header block, validates it, and keeps one hit per block start.
  - New hits carry `rfc822_validated: true`.
  - Inventories built earlier are de-duplicated when listed (`dedupe_adjacent_eml_hits`).
- Carved preview behaviour:
  - A **valid message** shows parsed headers, body and attachments.
  - **Valid headers with a binary body** shows the headers plus a fragment view of the body region (`carved_partial`).
  - **Anything else** is labelled as not an email and shown as a **fragment view** (`carved_unparsed`).
- New `parsers/binary_fragment.py` builds the fragment view. It never decodes binary as a text body. It shows:
  - ASCII and UTF‑16LE strings with absolute source offsets (equivalent to `strings -t d` / `strings -el`);
  - indicators: e‑mail addresses, URLs, Windows paths and JSON keys;
  - entropy and a classification;
  - an offset-labelled hex dump.
- The same fragment view replaces byte dumps for real `job_artifacts` emails that turn out to be unreadable.

## 3. Artifacts that did not open → parsers

| Artifact | Before | Now |
|---|---|---|
| Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve), EVTX, Prefetch, LNK, Jump Lists, SetupAPI, `$I` recycle records | "Opaque binary — download it" | Paged **parsed-records table** from the stage‑5 results (no evidence read). If nothing is stored, the registered parser runs once, stores its result like stage 5, and later opens read it from the database. A parse with no records shows the fragment view. |
| PST/OST | Placeholder text | Stored PST inventory records, when present. They are never parsed inline because these files can be gigabytes. |
| Outlook `.msg` | Always failed: `extract_msg` is **not** in `requirements.txt` | New `parsers/mapi_msg_ole.py` reads MS‑OXMSG with `olefile`, which is already a dependency. It returns sender, recipients (To/Cc/Bcc from recipient storages), subject, date, body, HTML body, transport headers and attachments. Attachment download works too. `extract_msg` is still preferred when installed. |
| Emails, images, documents with no MinIO copy | Summary text only, to avoid a shard scan | Read from the original evidence (see §4), then previewed normally |
| Any other binary | Download hint | Download hint plus the fragment view |

There is a new endpoint, `GET /api/jobs/{id}/artifacts/{aid}/records?offset&limit`, used by the table's "Load more". Paging happens inside PostgreSQL: `jsonb_array_elements … WITH ORDINALITY OFFSET/LIMIT`.

## 4. Faster opening (indexes)

**Before:** each click on a file without its own MinIO copy did two expensive things.

- It downloaded and decompressed the **whole extraction index**.
- It then decompressed a single-frame zstd tar shard **from byte 0** until the file was reached, which can be many GB.

**Now:**

- **`job_artifact_locations (job_id, path) PRIMARY KEY`** maps each path to its shard with one index lookup.
  - It is built once per job on first open. It is single-flight per job and protected by a PostgreSQL advisory lock.
  - It is fingerprinted on the shard set and rebuilt automatically after re-extraction.
- **Original evidence is read first for API opens** (`ARTIFACT_READ_SOURCE_FIRST=1`, the default).
  - TSK reads the file from the mounted, read-only E01 or raw image, so the cost is the file size.
  - Bytes are accepted only if the size and the recorded SHA‑256 match. On a mismatch the extracted copy is used and a warning is logged.
  - Deleted entries without a recorded hash are never read by path, because the name may now point at another inode.
  - Background workers keep reading shards first, so they do not compete for the evidence image.
- The shard, located through the index, is the fallback. The old whole-index reader is used only if the location index cannot be built.
- The existing copy to MinIO on first open (≤ 50 MB) keeps later opens fast.
- Migration `045_artifact_open_performance.sql` creates the two tables in every firm schema and re-asserts the preview hot-path indexes:
  - `artifact_parse_results(job_artifact_id, created_at DESC)`;
  - the path and name indexes;
  - a partial index for artifacts with no MinIO object.
  
  The earlier index migrations (037/039/043) were optional, and `apply_migrations.*` stopped at 037. It now includes 045.

## 5. Files

- New (backend):
  - `app/parsers/rfc822_validate.py`
  - `app/parsers/binary_fragment.py`
  - `app/parsers/mapi_msg_ole.py`
  - `app/services/artifact_parsed_view.py`
  - `app/services/artifact_locator.py`
- Modified (backend):
  - `app/services/artifact_preview.py`
  - `app/services/carved_artifact_content.py`
  - `app/services/signature_carve_inventory.py`
  - `app/services/processing_profile.py`
  - `app/parsers/outlook_msg_parser.py`
  - `app/routers/jobs.py`
  - `app/routers/artifacts.py`
  - `app/schemas/forensic.py`
- Frontend:
  - `components/forensic/HostEvidencePanel.tsx`
  - `components/forensic/ArtifactPreviewPanel.tsx` (new `ParsedRecordsView` and `FragmentView`)
  - `lib/forensicApi.ts`
  - `lib/types/forensic.ts`
  - `pages/forensic/JobDetailPage.tsx`
- SQL and scripts:
  - `migrations/045_artifact_open_performance.sql`
  - `scripts/apply_migrations.sh`
  - `scripts/apply_migrations.ps1`
- Tests:
  - `backend/tests/test_artifact_open_parsers_20261022.py` (38 tests)
  - `tests/test_processing_profile_selection_20261022.py` (12 tests)

## 6. Verification performed

See `DEEP_PROFILE_CARVED_EML_TEST_RESULTS_20261022.txt`. In summary:

- **New tests: 50/50 pass on the modified tree.**
  - Against the original code, all 12 profile tests fail.
  - The 5 carved-EML/carver tests and the 4 read-order tests also fail on the original code.
  - The original code reproduces Image 3: subject equals the file name and the body contains U+FFFD.
- Frontend:
  - `tsc -b` (strict) passes.
  - Errors injected into both edited components were detected, then reverted.
  - The `vite build --mode forensic` production bundle builds.
- **Full regression:** the backend and root suites were run on the original and the modified tree in the same environment. Results are in the results file.

**Not verified here:**

- a real E01 run;
- the TSK source read against a mounted image (it was tested with a stubbed image reader);
- live PostgreSQL execution of the new SQL (the records-page SQL and the location-index DDL/insert are not run against a database here);
- a real `.msg` file (the reader was tested on a synthetic MS‑OXMSG structure);
- browser rendering of the new views;
- performance figures. No timing improvement is claimed as measured. Compare the open time of a late-shard artifact before and after on your case.

## 7. Deploy

1. Back up `.env`, the PostgreSQL database and the MinIO volume metadata.
2. Apply the migration:
   ```powershell
   docker compose exec -T postgres psql -U forensic -d forensic -v ON_ERROR_STOP=1 -f /migrations/045_artifact_open_performance.sql
   ```
   (or `.\scripts\apply_migrations.ps1`). The API also creates the two tables on first use.
3. Rebuild and recreate, without removing any volumes:
   ```powershell
   docker compose build --no-cache api frontend
   docker compose up -d --no-build --force-recreate api frontend worker-disk worker-parse worker-report worker-agent
   ```
4. For the case in Image 1, create a new job and choose **Deep examination** before **Browse drives**. Check the log line `Examination mode: Deep examination`.
5. EML(X) counts from carve inventories built before this fix still include the false hits until the signature-carve inventory is rebuilt (reprocess inventory). The list itself already hides the off-by-one twins, and every false hit now opens as a fragment, not as an email.

## 8. Switches and rollback

- `ARTIFACT_READ_SOURCE_FIRST=0`: read the shard first, as before (the location index is still used).
- `ARTIFACT_ONDEMAND_PARSE_MAX_BYTES` (default 256 MiB): the size limit for an on-demand parse on open.
- Rollback: restore the previous files and rebuild. The two new tables can stay; nothing else reads them.
