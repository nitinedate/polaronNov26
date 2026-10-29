# Polaron V1.24.0: leave non-evidence ("noise") out of extraction

Nothing is ever deleted from the evidence. The original stays byte-identical (and evidence on the examiner's PC is
mounted read-only). "Removing noise" here means **not reading, extracting, indexing or reporting** files that are
not evidence, and recording every such decision so it can be defended.

## 1. Game libraries are left out automatically (Standard)
Installed game content is often tens or hundreds of GB of publisher files. Standard now skips the install trees of
Steam (`steamapps/common`, `downloading`, `shadercache`, `workshop/content`, `temp`), Epic Games, GOG, EA/Origin,
Riot, Ubisoft and the Xbox app (`XboxGames`). It is decided from the file-system listing (path and size), so for
evidence on the examiner's PC the skipped files are never uploaded.
- **Kept:** saves (`Documents/My Games`, AppData), launcher accounts and logs (Steam `userdata`, `config`,
  Epic launcher logs), and user content hidden inside a game folder: office documents, PDF, mail stores, password
  databases, keys, encrypted containers, `.rar/.7z`, CSV and SQLite files.
- Never in Deep examination. Counted per launcher as `game_library:<launcher>` in the filter statistics.

## 2. Examiner review before extraction
New option **Review folders before extraction** in the evidence panel (on by default for "This computer", where
every byte read is upload). Extraction then pauses after the file system is listed and the automatic noise rules
have run, before any file content is read. The job page shows where the remaining bytes are (folders with sizes and
share of the total, and every file over 1 GB). The examiner unticks what is not evidence (a VM folder, a backup dump,
an ISO) and clicks **Continue extraction**.
- Named artifacts inside an unticked folder are still extracted unless the examiner unticked that exact file:
  registry hives, event logs, scheduled tasks, WMI repository, Windows log files, setupapi (USB history), AppCompat /
  Amcache, SRUM, Prefetch, user hives, browser databases, plus everything the OS scope pack names specifically.
- The decision is logged with who, when, which paths and about how many bytes; counts go into the filter statistics
  (`examiner_excluded_files/bytes`, `examiner_protected_artifacts`, `examiner_excluded_paths`).
- The saved extraction plan is reused on continue, so the file system is not listed (re-read) a second time.
- The pause is never resumed automatically by the pipeline supervisor.

## 3. Known-good files (NIST NSRL) are dropped from the results
The NSRL hash filter existed but **could never fire**: it was only consulted before files are read, when no hash
exists. It is now applied where extraction has computed each file's SHA-256: a byte-identical match against the
reference set is removed from the extraction index, so parsing, OCR, search, RAG and the report never see it. It is
still listed with path, size and hash in `known_good.jsonl.zst` beside the manifest and counted as `known_good_hash`.
- Hash matching needs the whole file, so this cleans results; it does not reduce upload for evidence on a PC.
- Exact matching only (sorted index, no probabilistic filter), so it cannot discard a file by mistake.
- **Setup (optional, once):**
  1. Download the current NSRL RDS (modern, SQLite) from NIST and unpack it into
     `<AETHERIS_BACKUP_DIR>/forensic-data/job-data/known-good/`.
  2. `docker compose exec worker-disk python -m app.services.known_good_cli build /app/data/known-good/<RDS file>.db`
     (builds `nsrl-sha256.hgi`; allow several GB of memory while building).
  3. `docker compose exec worker-disk python -m app.services.known_good_cli status` shows `"active": true`.
  New extractions use it automatically. `FORENSIC_KNOWN_GOOD_ENABLED=false` switches it off; an index built for
  another hash algorithm is ignored with a warning.

## Measured on the test disk (real E01 listing)
928 files, 579 MB. The review showed Users/alice/Videos at 210 MB and Windows/System32 at 352 MB. Leaving out
"Windows" and "Videos" dropped 322 files (545 MB) and kept 204 named artifacts (Prefetch and registry hives).

## Found and fixed while testing
Event logs are only a *broad* claim in the OS scope pack, so the first version of the examiner exclusion would have
dropped `Security.evtx`, `System.evtx` and the PowerShell log when "Windows" was unticked. Well-known artifact
locations are now protected explicitly, with a test per location.

## Verification
`backend/tests/test_noise_review_v1_24.py`: 36 tests (game rule cases, Deep untouched, summary, protected artifacts
with the real scope pack, pause/approve gate, supervisor does not auto-resume, endpoints, real NSRL index build and
match, wrong-algorithm index ignored, CLI, manifest split). Full backend suite compared test by test with V1.20.1
under identical conditions: no test that passed before fails now; 81 new tests pass. Frontend: type-check and
35/35 tests (review panel, default-on review for "This computer").

## Not verified here
A full pipeline run with PostgreSQL and MinIO (the pause/continue path and the per-shard known-good filtering were
tested at function level, not end to end), and a real NSRL RDS file (tested with generated hash lists in the same
formats).
