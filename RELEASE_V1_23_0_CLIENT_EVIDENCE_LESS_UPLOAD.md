# Polaron V1.23.0: less upload for "This computer" evidence

Reading evidence that stays on the examiner's PC is limited by that PC's upload speed. This release sends fewer bytes
for the same result, and shows on the job card how much was actually read and sent.

## What changed
1. **Small blocks for scattered reads, large runs for sequential reads.** The reader used to fetch 4 MiB for every
   miss, so a 2 KB LNK file or one MFT record cost 4 MiB of upload. Now the unit is 128 KiB: a scattered read fetches
   one block, and while a file is read sequentially each request doubles up to 8 MiB.
2. **Read-ahead only for sustained streaming, and off over the outbound connection.** Prefetching past one artifact
   inside an E01 segment pulled in data of other files (often the Windows files Standard skips).
3. **Empty space and compression (agent 1.2.0).** The agent sends an all-zero block as a marker (nothing on the
   wire) and compresses a block with DEFLATE when samples show it saves at least 10 %. Already-compressed data
   (E01, ZIP/UFDR) is detected by sampling and passed through almost free. Over the office LAN only empty blocks are
   skipped by default (compressing could cost more CPU than it saves at LAN speed).
4. **Job card:** "Read from <PC> so far: X of the Y evidence, Z sent over the network".

Nothing about forensic handling changes: same read-only mount, same tamper check on every block, decoded blocks are
length-checked, and a corrupted compressed block is rejected and fetched again.

## Measured
Real agent (C#, under Mono) over the outbound connection, real pyewf/pytsk3 opening the image through the read-only
mount, every result byte-identical to reading the image locally. Test disk: 1 GiB NTFS laid out like a Windows PC
(300 MB system files, registry hives, event logs, Prefetch, LNK, browser history, 5 MB documents, two 100 MB videos,
about 500 MB empty space). "Before" = previous settings (4 MiB blocks, no encoding) through the same harness.

| Workload | E01 (559 MB): before -> after | Raw .dd (1,074 MB): before -> after |
|---|---|---|
| File system + artifacts | 253 -> 99 MB (2.6x less) | 319 -> 39 MB (8.3x less) |
| Standard (artifacts + user files) | 555 -> 361 MB (1.5x less) | 680 -> 302 MB (2.3x less) |
| Every byte (Deep) | 559 -> 559 MB (no change) | 1,074 -> 567 MB (1.9x less) |

**What this means for a real case**
- E01 is already compressed, so Deep examination of an E01 still reads every byte: 100 GB at 20 Mbit/s is still
  about 11 hours. Only a faster connection, the office network or the drive itself helps there.
- Standard on an E01 sends what Standard needs. On this disk most of that was the two videos. A case dominated by
  large user media gains little; a case dominated by Windows files and artifacts gains a lot.
- Raw images (.dd/.raw/.001) gain the most, because empty space and text compress.
- The test disk is synthetic. Use the job card's "read so far" figure on your own cases for real numbers.

## Found and fixed while measuring
- Read-ahead did nothing after a large run (the next block was already cached), and once fixed it over-fetched
  inside E01 segments (697 MB instead of 361 MB for Standard). Final rule: only for sustained streaming, never by
  default over the outbound connection.
- Compression was decided from the first 16 KiB of a run; runs starting with random data and ending in empty space
  went uncompressed. Four spread samples now decide (raw Deep: 716 -> 567 MB).

## Install
- **Server:** no container changes. New optional settings in `.env.example`: `CLIENT_EVIDENCE_BLOCK_KB` (128),
  `CLIENT_EVIDENCE_MAX_RUN_MB` (8), `CLIENT_EVIDENCE_WIRE_ENCODING` (auto), `CLIENT_EVIDENCE_RELAY_READAHEAD` (0).
- **Examiner PCs:** agent **1.2.0** for empty-space skipping and compression (same installer). Older agents keep
  working without compression.

## Verification
`backend/tests/test_client_evidence_v1_21.py`: 45 tests (6 new: block runs, both encodings, corrupted block retried,
old agents, counters across containers, empty blocks over the outbound connection). Full backend suite compared test
by test with V1.20.1. Frontend: type-check and 34/34 tests.

## Not verified here
A real Windows PC and internet link. Windows' DEFLATE may compress slightly differently from Mono's (the reader
accepts any valid DEFLATE stream), and its CPU cost on the PC was not measured on Windows.
