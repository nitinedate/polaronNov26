# Artifact browser fixes — carved-EML binary preview & infinite scroll — 2026-10-21

Base: `polaron.zip` (2026-10-21), on top of the cumulative change set. Source
patch only; no migration, no evidence/MinIO change.

## 1. Carved EML shows raw binary in the Plain text pane (Image 1)

**Symptom.** Opening a `Carved EML @ pagefile.sys:<offset>` showed mojibake
(``, CJK-looking glyphs) in the Plain text and Raw source panes.

**Cause.** Carved EMLs are recovered by a signature scan of unallocated space /
the page file. The surrounding bytes are arbitrary binary that merely begins with
an EML-like header. In `artifact_preview._apply_email_preview`, two paths dumped
those bytes as a text body: the parse-failure fallback decoded the raw RFC bytes
and set them as `body_text`, and the parse-success path trusted
`details["body_text"]` even when the "parsed" body was binary. `_decode_text`'s
latin-1 guard did not catch this because random bytes decode to *printable*
latin-1 glyphs (ratio > 0.85), so the mojibake passed.

**Fix.** A stricter readability gate, `_looks_like_readable_email()`, requires the
decoded body to be overwhelmingly ASCII (≥ 90%), almost free of stray control
bytes (≤ 2%), substantially letters/whitespace (≥ 55%), and free of the Unicode
replacement char. Verified: 0 false positives over 200 random carved blobs; real
and short genuine emails still pass. When a carved/undecodable fragment is
detected (on either the fallback or the parse-success path), the agent does **not**
dump bytes — it mounts the email shell with an honest notice ("recovered by
signature carving … no readable message body; use Raw source / Download") and sets
`carved_unparsed: true`. A real RFC822 message that merely tripped the strict
parser still shows its readable body. The frontend shows a small amber "carved
fragment — not a decodable email" note above the body tabs.

Files: `backend/app/services/artifact_preview.py`,
`frontend/src/components/forensic/ArtifactPreviewPanel.tsx`,
`frontend/src/lib/types/forensic.ts`.

## 2. Middle artifact list stops loading on scroll (Image 2, all categories)

**Symptom.** The artifact list (e.g. Picture · 11,930, or All artifacts · 57,892)
loaded a few pages on scroll, then stopped before the end, with the "scroll for
more" footer still showing.

**Cause.** `useInfiniteArtifactPage` gated "load more" on
`hasMore = items.length < total`. But the server reports `total` as a raw
`COUNT(*)` and then drops rows *after* counting — runtime-junk stripping,
file-type filtering, client-side group filtering, and de-duplication of carved
artifacts that can share an id across pages. So a page returns fewer new rows than
the page size, and eventually a page adds nothing new. `items.length` then stops
rising while `total` stays high, so `hasMore` stayed true forever but nothing
advanced it — the list froze with no way to recover.

**Fix.** The hook now stops only when the **server** is exhausted: a page that
returns fewer rows than `ARTIFACT_PAGE_SIZE` means there is nothing after it, and
a bounded run (5) of full pages that add no new rows (all-duplicate/all-filtered
tails) also ends paging. `hasMore` is driven by a proven `reachedEnd` flag rather
than a count comparison, so partially-filtered full pages keep loading to the real
end, and a transient fetch error does not permanently stop scrolling. The server's
`total` is still shown as the headline count.

File: `frontend/src/components/forensic/useInfiniteArtifactPage.ts`.

## 3. Verification

- `backend/tests/test_email_preview.py` (+4 carved cases): readable-email gate
  (0/200 false positives), carved binary not dumped (notice + `carved_unparsed`,
  no replacement chars), genuine-but-unparsed email keeps its body.
- `tests/test_infinite_scroll_pagination.py` (6): the brittle guard is gone;
  stops on short/empty page; recovers from transient error; and a Python mirror of
  the append logic proves it stops at a short page, stops on an all-duplicate tail,
  and continues through partially-filtered full pages. These fail against the
  original hook.
- Frontend `tsc -b` (strict): pass.
- Full backend + root suites, clean upload vs modified tree: no test that passes
  on the original fails on the modified tree.

**Not verified here:** a live browser scroll against a real 57k-artifact job, and a
real carved EML from an actual pagefile image. Logic and byte-level behaviour are
covered by the tests above.

## 4. Deploy

Frontend + backend rebuild (the backend change is the preview builder used by the
API). Backend workers reuse the `api` image:

```
docker compose build --no-cache api frontend
docker compose up -d --no-build --force-recreate api frontend worker-report worker-parse
```
