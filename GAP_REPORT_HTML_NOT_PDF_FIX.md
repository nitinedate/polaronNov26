# "Gap report still downloads as HTML" — why, and how to fix it for good

## What the filename proves
A download named `gap-assessment-<client>-merged-<N>-jobs.html` is produced by **one line
that exists only in the ORIGINAL code** (`export_merged_gap_report`, old line ~1130):

```python
return build_gap_report_html(ctx, include_cover=True).encode("utf-8"), "text/html",
       f"gap-assessment-{client_slug}-{suffix}.html"
```

The **updated** `backend/app/services/gap_assessment_report.py` has **no `.html` output path at
all** — it renders a PDF with two engines and, if both ever fail, raises a clear error. So if
you are getting an `.html` file, **the updated code is not the code that's running.** This is a
deployment gap, not a code gap.

## Two things that cause "my change didn't take effect"
1. **The Docker image wasn't rebuilt.** The API runs from a baked image, not your edited files.
   Copying files into the repo does nothing until you rebuild:
   ```bash
   docker compose build --no-cache api        # and any worker that renders reports
   docker compose up -d --force-recreate api
   ```
   (Use your actual service name; if a Celery worker generates the merged report, rebuild/restart it too.)
2. **An old container/process is still serving.** After rebuilding, force-recreate so the new
   image is actually running: `docker compose up -d --force-recreate`.

## Confirm in 10 seconds — run the diagnostic IN the API container
`scripts/check_pdf_engine.py` tells you (a) whether the fixed code is live, (b) whether
xhtml2pdf works in that environment, and (c) whether the PyMuPDF fallback works:
```bash
docker compose exec api python /app/scripts/check_pdf_engine.py
# or, on the host that runs it, from the backend dir:
python scripts/check_pdf_engine.py
```
It prints a one-line VERDICT. The common ones:
- *"OLD code is running … Deploy the updated file and REBUILD the image"* → do the rebuild above.
- *"xhtml2pdf is broken here, but the fallback works"* → downloads will be PDF via PyMuPDF
  (lower fidelity); the FAIL line shows the exact import/render error to repair for full fidelity.
- *"Everything is healthy"* → you'll get the full styled PDF.

## Why PDF rendering failed in the first place (the real trigger)
xhtml2pdf was almost certainly failing in your container (missing/broken `xhtml2pdf` or a
drifted `reportlab`), so the old code silently fell back to HTML. Two defenses are now in place:
- `xhtml2pdf` is pinned to the stable line in `backend/requirements.txt`
  (`xhtml2pdf>=0.2.16,<0.3`) so a rebuild can't pull a breaking release.
- `render_gap_pdf` now has the **PyMuPDF fallback**, so even if xhtml2pdf breaks again, downloads
  stay PDF instead of reverting to HTML.

Known-good versions (verified rendering the full report): `xhtml2pdf 0.2.28`, `reportlab 4.4.10`,
`pillow 12.x`, `pymupdf ≥1.24`.

## Bottom line
Deploy the updated `gap_assessment_report.py` **and rebuild the API image**, then run the
diagnostic to confirm. After that the Gap report downloads as PDF; it can no longer come out
as HTML.

---

## Update: the fallback PDF now renders cleanly (no stray bars)
When xhtml2pdf is unavailable, the PyMuPDF fallback previously mis-rendered the
xhtml2pdf-oriented HTML — stray red/gray/multicolour bars over the text — because
PyMuPDF's Story engine repaints a cell's solid `background-color` onto tall rows
elsewhere in the document.

Fix: a dedicated Story-safe builder, `build_fallback_report_html(ctx)` in
`gap_report_template.py`, is now used for the fallback path. It emits only
Story-friendly markup:
- fixed-px `<colgroup>` column widths (percent widths aren't honoured by Story),
- **no solid-background risk cells** — severity is shown with coloured left-border
  bars + coloured bold text (dark, readable variants), which do not bleed,
- its own cover page (so the separate cover merge is skipped on this path).

`render_gap_pdf(..., ctx=ctx)` now receives the context and uses this clean HTML
whenever it falls back to PyMuPDF. Result: even without xhtml2pdf, the Gap report
is a clean, aligned, colourful PDF. The styled xhtml2pdf render remains the
high-fidelity default when the engine is healthy.

---

## Update 2: fallback now matches the full report structure, section-per-page, zero bleed
Addressing the circled artifacts (stray blue line, grey blocks in blank areas) and the
structure/pagination requests:

- **No background-color fills anywhere.** PyMuPDF's Story engine repaints a filled cell's
  colour onto later pages/tall rows (the blue line and grey blocks). The fallback now uses
  **zero** `background-color`: section headings are blue text + a blue underline, table headers
  are bold text, and severity uses coloured left-border bars + coloured bold text. With no fills
  there is nothing to bleed.
- **Each section on its own page.** The fallback renders **one PyMuPDF Story per section**
  (cover, document control, TOC, then sections 1-6) and merges them, so every section starts on
  a fresh page and one section's content can never bleed into another.
- **Full front-matter restored**, matching the styled report: logo cover page → GENERAL SITE
  REPORT + REVISION HISTORY + confidential notice → TABLE OF CONTENTS (with real page numbers,
  computed from the rendered section lengths) → 1. INTRODUCTION … 6. KEY CONTACTS.

New template functions: `build_fallback_sections(ctx)` (one HTML doc per page-group) and
`build_fallback_toc(page_map)`. New renderer `_fitz_fallback_sections_pdf(ctx)` in
`gap_assessment_report.py` renders each section as its own Story, counts pages for the TOC, and
merges. `build_fallback_report_html(ctx)` is kept as a single-document fallback-of-last-resort.

This is still the fallback — the high-fidelity, serif xhtml2pdf report (your attached PDF) remains
the default whenever xhtml2pdf works. Run `scripts/check_pdf_engine.py` in the API container to
see why xhtml2pdf is failing there and restore it for the full-fidelity output.

## Update 3: keep finding tables closed and align fallback pages with the reference PDF
The fallback now paginates one vulnerability finding table per page and renders each summary
chunk as its own bounded Story. This prevents a long description or mitigation row from leaving
an open table border at a page break. Severity-count cells and risk cells use the reference
PDF's severity fills. The fallback contents page now has aligned section numbers, dotted leaders,
right-aligned page numbers, and the gray title/footer bars. Its page numbers are calculated from
the rendered summary and observation page counts. The primary xhtml2pdf path also uses one
finding detail table per page so the two renderers follow the same pagination rule.
