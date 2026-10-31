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
