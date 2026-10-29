# Polaron artifact preview targeted fix (2026-10-21)

Files are relative to the project root. Overlay the backend and frontend directories; rebuild forensic API and frontend. No database migration or evidence processing rerun.

## Problems addressed
- PDF preview endpoint eagerly read and extracted PDF text, followed by a separate authenticated browser byte fetch. The PDF branch now immediately returns the authenticated content URL and metadata, avoiding the first expensive read.
- The frontend's authenticated content fetch had no cancellation/timeout and silently ignored exceptions. It now aborts after 20 seconds and displays a useful error; switching artifacts cancels the previous fetch.
- Fetch helper now accepts an optional AbortSignal.

## Verify
- Select a small PNG: expected inline image (previous behavior preserved).
- Select a PDF: expected a timely preview descriptor followed by a PDF iframe; if original evidence is inaccessible, show a visible error within 20 seconds.
- Select files rapidly: earlier fetch is canceled and must not leak into a later preview.
- Select inaccessible MinIO content: an error is displayed, without incorrectly claiming the evidence is missing from the acquisition.
- Test large and atypical media; originals remain accessible by Download.

## Known limits
This does not guarantee visual renderers for every proprietary/binary evidence type. Unsupported files retain textual metadata or download/open actions. It does not fix server-side MinIO/archive retrieval latency itself; instrument `resolve_artifact_bytes` and `iter_artifact_content` if downloads also stall. The complete TypeScript project build and live Docker/API integration were not run in this environment.
