# Forensic taxonomy counts and selection patch

Apply the four files at their indicated paths on top of the most recent AXIOM tree/router patch. This is a source patch, not a complete application release.

- Backend taxonomy now returns per-section count computed from existing per-subcategory catalog counts. No ordinary disk-file counts are relabeled as forensic findings.
- Frontend shows catalog counts on headings and children, including zero when no classified findings are recorded.
- Clicking a catalog section sends catalog_section; clicking a child sends catalog_key to the existing artifact list endpoint. File extension categories continue using category and sub_category independently.
- Switching between forensic taxonomy and evidence-file categories clears the other filter.
- Current catalog count derives from the preexisting get_selection_artifact_catalog implementation; counts/list matching must be tested live. The backend artifact list may include file-path heuristic matches or virtual evidence records, so counts and browse results must be reconciled before claiming exact parity.

Deployment: back up the current project; merge updated files; rebuild API and frontend; verify Connected Devices > USB Devices count and record listing, and verify switching back to All artifacts restores files. Do not re-extract evidence.

Validation: Python syntax compilation passed. Full TypeScript build unavailable because this local source environment does not have installed React/TypeScript project dependencies. No database integration tests were run.
