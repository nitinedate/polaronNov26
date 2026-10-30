# Polaron — changes in this update

Four requests were addressed. Below is every file changed or added, and how to verify.

## 1 & 2. Gap-report PDF/DOCX fixes  (see GAP_REPORT_PDF_FIX.md)
- `backend/app/services/gap_report_template.py` — **modified**
  - Section 4 "SUMMARY OF VULNERABILITY ASSESSMENT" now paginates at **20 rows/page**
    (one self-contained table per page), so no rows are dropped. `SUMMARY_ROWS_PER_PAGE = 20`.
  - Section 5 "VULNERABILITY OBSERVATION" now shows **all actionable findings** (every
    severity except Info), **2 per page**, not just the top 10. `OBS_FINDINGS_PER_PAGE = 2`,
    `OBS_MAX_HOSTS_SHOWN = 25`.
  - TOC page math updated for the multi-page summary and full observation list.
- `backend/app/services/gap_assessment_report.py` — **modified**
  - DOCX export: observations changed from `findings[:10]` to all actionable findings.

## 3. WhatsApp offline recovery  (see WHATSAPP_OFFLINE_EXTRACT.md)
- `scripts/whatsapp_offline_extract.py` — **new** standalone examiner-workstation tool:
  decrypt crypt12/14/15 chats OFFLINE from an image / dir / tar / adb-backup, read-only,
  no device modification. Mirrors the pipeline's own whatsapp_crypt logic.

## 4. Mobile malware removal  (see MOBILE_MALWARE_REMOVAL_GUIDE.md)
- `backend/app/services/mobile_acquire/remediation_core.py` — **new**: pure logic (exact
  device-admin parsing, device-owner detection, brick-protection denylist, per-package
  outcome classification, device verdict, infected-app report). Unit-tested, no phone.
- `backend/app/services/mobile_acquire/live_remediate.py` — **modified (drop-in)**: uses the
  core; revokes the exact admin component; detects device-owner; brick-protection; disables
  accessibility + notification listeners; deletes residual public-storage payloads; returns
  `device_verdict` (clean|partial|needs_reflash) and `infected_report`. Backward-compatible
  `run_remediation(...)` (new `residual=`/`infected=` optional; result still has
  `removed`/`still_present`).
- `backend/app/malware/infected_apps.py` — **new**: `infected_apps(db, scan_id)` and
  `residual_paths(db, scan_id)` build the "which app is infected" rollup + cleanup plan from
  `mw_apps`/`mw_findings` (no schema change).
- `backend/app/services/mobile_acquire/ios_remediation.py` — **new**: honest iOS advisory +
  configuration-profile removal (software cannot delete iOS apps).
- `backend/tests/test_remediation_core.py`, `backend/tests/test_live_remediate_sim.py` — **new**.

Wiring the removal data end-to-end is 3 small edits documented in
MOBILE_MALWARE_REMOVAL_GUIDE.md ("How to wire it in").

## Verify
```
cd backend
python -m pytest tests/test_remediation_core.py tests/test_live_remediate_sim.py -q   # 7 passed
python tests/test_remediation_core.py        # ALL CORE TESTS PASSED
python tests/test_live_remediate_sim.py       # ALL ORCHESTRATION TESTS PASSED
```

## 5. Gap report downloaded as HTML instead of PDF — fixed
- `backend/app/services/gap_assessment_report.py` — **modified**: `render_gap_pdf` now has a
  two-engine pipeline (xhtml2pdf primary, PyMuPDF Story fallback) with failure logging; both
  exports raise a clear error instead of silently serving HTML on PDF-render failure. See
  GAP_REPORT_PDF_FIX.md section 3.
