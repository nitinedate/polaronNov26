# Gap-report PDF/DOCX fix — what changed and why

Two files change: `backend/app/services/gap_report_template.py` (PDF/HTML) and
`backend/app/services/gap_assessment_report.py` (DOCX). Apply `gap_report_fix.patch`
from the project root, or drop in the two included files.

## 1) Section 4 "SUMMARY OF VULNERABILITY ASSESSMENT" — 20 rows per page, nothing dropped
**Bug:** the whole findings table was one `<table>` inside one page. xhtml2pdf (the
PDF engine) cannot split a tall table across pages — it renders the first page's
rows and **silently drops the rest**. That is why your PDF stopped at row 20 and the
NOTES block disappeared, and page 7 jumped straight to section 5.

**Fix:** the table is now emitted as **one self-contained `<table>` per page, 20
rows each** (`SUMMARY_ROWS_PER_PAGE = 20`). The severity box shows once on page 1;
"Sr No." continues correctly across pages; NOTES appears after the last page; each
continuation page is titled "… (CONTINUED)". Verified: all 153 rows + NOTES render.

## 2) Section 5 "VULNERABILITY OBSERVATION" — all findings except Info, not top 10
**Bug:** hard-capped at `findings[:10]` with the intro "top 10 identified
vulnerabilities".

**Fix:** shows **every actionable finding** (all severities except Info — Info is
already excluded upstream), packed **2 detail tables per page** in the same visual
style, with a "… (CONTINUED)" header. Intro now reads "List of all identified
vulnerabilities (excluding informational observations)." The DOCX export
(`gap_assessment_report.py`) had the same `findings[:10]` cap — also removed.

### Tuning knobs (top of the respective functions)
- `SUMMARY_ROWS_PER_PAGE = 20` — summary rows per page.
- `OBS_FINDINGS_PER_PAGE = 2` — observation blocks per page. **Do not raise above 2:**
  3 full detail blocks overflow a page and trip xhtml2pdf's `_FrameBreak.wrap` crash.
- `OBS_MAX_HOSTS_SHOWN = 25` — caps the IP list in a finding's detail table so a
  finding hitting many hosts can't overflow a page (full host list stays in the
  Solution Set export).

## Verified
- All 153 summary rows present (1→153) + NOTES; 8 summary pages.
- All 153 findings in section 5; 77 observation pages; 2 per page.
- TOC page numbers recomputed for multi-page summary + full observation list.
- Existing unit-test assertions (`test_summary_table_uses_full_risk_cell`,
  `test_toc_leader_dots_fill_to_page_number`) still pass.
- Renders cleanly (ERR=0) including a stress case of one finding with 80 hosts.
