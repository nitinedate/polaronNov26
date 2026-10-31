"""Lilavati-style Gap Assessment Report HTML/PDF template (Aetheris branding)."""

from __future__ import annotations

import base64
import re
import html
import mimetypes
from pathlib import Path
from typing import Any

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "gap_report"

# V1.10.7 branding: Polaron Technologies Pvt Ltd and its logo on every gap report.
REPORT_COMPANY = "Polaron Technologies Pvt Ltd"
REPORT_LOGO_FILE = "polaron_logo.png"
# "AETHERIS TECHNOLOGIES PVT LTD." / "Aetheris Technologies Pvt. Ltd" in any case.
# A dot after "Ltd" is dropped only mid-sentence (followed by a lowercase word),
# so a sentence-ending period stays.
_OLD_COMPANY_RE = re.compile(
    r"aetheris\s+technologies\s+pvt\.?\s*ltd(?:\.(?=\s+(?-i:[a-z])))?",
    re.IGNORECASE,
)


def rebrand_company(text: Any) -> Any:
    """Replace the former company name with REPORT_COMPANY in report text (V1.10.7).

    Applied when a report is rendered, so site overviews saved earlier (company
    name, introduction) show the new name without editing stored data.
    """
    if not isinstance(text, str) or "aetheris" not in text.lower():
        return text
    if re.fullmatch(r"\s*" + _OLD_COMPANY_RE.pattern + r"\.?\s*", text, re.IGNORECASE):
        return REPORT_COMPANY  # the whole value is the company name, e.g. "AETHERIS TECHNOLOGIES PVT. LTD."
    return _OLD_COMPANY_RE.sub(REPORT_COMPANY, text)

# Colors extracted from reference PDF (Gap Analysis Report december 2025 lilavati.pdf)
COLOR_GAP_RED = "#ff0000"
COLOR_NAVY = "#1f3860"
COLOR_CLIENT_BLUE = "#446ec4"
COLOR_SECTION_BAR = "#446ec4"
COLOR_LABEL_RED = "#c00000"
COLOR_CRITICAL = "#c00000"
COLOR_HIGH = "#ff0000"
COLOR_MEDIUM = "#ffc000"
COLOR_LOW = "#92d050"
COLOR_INFO = "#5b9bd5"

_RISK_BG = {
    "Critical": COLOR_CRITICAL,
    "High": COLOR_HIGH,
    "Medium": COLOR_MEDIUM,
    "Low": COLOR_LOW,
    "Info": COLOR_INFO,
}

TOC_ITEMS: list[tuple[str, str]] = [
    ("INTRODUCTION", "intro"),
    ("SITE OVERVIEW", "site_overview"),
    ("SITE INFRASTRUCTURE", "site_infra"),
    ("SUMMARY OF VULNERABILITY ASSESSMENT", "summary"),
    ("VULNERABILITY OBSERVATION", "vuln_observation"),
    ("KEY CONTACTS", "contacts"),
]

def _estimate_gap_observation_pages(
    findings_count: int,
    *,
    findings: list[dict[str, Any]] | None = None,
    ctx: dict[str, Any] | None = None,
) -> int:
    """Printed-page count for TOC.

    Section 5 keeps each actionable finding table on its own page. The shared
    page-size setting is also used by the styled renderer and TOC calculator.
    """
    if findings_count <= 0:
        return 1
    return (findings_count + OBS_FINDINGS_PER_PAGE - 1) // OBS_FINDINGS_PER_PAGE


def _esc(text: str | None) -> str:
    return html.escape(str(text or ""))


# xhtml2pdf ignores word-break / zero-width spaces on dotted NVT OIDs.
# Insert explicit <br/> at dot boundaries so the value stays inside the cell.
_OID_LINE_CHARS = 20


def _oid_lines(text: str, *, max_chars: int = _OID_LINE_CHARS) -> list[str]:
    rest = (text or "").strip()
    if not rest:
        return ["—"]
    lines: list[str] = []
    while rest:
        if len(rest) <= max_chars:
            lines.append(rest)
            break
        window = rest[: max_chars + 1]
        brk = max(window.rfind("."), window.rfind("-"))
        if brk <= 0:
            brk = max_chars
            lines.append(rest[:brk])
            rest = rest[brk:]
            continue
        lines.append(rest[: brk + 1])
        rest = rest[brk + 1 :]
    return lines


def _soft_wrap_oid(value: str | None) -> str:
    text = str(value or "").strip() or "—"
    if text == "—":
        return _esc(text)
    return "<br/>".join(_esc(part) for part in _oid_lines(text))


_COVER_ORNAMENT_FILES = ("cover_ornament_top.png", "cover_ornament_bottom.png")


def _flatten_cover_ornament_image(image: "Image.Image") -> "Image.Image":
    """Replace opaque black ornament backgrounds with white for PDF/HTML cover."""
    from PIL import Image

    rgba = image.convert("RGBA")
    pixels = rgba.load()
    for y in range(rgba.height):
        for x in range(rgba.width):
            red, green, blue, alpha = pixels[x, y]
            if alpha < 16 or (red < 48 and green < 48 and blue < 48):
                pixels[x, y] = (255, 255, 255, 0)
    white = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(white, rgba).convert("RGB")


def _ensure_cover_ornament_assets() -> None:
    """Write white-background ornament PNGs used by HTML and PDF cover rendering."""
    from PIL import Image

    for filename in _COVER_ORNAMENT_FILES:
        source = _STATIC_DIR / filename
        if not source.is_file():
            continue
        flattened = _flatten_cover_ornament_image(Image.open(source))
        stem = Path(filename)
        out = _STATIC_DIR / f"{stem.stem}_pdf{stem.suffix}"
        flattened.save(out, format="PNG")


def _load_cover_ornament(filename: str, *, max_width: int | None = None) -> "Image.Image | None":
    from PIL import Image

    source = _STATIC_DIR / filename
    if not source.is_file():
        return None
    image = _flatten_cover_ornament_image(Image.open(source))
    if max_width and image.width > max_width:
        ratio = max_width / image.width
        image = image.resize(
            (int(image.width * ratio), int(image.height * ratio)),
            Image.Resampling.LANCZOS,
        )
    return image


def _cover_asset_path(filename: str) -> Path | None:
    stem = Path(filename)
    pdf_name = f"{stem.stem}_pdf{stem.suffix}"
    for candidate in (pdf_name, filename):
        path = _STATIC_DIR / candidate
        if path.is_file():
            return path
    return None


def _asset_data_uri(filename: str) -> str:
    if filename in _COVER_ORNAMENT_FILES:
        _ensure_cover_ornament_assets()
    stem = Path(filename)
    pdf_name = f"{stem.stem}_pdf{stem.suffix}"
    for candidate in (pdf_name, filename):
        path = _STATIC_DIR / candidate
        if path.is_file():
            mime, _ = mimetypes.guess_type(path.name)
            mime = mime or "application/octet-stream"
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            return f"data:{mime};base64,{encoded}"
    return ""


def _risk_bg(risk: str) -> str:
    return _RISK_BG.get(risk, "#808080")


def _risk_badge(risk: str, *, block: bool = False) -> str:
    bg = _risk_bg(risk)
    style = f"background-color:{bg};color:#ffffff;"
    cls = "risk-badge"
    if block:
        cls += " risk-badge-block"
    return f'<span class="{cls}" style="{style}">{_esc(risk.upper())}</span>'


def _section_bar(title: str, *, large: bool = False) -> str:
    cls = "section-bar section-bar-large" if large else "section-bar"
    return f'<div class="{cls}">{_esc(title.upper())}</div>'



def _truncate_page_text(text: str, *, max_len: int = 420) -> str:
    text = (text or "").strip()
    if len(text) <= max_len:
        return text
    cut = text[: max_len - 1].rsplit(" ", 1)[0] or text[: max_len - 1]
    return cut.rstrip(".,;:") + "…"


def _page_wrap(
    body: str,
    page_no: int,
    *,
    section_bars: list[str] | None = None,
    bottom_bars: list[str] | None = None,
    page_break_before: bool = False,
    page_break_after: bool = True,
    flow: bool = False,
) -> str:
    bars_titles = section_bars if section_bars is not None else bottom_bars
    bars = ""
    for title in bars_titles or []:
        bars += _section_bar(title, large=(title.upper() == "GENERAL SITE REPORT"))
    break_cls = " report-page-break-before" if page_break_before else ""
    end_cls = " report-page-last" if not page_break_after else ""
    flow_cls = " report-page-flow" if flow else ""
    return (
        f'<div class="report-page{break_cls}{end_cls}{flow_cls}">'
        f'<div class="page-body">{bars}<div class="page-content">{body}</div></div>'
        f"</div>"
    )


GAP_REPORT_CSS = """
@page { size: 597pt 843pt; margin: 14mm 16mm 18mm 16mm; }
* { box-sizing: border-box; }
body {
  font-family: 'Times New Roman', Times, Georgia, serif;
  font-size: 12pt;
  line-height: 1.35;
  color: #000;
  margin: 0;
  padding: 0;
}
.report-page {
  page-break-after: always;
  page-break-inside: avoid;
}
.report-page-last {
  page-break-after: auto;
}
.report-page-flow {
  page-break-inside: auto;
}
/* Document-control page must NOT use page-break-inside:avoid — xhtml2pdf
   shrinks the whole page to a thin left strip when that flag is set. */
.report-page-doc-control {
  page-break-after: always;
  page-break-inside: auto;
}
.report-page-break-before {
  page-break-before: always;
}
.page-body {
  padding-bottom: 10mm;
}
.page-content {
  padding-bottom: 0;
}
.page-footer {
  display: none;
}
.doc-page-bar {
  background-color: #7f7f7f;
  color: #ffffff;
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 18pt;
  padding: 10px 12px;
  margin: 0;
  text-transform: uppercase;
  text-align: center;
  border: 1px solid #000;
}
.doc-block {
  width: 100% !important;
  border-collapse: collapse;
  margin: 0;
}
.doc-block td,
.doc-block th {
  border: 1px solid #000;
  padding: 8px 12px;
  vertical-align: middle;
  font-size: 14pt;
}
.doc-label {
  font-weight: bold;
  background: #d9d9d9;
  width: 25%;
}
.doc-value {
  background: #ffffff;
  width: 75%;
}
.revision-bar {
  background-color: #7f7f7f;
  color: #ffffff;
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 13pt;
  padding: 8px 12px;
  margin: 0;
  text-align: center;
  text-transform: uppercase;
  border: 1px solid #000;
}
.doc-block th {
  background: #d9d9d9;
  font-weight: bold;
  text-align: left;
  width: 25%;
}
.disclaimer-shell {
  width: 100%;
  border-collapse: collapse;
  margin: 0;
}
.doc-control-spacer {
  margin: 0;
  padding: 0;
  line-height: 1.15;
  font-size: 12pt;
  height: auto;
}
/* Outer shell keeps disclaimer at the bottom of page 2 (xhtml2pdf-safe). */
.doc-control-shell {
  width: 100%;
  border-collapse: collapse;
  border: 0;
}
.doc-control-shell td {
  border: 0;
  padding: 0;
}
.site-overview-line {
  font-size: 12pt;
  margin: 0 0 6px;
}
.site-overview-label {
  color: """ + COLOR_LABEL_RED + """;
  font-weight: bold;
  text-decoration: underline;
}
.section-bar {
  background-color: """ + COLOR_SECTION_BAR + """;
  color: #ffffff;
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 15.5pt;
  padding: 8px 12px;
  margin: 0 0 6mm 0;
  text-transform: uppercase;
}
.section-bar-large {
  font-size: 20pt;
  padding: 10px 12px;
}
.cover-page {
  page-break-after: always;
  page-break-inside: avoid;
}
.cover-frame {
  min-height: 248mm;
  padding: 10mm 10mm 16mm;
  text-align: center;
}
.cover-page .page-body {
  text-align: center;
  padding-top: 0;
}
.cover-logo {
  width: 280px;
  max-width: 85%;
  height: auto;
  margin: 8mm auto 0;
  display: block;
}
.cover-ornament-top {
  width: 110px;
  height: auto;
  margin: 0 auto 5mm;
  display: block;
}
.cover-ornament-mid {
  width: 58px;
  height: auto;
  margin: 4mm auto;
  display: block;
}
.cover-ornament-bottom {
  width: 58px;
  height: 36px;
  margin: 4mm auto 0;
  display: block;
}
.cover-rule {
  border: none;
  border-top: 1px solid """ + COLOR_CLIENT_BLUE + """;
  width: 78%;
  margin: 5mm auto;
}
.cover-rule-thick {
  border: none;
  border-top: 3px solid """ + COLOR_NAVY + """;
  width: 78%;
  margin: 4mm auto;
}
.cover-title-block {
  margin: 2mm auto;
  padding: 0;
}
.cover-title-text {
  padding-top: 0;
  padding-bottom: 2mm;
}
.cover-analysis-title {
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 26pt;
  color: """ + COLOR_NAVY + """;
  margin: 0;
  line-height: 1.05;
  letter-spacing: 0.5px;
}
.cover-gap {
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 28pt;
  color: """ + COLOR_GAP_RED + """;
  margin: 0;
  line-height: 1.05;
}
.cover-assessment {
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 21pt;
  color: """ + COLOR_NAVY + """;
  margin: 2mm 0 0 0;
  line-height: 1.1;
}
.cover-client {
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 14pt;
  color: """ + COLOR_CLIENT_BLUE + """;
  margin: 4mm 0 0 0;
}
.cover-date {
  font-family: Arial, Helvetica, sans-serif;
  font-weight: bold;
  font-size: 12pt;
  color: #000;
  margin: 0 0 4mm 0;
}
.cover-meta-block {
  margin: 8mm auto 0;
}
.cover-company {
  font-family: Arial, Helvetica, sans-serif;
  font-weight: bold;
  font-size: 12pt;
  color: #000;
  margin: 0;
}
.disclaimer-box {
  background: #000;
  color: #c00000;
  font-family: Arial, Helvetica, sans-serif;
  font-size: 11pt;
  font-weight: bold;
  text-align: center;
  text-transform: uppercase;
  padding: 12px 14px;
  line-height: 1.4;
  border: 1px solid #000;
}
.toc-shell {
  width: 100%;
  border-collapse: collapse;
  margin-top: 0;
  table-layout: fixed;
}
/* TOC body matches report body (Times New Roman). Period leaders still fill
   the title column via overflow clip — do not revert to Courier. */
.toc-shell td {
  font-family: 'Times New Roman', Times, Georgia, serif;
  font-size: 11pt;
  color: #000000;
  text-transform: uppercase;
  vertical-align: bottom;
}
/* 3-column TOC: Sr No | Title + dots | tight page column so leaders reach the number */
.toc-col-sr {
  width: 6%;
  padding: 9px 2px 9px 4px;
  white-space: nowrap;
  text-align: left;
  border: none;
}
.toc-col-title {
  width: 89%;
  padding: 9px 2px;
  white-space: nowrap;
  overflow: hidden;
  border: none;
}
.toc-col-page {
  width: 5%;
  padding: 9px 2px 9px 2px;
  white-space: nowrap;
  text-align: right;
  border: none;
}
.toc-title-cell {
  background-color: #7f7f7f;
  color: #ffffff;
  font-family: 'Times New Roman', Times, serif;
  font-weight: bold;
  font-size: 15pt;
  padding: 9px 12px;
  text-transform: uppercase;
  text-align: center;
}
.toc-footer-cell {
  background-color: #b5b5b5;
  height: 26px;
  padding: 0;
}
.toc-pagenum-underline {
  text-decoration: underline;
}
.severity-summary {
  border-collapse: collapse;
  margin: 4px 0 8px 0;
  font-size: 8.5pt;
  text-align: center;
}
.severity-summary th, .severity-summary td {
  border: 1px solid #666;
  padding: 4px 5px;
}
.severity-summary th { background: #eeeeee; font-weight: bold; }
.severity-summary .sev-critical { background: #c00000; color: #fff; }
.severity-summary .sev-high { background: #ff0000; color: #fff; }
.severity-summary .sev-medium { background: #ffc000; color: #000; }
.severity-summary .sev-low { background: #92d050; color: #000; }
.severity-summary .sev-info { background: #5b9bd5; color: #fff; }
.appendix-table, .warning-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 8.3pt;
  margin-top: 4px;
}
.appendix-table th, .appendix-table td, .warning-table th, .warning-table td {
  border: 1px solid #777; padding: 3px 4px; vertical-align: top;
}
.appendix-table th, .warning-table th { background: #e7e6e6; font-weight: bold; }
.appendix-table .col-sr { width: 7%; }
.appendix-table .col-host { width: 16%; }
.appendix-table .col-port { width: 11%; }
.appendix-table .col-obs { width: 38%; }
.appendix-table .col-oid { width: 28%; }
.appendix-note { font-size: 9pt; margin: 4px 0 8px 0; }
.mono-small, .appendix-table .col-oid {
  font-family: 'Courier New', Courier, monospace;
  font-size: 7.4pt;
  word-wrap: break-word;
  overflow-wrap: break-word;
}
.finding-detail {
  margin: 0 0 8mm;
  page-break-inside: avoid;
}
.finding-detail + .finding-detail {
  margin-top: 4mm;
}
.finding-detail-title {
  font-weight: bold;
  font-size: 12pt;
  color: """ + COLOR_LABEL_RED + """;
  margin: 0 0 6px;
  page-break-after: avoid;
}
.finding-kv-table {
  width: 100%;
  border-collapse: collapse;
  margin: 0 0 4mm;
  table-layout: fixed;
  font-size: 12pt;
  page-break-inside: avoid;
}
.finding-kv-table td {
  border: 1px solid #000;
  padding: 6px 10px;
  vertical-align: top;
}
.finding-kv-key {
  width: 25%;
  font-weight: bold;
  background: #ffffff;
}
.finding-kv-value {
  width: 75%;
  text-align: left;
}
.finding-kv-value.finding-kv-risk {
  font-weight: bold;
  text-align: center !important;
  color: #ffffff !important;
  vertical-align: middle;
}
.vuln-obs-intro {
  font-size: 11pt;
  margin: 0 0 6mm;
}
.contacts-block {
  margin: 0;
  font-size: 15pt;
}
.contacts-entry {
  margin: 0 0 8mm;
  line-height: 1.35;
  padding: 0;
  font-size: 15pt;
}
.contacts-entry-detail {
  margin: 0;
  padding: 0;
  line-height: 1.35;
  font-size: 14pt;
}
.body-text {
  font-size: 12pt;
  text-align: justify;
  margin: 0 0 8px;
}
.body-text p { margin: 0 0 8px; }
.label-red {
  color: """ + COLOR_LABEL_RED + """;
  font-weight: bold;
  font-size: 11pt;
  margin: 10px 0 4px;
}
.site-list {
  margin: 0 0 6px 16px;
  padding: 0;
}
.site-list li {
  margin: 2px 0;
  font-size: 12pt;
}
.gap-summary {
  width: 100%;
  border-collapse: collapse;
  margin: 6mm 0;
  font-size: 12pt;
}
.gap-summary th,
.gap-summary td {
  border: 1px solid #000;
  padding: 6px 8px;
  vertical-align: middle;
}
.gap-summary th {
  font-weight: bold;
  text-align: left;
  background-color: #d9d9d9;
  color: #000;
}
.gap-summary .col-srno { width: 10%; text-align: center; }
.gap-summary .col-risk { width: 18%; text-align: center; }
.gap-summary .col-name { width: 72%; }
.risk-badge {
  display: inline-block;
  color: #fff;
  font-weight: bold;
  font-size: 10pt;
  padding: 3px 10px;
  text-align: center;
  min-width: 72px;
}
.risk-badge-block {
  display: block;
  width: 100%;
  box-sizing: border-box;
}
.gap-summary .col-risk {
  padding: 6px 8px;
  color: #fff;
  font-weight: bold;
  text-align: center;
}
.gap-summary .risk-cell {
  color: #fff;
  font-weight: bold;
  text-align: center;
}
.notes-heading {
  color: """ + COLOR_LABEL_RED + """;
  font-weight: bold;
  font-size: 11.8pt;
  margin: 8mm 0 4mm;
  text-decoration: underline;
}
.important-notes {
  margin: 0 0 6px 18px;
  padding: 0;
  font-size: 12pt;
}
.important-notes li {
  margin: 4px 0;
}
.note-label {
  color: """ + COLOR_LABEL_RED + """;
  font-weight: bold;
}
.obs-item {
  margin-bottom: 8mm;
  font-size: 11pt;
}
.obs-title {
  font-weight: bold;
  margin-bottom: 2px;
}
.finding-block {
  margin-bottom: 10mm;
  page-break-inside: avoid;
}
.finding-title {
  background-color: """ + COLOR_LABEL_RED + """;
  color: #ffffff;
  font-weight: bold;
  font-size: 12pt;
  padding: 6px 10px;
  margin: 0;
}
.finding-title-high {
  background-color: """ + COLOR_HIGH + """;
}
.finding-meta {
  margin: 6px 0;
  font-size: 11pt;
}
.finding-meta strong { font-weight: bold; }
.finding-mitigation {
  margin: 4px 0 0 16px;
  padding: 0;
}
.finding-mitigation li { margin: 3px 0; }
.contacts-list {
  margin: 0;
  padding: 0 0 0 20px;
  font-size: 11pt;
}
.contacts-list li { margin-bottom: 8mm; }
"""


def _risk_cell(risk: str) -> str:
    bg = _risk_bg(risk)
    return (
        f'<td class="col-risk risk-cell" style="background-color:{bg};">'
        f"{_esc(risk.upper())}</td>"
    )


def _cover_page(client: str, company: str, report_date: str = "") -> str:
    _ensure_cover_ornament_assets()
    logo = _asset_data_uri(REPORT_LOGO_FILE)
    ornament_top = _asset_data_uri("cover_ornament_top.png")
    ornament_mid = _asset_data_uri("cover_ornament_bottom.png")
    logo_html = f'<img class="cover-logo" src="{logo}" alt="{_esc(REPORT_COMPANY)}" />' if logo else ""
    top_html = f'<img class="cover-ornament-top" src="{ornament_top}" alt="" />' if ornament_top else ""
    mid_html = f'<img class="cover-ornament-mid" src="{ornament_mid}" alt="" />' if ornament_mid else ""
    date_line = f"<p class='cover-date'>{_esc(report_date)}</p>" if report_date else ""
    body = (
        '<div class="cover-frame">'
        f"{top_html}"
        "<hr class='cover-rule'/>"
        '<div class="cover-title-block">'
        '<div class="cover-title-text">'
        "<p class='cover-analysis-title'>GAP ANALYSIS REPORT</p>"
        "</div>"
        "</div>"
        "<hr class='cover-rule-thick'/>"
        f"{mid_html}"
        f"<p class='cover-client'>{_esc(client)}</p>"
        f"{logo_html}"
        '<div class="cover-meta-block">'
        f"{date_line}"
        f"<p class='cover-company'>{_esc(company)}</p>"
        "</div>"
        "</div>"
    )
    return (
        f'<div class="report-page cover-page">'
        f'<div class="page-body"><div class="page-content">{body}</div></div>'
        f"</div>"
    )


def _document_control_page(
    *,
    client: str,
    author: str,
    version: str,
    report_date: str,
    department: str = "",
    page_no: int,
) -> str:
    """GENERAL SITE REPORT document-control page (PDF page 2).

    Built as simple full-width tables with explicit cell widths so xhtml2pdf
    does not collapse the layout into a thin left-hand strip.
    """
    disclaimer_text = (
        "THIS REPORT IS CONFIDENTIAL AND INTENDED SOLELY FOR THE USE AND "
        "INFORMATION OF THE ORGANIZATION TO WHOM IT IS ADDRESSED."
    )
    dept = department or "—"
    # Two separate tables (meta + revision) match the reference layout and
    # avoid colspan/colgroup bugs in xhtml2pdf.
    meta_table = (
        "<table width='100%' border='1' cellspacing='0' cellpadding='8' class='doc-block'>"
        "<tr>"
        "<td colspan='2' align='center' bgcolor='#7f7f7f' class='doc-page-bar' "
        "style='background-color:#7f7f7f;color:#ffffff;font-weight:bold;text-align:center;'>"
        "GENERAL SITE REPORT"
        "</td>"
        "</tr>"
        "<tr>"
        "<td width='25%' bgcolor='#d9d9d9' class='doc-label'><b>Document Type</b></td>"
        "<td width='75%' class='doc-value'>General Site Report</td>"
        "</tr>"
        f"<tr>"
        f"<td width='25%' bgcolor='#d9d9d9' class='doc-label'><b>Client</b></td>"
        f"<td width='75%' class='doc-value'>{_esc(client)}</td>"
        f"</tr>"
        f"<tr>"
        f"<td width='25%' bgcolor='#d9d9d9' class='doc-label'><b>Department</b></td>"
        f"<td width='75%' class='doc-value'>{_esc(dept)}</td>"
        f"</tr>"
        f"<tr>"
        f"<td width='25%' bgcolor='#d9d9d9' class='doc-label'><b>Creation Date</b></td>"
        f"<td width='75%' class='doc-value'>{_esc(report_date)}</td>"
        f"</tr>"
        f"<tr>"
        f"<td width='25%' bgcolor='#d9d9d9' class='doc-label'><b>Author</b></td>"
        f"<td width='75%' class='doc-value'>{_esc(author)}</td>"
        f"</tr>"
        "</table>"
    )
    # Small gap between meta and revision tables (reference keeps them near the top).
    between_tables = "<div class='doc-control-spacer' style='height:6pt;'>&nbsp;</div>"
    revision_table = (
        "<table width='100%' border='1' cellspacing='0' cellpadding='8' class='doc-block'>"
        "<tr>"
        "<td colspan='4' align='center' bgcolor='#7f7f7f' class='revision-bar' "
        "style='background-color:#7f7f7f;color:#ffffff;font-weight:bold;text-align:center;'>"
        "REVISION HISTORY"
        "</td>"
        "</tr>"
        "<tr>"
        "<th width='25%' bgcolor='#d9d9d9' align='left'>Version</th>"
        "<th width='25%' bgcolor='#d9d9d9' align='left'>Date</th>"
        "<th width='25%' bgcolor='#d9d9d9' align='left'>Author</th>"
        "<th width='25%' bgcolor='#d9d9d9' align='left'>Description</th>"
        "</tr>"
        f"<tr>"
        f"<td width='25%'>{_esc(version)}</td>"
        f"<td width='25%'>{_esc(report_date)}</td>"
        f"<td width='25%'>{_esc(author)}</td>"
        f"<td width='25%'>GAP Analysis Report</td>"
        f"</tr>"
        "</table>"
    )
    disclaimer = (
        "<table width='100%' border='0' cellspacing='0' cellpadding='0' class='disclaimer-shell'>"
        "<tr>"
        "<td align='center' bgcolor='#000000' class='disclaimer-box' "
        "style='background-color:#000000;color:#c00000;font-weight:bold;"
        "text-align:center;padding:12px 14px;'>"
        f"{_esc(disclaimer_text)}"
        "</td>"
        "</tr>"
        "</table>"
    )
    # Exactly 7 blank lines between revision history and the confidentiality
    # banner, plus a short spacer so the black bar sits lower on the page
    # without overflowing onto page 3 (xhtml2pdf). Do NOT nest content tables
    # inside another width-constrained table (that shrinks to a thin strip).
    after_revision = (
        f"<div class='doc-control-spacer'>{'<br/>' * 7}</div>"
        "<table width='100%' border='0' cellspacing='0' cellpadding='0' height='60'>"
        "<tr><td height='60' style='font-size:1pt;'>&nbsp;</td></tr>"
        "</table>"
    )
    body = f"{meta_table}{between_tables}{revision_table}{after_revision}{disclaimer}"
    # Dedicated page class — disables page-break-inside:avoid shrink-to-fit,
    # without using report-page-flow (finding pages must stay non-flow).
    return (
        f'<div class="report-page report-page-doc-control">'
        f'<div class="page-body"><div class="page-content">{body}</div></div>'
        f"</div>"
    )


def _format_toc_pagenum(key: str, page_map: dict[str, Any]) -> str:
    if key == "site_infra":
        val = page_map["site_infra"]
        if isinstance(val, tuple):
            start, end = val
            return f'{start}/<span class="toc-pagenum-underline">{end}</span>'
        return str(val)
    return str(page_map.get(key, ""))


_TOC_DOT = "."
_TOC_FONT = "Times-Roman"
_TOC_SIZE_PT = 11
# Must match @page size/margins and .toc-col-title width in GAP_REPORT_CSS.
_TOC_PAGE_WIDTH_PT = 597.0
_TOC_SIDE_MARGIN_MM = 16.0
_TOC_TITLE_COL_FRAC = 0.89
# Cell padding plus a small air gap so dots stop just before the page number.
_TOC_LEADER_INSET_PT = 2.0


def _toc_plain_pagenum(pagenum_html: str) -> str:
    return (
        pagenum_html.replace('<span class="toc-pagenum-underline">', "")
        .replace("</span>", "")
        .strip()
    )


def _toc_page_field(pagenum_plain: str) -> str:
    return pagenum_plain.replace(" ", "\u00a0")


def _toc_leader_dots(title: str) -> str:
    """Enough Times-Roman periods to fill the title column up to the page number."""
    from reportlab.pdfbase.pdfmetrics import stringWidth

    content_w = _TOC_PAGE_WIDTH_PT - 2 * (_TOC_SIDE_MARGIN_MM * 72.0 / 25.4)
    usable = content_w * _TOC_TITLE_COL_FRAC - _TOC_LEADER_INSET_PT
    title_w = stringWidth(title, _TOC_FONT, _TOC_SIZE_PT)
    period_w = stringWidth(_TOC_DOT, _TOC_FONT, _TOC_SIZE_PT) or 2.75
    count = max(3, int((usable - title_w) / period_w))
    return _TOC_DOT * count


def _toc_leader_line(idx: int, title: str, pagenum_plain: str) -> str:
    """Plain-text stand-in used by unit tests (sr + title + dots + page)."""
    sr = f"{idx}."
    name = title.upper()
    return f"{sr} {name}{_toc_leader_dots(name)}{pagenum_plain}"


def _toc_page_cell_html(pagenum_html: str) -> str:
    plain = _toc_plain_pagenum(pagenum_html)
    if "toc-pagenum-underline" in pagenum_html and "/" in plain:
        start, end = plain.split("/", 1)
        return (
            f"{_esc(start)}/"
            f'<span class="toc-pagenum-underline">{_esc(end)}</span>'
        )
    return _esc(plain)


def _toc_row_html(idx: int, title: str, pagenum_html: str) -> str:
    """3 cols, Times New Roman, period leaders to just before the page number."""
    sr = f"{idx}."
    name = title.upper()
    page_html = _toc_page_cell_html(pagenum_html)
    title_with_dots = f"{name.replace(' ', chr(160))}{_toc_leader_dots(name)}"
    return (
        f"<td class='toc-col-sr' width='6%'>{_esc(sr)}</td>"
        f"<td class='toc-col-title' width='89%'>{_esc(title_with_dots)}</td>"
        f"<td class='toc-col-page' width='5%'>{page_html}</td>"
    )


def _toc_page(page_no: int, page_map: dict[str, Any]) -> str:
    rows = [
        "<tr><td class='toc-title-cell' colspan='3'>TABLE OF CONTENTS</td></tr>",
    ]
    items = list(TOC_ITEMS)
    for idx, (title, key) in enumerate(items, start=1):
        rows.append(
            f"<tr>{_toc_row_html(idx, title, _format_toc_pagenum(key, page_map))}</tr>"
        )
    rows.append("<tr><td class='toc-footer-cell' colspan='3'>&nbsp;</td></tr>")
    body = (
        "<table width='100%' cellspacing='0' cellpadding='0' class='toc-shell'>"
        "<col style='width:6%'/>"
        "<col style='width:89%'/>"
        "<col style='width:5%'/>"
        f"{''.join(rows)}</table>"
    )
    return _page_wrap(body, page_no)


def _site_field(label: str, value: str) -> str:
    return f"<p class='label-red'>{_esc(label)}</p><p class='body-text'>{_esc(value)}</p>"


def _site_value(val: Any, default: str = "Not specified") -> str:
    text = str(val or "").strip()
    if not text or text in {"—", "-", "N/A", "n/a"}:
        return default
    return text


def _site_bullets(label: str, items: list[tuple[str, str]]) -> str:
    lis = "".join(
        f"<li><strong>{_esc(k)}:</strong> {_esc(_site_value(v))}</li>" for k, v in items
    )
    return f"<p class='label-red'>{_esc(label)}</p><ul class='site-list'>{lis}</ul>"


def _site_overview_fields(site: dict[str, Any], client: str, report_date: str = "") -> str:
    lines = [
        ("CLIENT:", client),
        ("BRANCH LOCATION's:", _site_value(site.get("branch_locations"))),
        ("CONTACT PERSON:", _site_value(site.get("contact_person"))),
    ]
    return "".join(
        f"<p class='site-overview-line'><span class='site-overview-label'>{_esc(label)}</span> {_esc(value)}</p>"
        for label, value in lines
    )


def _site_infrastructure_reference_body(site: dict[str, Any]) -> str:
    fw = site.get("firewall") or {}
    inet = site.get("internet") or {}
    email_items = site.get("email_services") or site.get("email") or []
    if isinstance(email_items, str):
        email_items = [email_items] if email_items.strip() else []
    email_html = ""
    if email_items:
        lis = "".join(f"<li>{_esc(_site_value(item))}</li>" for item in email_items)
        email_html = f"<p class='label-red'>EMAIL:</p><ul class='site-list'>{lis}</ul>"
    else:
        email_html = f"<p class='body-text'><strong>EMAIL:</strong> {_esc(_site_value(site.get('email_summary')))}</p>"

    return "\n".join(
        [
            f"<p class='body-text'><strong>ENDPOINTS:</strong> No. of Endpoints – {_esc(_site_value(site.get('num_endpoints')))}</p>",
            f"<p class='body-text'><strong>FIREWALL:</strong> {_esc(_site_value(fw.get('make_model') or site.get('firewall_summary'), 'No Firewall'))}</p>",
            f"<p class='body-text'><strong>BACKUP:</strong> {_esc(_site_value(site.get('backup_storage')))}</p>",
            f"<p class='body-text'><strong>SWITCH:</strong> {_esc(_site_value(site.get('switch')))}</p>",
            f"<p class='body-text'><strong>ROUTER:</strong> {_esc(_site_value(site.get('router')))}</p>",
            f"<p class='body-text'><strong>INTERNET:</strong> {_esc(_site_value(inet.get('vendors') or inet.get('type')))}</p>",
            f"<p class='body-text'><strong>ANTIVIRUS:</strong> {_esc(_site_value(site.get('antivirus')))}</p>",
            email_html,
        ]
    )


def _site_overview_reference_body(site: dict[str, Any], client: str, report_date: str = "") -> str:
    return _site_overview_fields(site, client, report_date)


def _site_infrastructure_parts(site: dict[str, Any], client: str, report_date: str = "") -> tuple[str, str]:
    fw = site.get("firewall") or {}
    inet = site.get("internet") or {}
    oses = site.get("operating_systems") or {}
    page_infra_one = "\n".join(
        [
            _site_bullets(
                "GENERAL INFORMATION:",
                [
                    ("Geographic Locations", site.get("geographic_locations")),
                    ("Number of Offices", site.get("num_offices")),
                    ("Number of Endpoints", site.get("num_endpoints")),
                ],
            ),
            _site_bullets(
                "OPERATING SYSTEMS:",
                [
                    ("Windows", oses.get("windows")),
                    ("Linux/Ubuntu", oses.get("linux", "0")),
                    ("Mac", oses.get("mac", "0")),
                    ("Data Centers", site.get("data_centers")),
                ],
            ),
            _site_bullets(
                "IT SECURITY & NETWORK:",
                [
                    ("Critical Servers", site.get("critical_servers")),
                    ("Critical Devices", site.get("critical_devices")),
                    ("Web Applications", site.get("web_apps")),
                    ("Mobile Applications", site.get("mobile_apps")),
                ],
            ),
        ]
    )
    page_infra_two = "\n".join(
        [
            _site_bullets(
                "FIREWALL:",
                [
                    ("Make & Model", fw.get("make_model")),
                    ("Policies & Logs", fw.get("policies_logs")),
                ],
            ),
            _site_bullets(
                "INTERNET CONNECTIVITY:",
                [
                    ("Type", inet.get("type")),
                    ("Vendors", inet.get("vendors")),
                    ("VPN & SDWAN", inet.get("vpn_sdwans")),
                    ("IDS/IPS", inet.get("ids_ips")),
                    ("DNS Security", inet.get("dns_security")),
                ],
            ),
            f"<p class='body-text'><strong>Network Access Control (NAC):</strong> {_esc(_site_value(site.get('nac')))}</p>",
            f"<p class='body-text'><strong>Antivirus:</strong> {_esc(_site_value(site.get('antivirus')))}</p>",
            f"<p class='body-text'><strong>Backup Storage:</strong> {_esc(_site_value(site.get('backup_storage')))}</p>",
        ]
    )
    return page_infra_one, page_infra_two


def _site_infrastructure_body(site: dict[str, Any], client: str) -> str:
    one, two = _site_infrastructure_parts(site, client)
    return f"{one}\n{two}"


def _intro_paragraphs(intro: str) -> str:
    blocks = [block.strip() for block in intro.replace("\r", "").split("\n\n") if block.strip()]
    parts: list[str] = []
    for block in blocks:
        lines = [line.strip() for line in block.split("\n") if line.strip()]
        if any(line.startswith("•") for line in lines):
            content = "<br/>".join(_esc(line) for line in lines)
        else:
            content = _esc(" ".join(lines))
        parts.append(f"<p class='body-text'>{content}</p>")
    return "".join(parts)


def _assessment_notice_html(assessment: dict[str, Any] | None, *, no_findings: bool = False) -> str:
    assessment = assessment or {}
    verified = bool(assessment.get("verified"))
    clean_eligible = bool(assessment.get("clean_eligible"))
    message = str(assessment.get("message") or "").strip()
    target_count = assessment.get("target_count")
    assessed = assessment.get("hosts_assessed")
    task_id = assessment.get("task_id")
    report_id = assessment.get("report_id")

    if verified and clean_eligible:
        headline = "Assessment evidence verified"
        if no_findings:
            conclusion = "Scan completed successfully; no actionable vulnerabilities were identified."
        else:
            conclusion = message or "The latest vulnerability assessment is verified."
        border = "#2e7d32"
        background = "#edf7ed"
    elif verified:
        # v1.2.1: do not render internal scanner-warning status blocks in the
        # client-facing Summary or Vulnerability Observation sections. The
        # warning evidence remains persisted in vuln_scan_results and, when
        # available, remains auditable in Appendix B. Importantly, this does
        # NOT change clean_eligible semantics: warning-bearing zero-finding
        # scans are still prevented from being represented as verified-clean.
        return ""
    else:
        headline = "ASSESSMENT INCOMPLETE / UNVERIFIED"
        conclusion = message or "Assessment status is unverified; no clean conclusion can be made."
        border = "#b3261e"
        background = "#fff1f0"

    evidence_parts = []
    if target_count is not None or assessed is not None:
        evidence_parts.append(
            f"Targets assessed: {_esc(str(assessed if assessed is not None else 0))} / "
            f"{_esc(str(target_count if target_count is not None else 0))}"
        )
    if task_id:
        evidence_parts.append(f"OpenVAS task: {_esc(str(task_id))}")
    if report_id:
        evidence_parts.append(f"Report: {_esc(str(report_id))}")
    evidence = "<br/>".join(evidence_parts)
    evidence_html = f"<div style='font-size:8.5pt;margin-top:4px'>{evidence}</div>" if evidence else ""
    return (
        f"<div style='border:1.5px solid {border};background:{background};padding:8px;margin:4px 0 10px 0'>"
        f"<p class='body-text' style='margin:0'><strong>{_esc(headline)}</strong></p>"
        f"<p class='body-text' style='margin:4px 0 0 0'>{_esc(conclusion)}</p>"
        f"{evidence_html}</div>"
    )


def _severity_summary_html(summary: dict[str, Any] | None) -> str:
    summary = summary or {}
    values = {key: int(summary.get(key) or 0) for key in ("Critical", "High", "Medium", "Low", "Info")}
    total = int(summary.get("total") or sum(values.values()))
    actionable = int(summary.get("actionable") or sum(values[k] for k in ("Critical", "High", "Medium", "Low")))
    return (
        "<table width='100%' class='severity-summary'><tr>"
        "<th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>"
        f"<tr><td class='sev-critical'>{values['Critical']}</td>"
        f"<td class='sev-high'>{values['High']}</td>"
        f"<td class='sev-medium'>{values['Medium']}</td>"
        f"<td class='sev-low'>{values['Low']}</td>"
        f"<td class='sev-info'>{values['Info']}</td><td>{total}</td></tr></table>"
        f"<p class='appendix-note'><strong>Actionable findings:</strong> {actionable} &nbsp; | &nbsp; "
        f"<strong>Informational observations:</strong> {values['Info']}</p>"
    )


# Section 4 "SUMMARY OF VULNERABILITY ASSESSMENT" is paginated at this many
# findings per printed page. xhtml2pdf (pisa) cannot split one tall <table>
# across pages — it renders the first page's worth of rows and silently drops
# the rest — so we emit one self-contained <table> per page instead.
SUMMARY_ROWS_PER_PAGE = 18


def _summary_row_html(idx: int, f: dict[str, Any]) -> str:
    return (
        f"<tr><td class='col-srno'>{idx}</td>"
        f"{_risk_cell(f['risk'])}"
        f"<td class='col-name'><strong>{_esc(f['name'])}</strong></td></tr>"
    )


def _summary_rows_table(findings_chunk: list[dict[str, Any]], start_idx: int) -> str:
    """One complete <table> for a single page's worth of summary rows.

    Sr No. continues from ``start_idx`` so numbering is correct across pages.
    """
    rows = "".join(
        _summary_row_html(start_idx + offset, f) for offset, f in enumerate(findings_chunk)
    )
    return (
        "<table width='100%' border='1' cellspacing='0' cellpadding='0' class='gap-summary'>"
        "<thead><tr><th class='col-srno'>Sr No.</th><th class='col-risk'>Risk</th>"
        "<th class='col-name'>Name</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _summary_notes_html() -> str:
    return (
        "<p class='notes-heading'>NOTES:</p>"
        "<ul class='important-notes'>"
        "<li>Kindly implement changes in the mentioned in the solution set attached with the "
        "Vulnerability Assessment Report.</li>"
        "<li>The changes will help you enhance your security posture.</li>"
        "</ul>"
    )


def _summary_pages(
    findings: list[dict[str, Any]],
    finding_summary: dict[str, Any] | None = None,
    *,
    per_page: int = SUMMARY_ROWS_PER_PAGE,
) -> list[str]:
    """Body HTML for each printed page of section 4.

    The severity breakdown box is rendered once on the first page; the findings
    table is split into chunks of ``per_page`` rows, each as its own <table> so
    the PDF engine paginates cleanly without dropping rows. The NOTES block is
    appended only after the final chunk.
    """
    severity_summary = _severity_summary_html(finding_summary)
    if not findings:
        return [severity_summary]
    bodies: list[str] = []
    total = len(findings)
    for start in range(0, total, per_page):
        chunk = findings[start : start + per_page]
        is_first = start == 0
        is_last = (start + per_page) >= total
        parts: list[str] = []
        if is_first:
            parts.append(severity_summary)
        parts.append(_summary_rows_table(chunk, start + 1))
        if is_last:
            parts.append(_summary_notes_html())
        bodies.append("".join(parts))
    return bodies


def _summary_page_count(findings_count: int, *, per_page: int = SUMMARY_ROWS_PER_PAGE) -> int:
    if findings_count <= 0:
        return 1
    return (findings_count + per_page - 1) // per_page


def _summary_table(
    findings: list[dict[str, Any]],
    assessment: dict[str, Any] | None = None,
    finding_summary: dict[str, Any] | None = None,
) -> str:
    """Single-block summary (severity box + full table + notes).

    Retained for callers/tests that want the whole section in one string. The
    paginated report uses :func:`_summary_pages` instead.
    """
    severity_summary = _severity_summary_html(finding_summary)
    if not findings:
        return severity_summary
    return severity_summary + _summary_rows_table(findings, 1) + _summary_notes_html()


def _finding_title_class(risk: str) -> str:
    return "finding-title finding-title-high" if risk == "High" else "finding-title"


def render_gap_cover_pdf(
    client: str,
    company: str = REPORT_COMPANY,
    report_date: str = "",
) -> bytes | None:
    """Render page-1 cover matching the Fundfox GAP ANALYSIS REPORT layout."""
    _ensure_cover_ornament_assets()
    try:
        import io

        import fitz
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return None

    width, height = 1193, 1688
    im = Image.new("RGB", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(im)

    def load_font(candidates: tuple[str, ...], size: int):
        for path in candidates:
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
        return ImageFont.load_default()

    def paste_centered(asset_name: str, top_y: int, *, max_width: int) -> int:
        asset = _load_cover_ornament(asset_name, max_width=max_width)
        if asset is None:
            return top_y
        x = (width - asset.width) // 2
        im.paste(asset, (x, top_y))
        return top_y + asset.height

    title_font = load_font(
        (
            r"C:\Windows\Fonts\timesbd.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
        ),
        54,
    )
    client_font = load_font(
        (
            r"C:\Windows\Fonts\timesbd.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
        ),
        34,
    )
    footer_font = load_font(
        (
            r"C:\Windows\Fonts\arialbd.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        ),
        28,
    )

    navy = (31, 56, 96)
    client_blue = (68, 110, 196)
    rule_blue = (68, 110, 196)
    cx = width // 2
    line_left = 131
    line_right = width - 131

    y = 72
    y = paste_centered("cover_ornament_top.png", y, max_width=220) + 28

    draw.line((line_left, y, line_right, y), fill=rule_blue, width=2)
    y += 34

    title = "GAP ANALYSIS REPORT"
    bbox = draw.textbbox((0, 0), title, font=title_font)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw // 2, y), title, fill=navy, font=title_font)
    y += (bbox[3] - bbox[1]) + 28
    draw.line((line_left, y, line_right, y), fill=navy, width=5)
    y += 36

    y = paste_centered("cover_ornament_bottom.png", y, max_width=116) + 24

    client_text = client.strip()
    cb = draw.textbbox((0, 0), client_text, font=client_font)
    ctw = cb[2] - cb[0]
    draw.text((cx - ctw // 2, y), client_text, fill=client_blue, font=client_font)
    y += (cb[3] - cb[1]) + 40

    logo_path = _cover_asset_path(REPORT_LOGO_FILE)
    if logo_path:
        logo = Image.open(logo_path).convert("RGBA")
        # The Polaron logo is wide (about 2.7:1), so allow more width than height.
        max_w, max_h = 620, 230
        ratio = min(max_w / logo.width, max_h / logo.height, 1.0)
        logo = logo.resize((int(logo.width * ratio), int(logo.height * ratio)), Image.Resampling.LANCZOS)
        bg = Image.new("RGBA", logo.size, (255, 255, 255, 255))
        flat_logo = Image.alpha_composite(bg, logo).convert("RGB")
        lx = cx - flat_logo.width // 2
        im.paste(flat_logo, (lx, y))
        y += flat_logo.height + 36

    if report_date:
        db = draw.textbbox((0, 0), report_date, font=footer_font)
        dtw = db[2] - db[0]
        draw.text((cx - dtw // 2, y), report_date, fill=(0, 0, 0), font=footer_font)
        y += (db[3] - db[1]) + 18

    company_text = str(rebrand_company(company or REPORT_COMPANY)).strip()
    cob = draw.textbbox((0, 0), company_text, font=footer_font)
    cotw = cob[2] - cob[0]
    draw.text((cx - cotw // 2, y), company_text, fill=(0, 0, 0), font=footer_font)

    png_buf = io.BytesIO()
    im.save(png_buf, format="PNG")
    doc = fitz.open()
    page = doc.new_page(width=597.0, height=843.48)
    page.insert_image(page.rect, stream=png_buf.getvalue())
    return doc.tobytes()


_WATERMARK_PNG: bytes | None = None

# Match cover_reference_full.png (597×843 pt page at 2× raster).
_WATERMARK_CANVAS_W = 1193
_WATERMARK_CANVAS_H = 1688
_WATERMARK_FONT_SIZE = 80
# -45° → readable diagonal: C higher (top-left) → L lower (bottom-right).
# Avoid ±135° — those flip letters upside-down / unreadable.
_WATERMARK_ANGLE = -45
_WATERMARK_COLOR = (228, 229, 230, 155)
_WATERMARK_Y_OFFSET = -40
_WATERMARK_STATIC_NAME = "watermark_confidential_readable.png"


def _watermark_font(size: int):
    from PIL import ImageFont

    for path in (
        "arialbd.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _build_confidential_watermark_png() -> bytes:
    """Full-page diagonal CONFIDENTIAL with C at top and L at bottom."""
    global _WATERMARK_PNG
    if _WATERMARK_PNG is not None:
        return _WATERMARK_PNG

    static_path = _STATIC_DIR / _WATERMARK_STATIC_NAME
    # Drop stale upside-down / opposite-orientation caches.
    for stale in (
        "watermark_confidential.png",
        "watermark_confidential_tr_bl.png",
        "watermark_confidential_c_top.png",
    ):
        legacy = _STATIC_DIR / stale
        if legacy.is_file():
            try:
                legacy.unlink()
            except OSError:
                pass

    if static_path.is_file():
        _WATERMARK_PNG = static_path.read_bytes()
        return _WATERMARK_PNG

    try:
        import io

        from PIL import Image, ImageDraw
    except ImportError:
        return b""

    canvas = Image.new("RGBA", (_WATERMARK_CANVAS_W, _WATERMARK_CANVAS_H), (255, 255, 255, 0))
    draw = ImageDraw.Draw(canvas)
    font = _watermark_font(_WATERMARK_FONT_SIZE)
    text = "CONFIDENTIAL"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tmp = Image.new("RGBA", (tw + 40, th + 40), (0, 0, 0, 0))
    td = ImageDraw.Draw(tmp)
    td.text((20, 20), text, font=font, fill=_WATERMARK_COLOR)
    tmp = tmp.rotate(_WATERMARK_ANGLE, expand=True, resample=Image.Resampling.BICUBIC)
    ox = (_WATERMARK_CANVAS_W - tmp.width) // 2
    oy = (_WATERMARK_CANVAS_H - tmp.height) // 2 + _WATERMARK_Y_OFFSET
    canvas.paste(tmp, (ox, oy), tmp)

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    _WATERMARK_PNG = buf.getvalue()
    try:
        _STATIC_DIR.mkdir(parents=True, exist_ok=True)
        static_path.write_bytes(_WATERMARK_PNG)
    except OSError:
        pass
    return _WATERMARK_PNG


def apply_confidential_watermark(pdf_bytes: bytes, *, skip_first_page: bool = True) -> bytes:
    """Draw the same large diagonal CONFIDENTIAL watermark as the cover on inner pages."""
    try:
        import fitz
    except ImportError:
        return pdf_bytes

    wm_png = _build_confidential_watermark_png()
    if not wm_png:
        return pdf_bytes

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for idx in range(doc.page_count):
        if skip_first_page and idx == 0:
            continue
        page = doc[idx]
        page.insert_image(page.rect, stream=wm_png, overlay=False)

    out = doc.tobytes()
    doc.close()
    return out


def stamp_gap_page_numbers(pdf_bytes: bytes) -> bytes:
    """Place centered page numbers at the bottom of every PDF page."""
    try:
        import fitz
    except ImportError:
        return pdf_bytes

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for page in doc:
        rect = page.rect
        footer = fitz.Rect(0, rect.height - 42, rect.width, rect.height - 16)
        page.insert_textbox(
            footer,
            str(page.number + 1),
            fontsize=11,
            fontname="tiro",
            color=(0, 0, 0),
            align=fitz.TEXT_ALIGN_CENTER,
        )
    out = doc.tobytes()
    doc.close()
    return out


def _finding_risk_row(risk: str) -> str:
    bg = _risk_bg(risk)
    return (
        f"<tr><td class='finding-kv-key'>{_esc('Risk')}</td>"
        f'<td class="finding-kv-value finding-kv-risk" style="background-color:{bg};">'
        f"{_esc(risk)}</td></tr>"
    )


def _finding_kv_row(label: str, value_html: str) -> str:
    return (
        f"<tr><td class='finding-kv-key'>{_esc(label)}</td>"
        f"<td class='finding-kv-value'>{value_html}</td></tr>"
    )


def _finding_detail_html(f: dict[str, Any], ctx: dict[str, Any]) -> str:
    desc_fn = ctx.get("_finding_description")
    mit_fn = ctx.get("_mitigation_text")
    impact_fn = ctx.get("_impact_text")
    host_list = f.get("hosts") or []
    if len(host_list) > OBS_MAX_HOSTS_SHOWN:
        hosts = ", ".join(host_list[:OBS_MAX_HOSTS_SHOWN]) + f" (+{len(host_list) - OBS_MAX_HOSTS_SHOWN} more)"
    elif host_list:
        hosts = ", ".join(host_list)
    else:
        hosts = "Not specified"
    desc = desc_fn(f) if desc_fn else (f.get("client_description") or f.get("description") or f["name"])
    impact = impact_fn(f) if impact_fn else (f.get("client_impact") or f.get("description") or f["name"])
    mit = mit_fn(f) if mit_fn else (f.get("remediation") or "Review and remediate per vendor guidance.")
    table = (
        "<table width='100%' border='1' cellspacing='0' cellpadding='0' class='finding-kv-table'>"
        f"{_finding_risk_row(f['risk'])}"
        f"{_finding_kv_row('IP address', _esc(hosts))}"
        f"{_finding_kv_row('Description', _esc(desc))}"
        f"{_finding_kv_row('Impact', _esc(impact))}"
        f"{_finding_kv_row('Mitigation', _esc(mit))}"
        "</table>"
    )
    return (
        f"<div class='finding-detail'>"
        f"<p class='finding-detail-title'>&#9656; {_esc(f['name'])}</p>"
        f"{table}"
        f"</div>"
    )


def _observation_bullets_html(findings: list[dict[str, Any]], ctx: dict[str, Any]) -> str:
    obs_fn = ctx.get("_finding_observation")
    if not findings:
        return "<p class='body-text'><em>No observations recorded for this case.</em></p>"
    items = []
    for f in findings:
        obs = obs_fn(f) if obs_fn else (f.get("client_observation") or f.get("observation") or f["name"])
        obs = _truncate_page_text(obs, max_len=520)
        items.append(
            f"<p class='body-text'><strong>• {_esc(f['name'])}</strong><br/>"
            f"<strong>Observation:</strong> {_esc(obs)}</p>"
        )
    return "".join(items)


def _recommendation_bullets_html(findings: list[dict[str, Any]], ctx: dict[str, Any]) -> str:
    rec_fn = ctx.get("_finding_recommendation")
    if not findings:
        return "<p class='body-text'><em>No recommendations recorded for this case.</em></p>"
    items = []
    for f in findings:
        rec = rec_fn(f) if rec_fn else (f.get("client_recommendation") or "")
        rec = _truncate_page_text(rec, max_len=520)
        if rec:
            items.append(
                f"<p class='body-text'><strong>• {_esc(f['name'])}</strong><br/>"
                f"<strong>Recommendation:</strong> {_esc(rec)}</p>"
            )
    return "".join(items) or "<p class='body-text'><em>No recommendations recorded for this case.</em></p>"


def _impact_bullets_html(findings: list[dict[str, Any]], ctx: dict[str, Any]) -> str:
    impact_fn = ctx.get("_impact_text")
    if not findings:
        return "<p class='body-text'><em>No impact summary recorded for this case.</em></p>"
    items = []
    for f in findings:
        if impact_fn:
            impact = impact_fn(f)
        else:
            impact = f.get("client_impact") or f.get("description") or f["name"]
        impact = _truncate_page_text(impact, max_len=520)
        items.append(f"<p class='body-text'><strong>• {_esc(f['name'])}:</strong> {_esc(impact)}</p>")
    return "".join(items)


def _contacts_html(contacts: list[dict[str, Any]]) -> str:
    blocks = []
    for c in contacts:
        name = c.get("name", "")
        title = c.get("title", "")
        email = c.get("email", "")
        lines = [f"• {_esc(name)}"]
        detail_lines = []
        if title:
            detail_lines.append(f"\u00a0\u00a0{_esc(title)}")
        if email:
            detail_lines.append(f"\u00a0\u00a0{_esc(email)}")
        if detail_lines:
            body = f"{lines[0]}<br/>{'<br/>'.join(detail_lines)}"
        else:
            body = lines[0]
        blocks.append(f"<p class='contacts-entry'>{body}</p>")
    return f"<div class='contacts-block'>{''.join(blocks)}</div>"


# Section 5 keeps each finding table together on its own page. This matches the
# reference report and prevents the PDF engines from leaving an open table at a
# page boundary when a finding contains long evidence text.
OBS_FINDINGS_PER_PAGE = 1

# Cap the IP list shown in a finding's detail table so a finding affecting many
# hosts cannot grow a block tall enough to overflow the page. The full per-host
# breakdown remains in the Solution Set export.
OBS_MAX_HOSTS_SHOWN = 25


def _finding_details_pages(findings: list[dict[str, Any]], ctx: dict[str, Any]) -> list[tuple[str, list[str] | None, bool]]:
    intro = (
        "<p class='vuln-obs-intro'>&#9656; List of all identified vulnerabilities "
        "(excluding informational observations).</p>"
    )
    if not findings:
        return [(intro, ["5. VULNERABILITY OBSERVATION"], False)]

    pages: list[tuple[str, list[str] | None, bool]] = []
    total = len(findings)
    for page_idx, start in enumerate(range(0, total, OBS_FINDINGS_PER_PAGE)):
        chunk = findings[start : start + OBS_FINDINGS_PER_PAGE]
        detail_html = "".join(_finding_detail_html(f, ctx) for f in chunk)
        body = (intro if page_idx == 0 else "") + detail_html
        if page_idx == 0:
            section = ["5. VULNERABILITY OBSERVATION"]
        else:
            section = ["5. VULNERABILITY OBSERVATION (CONTINUED)"]
        # One finding per page keeps the table and its outer border together.
        pages.append((body, section, False))
    return pages


def _compute_toc_page_map(*, findings_count: int, findings: list[dict[str, Any]] | None = None, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = ctx or {}
    intro = 4
    site_overview = 5
    site_infra = 5
    summary = 6
    # Section 4 now spans one page per SUMMARY_ROWS_PER_PAGE findings, so the
    # observation section starts after all summary pages.
    summary_pages = _summary_page_count(findings_count)
    vuln_observation = summary + summary_pages
    detail_page_count = _estimate_gap_observation_pages(
        findings_count,
        findings=findings,
        ctx=ctx,
    )
    contacts = vuln_observation + detail_page_count
    return {
        "intro": intro,
        "site_overview": site_overview,
        "site_infra": site_infra,
        "summary": summary,
        "vuln_observation": vuln_observation,
        "contacts": contacts,
    }


# PyMuPDF's Story engine repaints a cell's solid background-color onto tall rows
# and onto later pages (stray coloured/grey bars). So the fallback uses NO
# background fills anywhere: section headings are blue text + a blue underline,
# table headers are bold text, and severity is shown with coloured left-border
# bars + coloured bold text. With fills gone there is nothing left to bleed.
_FALLBACK_CSS = """<style>
body { font-family: Helvetica, Arial, sans-serif; font-size: 11pt; color: #000; }
h1.cover { text-align: center; font-size: 26pt; color: #1f3860; margin: 48px 0 10px; letter-spacing: 1px; }
img.cover-logo { display: block; margin: 20px auto; }
p.cover-sub { text-align: center; color: #446ec4; font-size: 15pt; font-weight: bold; margin: 6px 0; }
p.cover-meta { text-align: center; font-size: 12pt; font-weight: bold; margin: 4px 0; }
p.title { text-align: center; font-weight: bold; font-size: 12pt; letter-spacing: 1px; margin: 16px 0 6px; }
p.notice { border: 2px solid #000; color: #c00000; font-weight: bold; text-align: center; padding: 10px; margin: 28px 0; }
h2.section { color: #1f3860; font-weight: bold; font-size: 15pt; border-bottom: 3px solid #446ec4; padding: 2px 0 5px; margin: 2px 0 12px; }
p.body { margin: 6px 0; }
p.obs-name { color: #c00000; font-weight: bold; margin: 14px 0 4px; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 14px; }
th, td { border: 1px solid #808080; padding: 5px 7px; vertical-align: top; text-align: left; }
th { font-weight: bold; }
td.srno { text-align: center; }
table.sev td { text-align: center; font-weight: bold; font-size: 10pt; }
table.sev th { background: #eeeeee; text-align: center; }
table.sev td.sev-critical { background: #c00000; color: #fff; }
table.sev td.sev-high { background: #ff0000; color: #fff; }
table.sev td.sev-medium { background: #ffc000; color: #000; }
table.sev td.sev-low { background: #92d050; color: #000; }
table.sev td.sev-info { background: #5b9bd5; color: #fff; }
table.sev td.sev-total { background: #fff; color: #000; }
p.toc-title-band { width: 525px; background: #7f7f7f; color: #fff; font-weight: bold; text-align: center; padding: 9px; margin: 0 0 4px; }
p.toc-row { font-size: 11pt; margin: 7px 0; white-space: nowrap; }
div.toc-footer-band { width: 525px; height: 18px; background: #b5b5b5; margin: 4px 0 0; }
table.summary td.risk-cell { font-weight: bold; text-align: center; }
table.summary th { background: #d9d9d9; }
table.kv { page-break-inside: avoid; break-inside: avoid; }
table.kv tr { page-break-inside: avoid; break-inside: avoid; }
table.kv td.risk-cell { font-weight: bold; text-align: center; }
</style>"""

# Readable text colours for the fallback (no cell fills). Darkened so Medium/Low
# stay legible on white.
_FB_RISK_TEXT = {
    "Critical": "#c00000",
    "High": "#d00000",
    "Medium": "#b06a00",
    "Low": "#3f7a2e",
    "Info": "#2e6da4",
}

# Section 5 lists every actionable finding (same for the fallback). Front-matter
# labels for the table of contents, in order; keys map to _fallback_section_bodies.
_FB_TOC_ENTRIES = [
    ("INTRODUCTION", "intro"),
    ("SITE OVERVIEW", "overview"),
    ("SITE INFRASTRUCTURE", "infra"),
    ("SUMMARY OF VULNERABILITY ASSESSMENT", "summary"),
    ("VULNERABILITY OBSERVATION", "observation"),
    ("KEY CONTACTS", "contacts"),
]


def _fb_doc(body: str) -> str:
    return "<html><head><meta charset='utf-8'/>" + _FALLBACK_CSS + "</head><body>" + body + "</body></html>"


def _fallback_section_bodies(ctx: dict[str, Any]) -> dict[str, str]:
    """Body HTML for each page-group of the fallback report (no html/head wrapper).

    Keys: cover, docctrl, intro, overview, infra, summary, observation, contacts.
    Rendered one-Story-per-body so each section starts on a new page with no
    cross-section bleed.
    """
    site = ctx.get("site") or {}
    client = _esc(ctx.get("client") or "")
    report_date = _esc(ctx.get("report_date") or "")
    company = _esc(_site_value(site.get("company_name"), REPORT_COMPANY))
    author = _esc(_site_value(site.get("author"), ""))
    version = _esc(site.get("document_version") or "1.0")
    findings = ctx.get("findings") or []
    fs = ctx.get("finding_summary") or {}

    desc_fn = ctx.get("_finding_description") or (lambda f: f.get("description") or f.get("name") or "")
    impact_fn = ctx.get("_impact_text") or (lambda f: "")
    mit_fn = ctx.get("_mitigation_text") or (lambda f: f.get("remediation") or "")

    # --- cover (logo page) ---
    logo_uri = ""
    try:
        logo_uri = _asset_data_uri(REPORT_LOGO_FILE)
    except Exception:
        logo_uri = ""
    logo_html = f"<img class='cover-logo' src='{logo_uri}' style='max-width:300px'/>" if logo_uri else ""
    cover = (f"<h1 class='cover'>GAP ANALYSIS REPORT</h1><p class='cover-sub'>{client}</p>"
             f"{logo_html}<p class='cover-meta'>{report_date}</p><p class='cover-meta'>{company}</p>")

    # --- document control: GENERAL SITE REPORT + REVISION HISTORY + notice ---
    docctrl = (
        "<p class='title'>GENERAL SITE REPORT</p>"
        "<table><colgroup><col style='width:150px'/><col/></colgroup><tbody>"
        "<tr><th>Document Type</th><td>General Site Report</td></tr>"
        f"<tr><th>Client</th><td>{client}</td></tr>"
        f"<tr><th>Department</th><td>{_esc(_site_value(site.get('department')))}</td></tr>"
        f"<tr><th>Creation Date</th><td>{report_date}</td></tr>"
        f"<tr><th>Author</th><td>{author}</td></tr>"
        "</tbody></table>"
        "<p class='title'>REVISION HISTORY</p>"
        "<table><thead><tr><th>Version</th><th>Date</th><th>Author</th><th>Description</th></tr></thead>"
        f"<tbody><tr><td>{version}</td><td>{report_date}</td><td>{author}</td><td>GAP Analysis Report</td></tr></tbody></table>"
        "<p class='notice'>THIS REPORT IS CONFIDENTIAL AND INTENDED SOLELY FOR THE USE AND "
        "INFORMATION OF THE ORGANIZATION TO WHOM IT IS ADDRESSED.</p>"
    )

    # --- 1. Introduction ---
    intro_txt = _esc(ctx.get("intro") or "")
    intro = "<h2 class='section'>1. INTRODUCTION</h2>" + (f"<p class='body'>{intro_txt}</p>" if intro_txt else "")

    # --- 2. Site overview ---
    overview = "<h2 class='section'>2. SITE OVERVIEW</h2>" + "".join(
        f"<p class='body'><strong>{lbl}</strong> {val}</p>" for lbl, val in (
            ("CLIENT:", client),
            ("BRANCH LOCATION's:", _esc(_site_value(site.get("branch_locations")))),
            ("CONTACT PERSON:", _esc(_site_value(site.get("contact_person"))))))

    # --- 3. Site infrastructure ---
    fw = site.get("firewall") or {}
    infra = ("<h2 class='section'>3. SITE INFRASTRUCTURE</h2>"
             f"<p class='body'><strong>ENDPOINTS:</strong> No. of Endpoints – {_esc(_site_value(site.get('num_endpoints')))}</p>"
             f"<p class='body'><strong>FIREWALL:</strong> {_esc(_site_value(fw.get('make_model') or site.get('firewall_summary'), 'No Firewall'))}</p>")

    # --- 4. Summary ---
    sev_headers = "".join(f"<th>{label}</th>" for label in ("Critical", "High", "Medium", "Low", "Info", "Total"))
    sev_values = "".join(
        f"<td class='sev-{key.lower()}'>{_esc(fs.get(key, 0))}</td>"
        for key in ("Critical", "High", "Medium", "Low", "Info")
    ) + f"<td class='sev-total'>{_esc(fs.get('total', len(findings)))}</td>"
    summary_parts = ["<h2 class='section'>4. SUMMARY OF VULNERABILITY ASSESSMENT</h2>",
                     f"<table class='sev'><tbody><tr>{sev_headers}</tr><tr>{sev_values}</tr></tbody></table>"]
    if fs.get("actionable") is not None:
        summary_parts.append(
            f"<p class='body'><strong>Actionable findings:</strong> {_esc(fs.get('actionable'))} &nbsp; | &nbsp; "
            f"<strong>Informational observations:</strong> {_esc(fs.get('informational', fs.get('Info', 0)))}</p>")
    rows = []
    for idx, f in enumerate(findings, start=1):
        risk = f.get("risk", "")
        risk_bg = _RISK_BG.get(risk, "#808080")
        risk_text = "#000000" if risk in {"Medium", "Low"} else "#ffffff"
        rows.append(f"<tr><td class='srno'>{idx}</td>"
                    f"<td class='risk-cell' bgcolor='{risk_bg}' style='background-color:{risk_bg};color:{risk_text}'>"
                    f"{_esc(str(risk).upper())}</td>"
                    f"<td><strong>{_esc(f.get('name', ''))}</strong></td></tr>")
    summary_parts.append(
        "<table class='summary'><colgroup><col style='width:70px'/><col style='width:120px'/><col/></colgroup>"
        "<thead><tr><th>Sr No.</th><th>Risk</th><th>Name</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>")
    summary_parts.append("<p class='body'><strong>NOTES:</strong> Kindly implement the changes mentioned in the "
                         "solution set attached with the Vulnerability Assessment Report. The changes will help you "
                         "enhance your security posture.</p>")
    summary = "".join(summary_parts)

    # --- 5. Vulnerability observation (all actionable findings) ---
    obs_parts = ["<h2 class='section'>5. VULNERABILITY OBSERVATION</h2>",
                 "<p class='body'>&#9632; List of all identified vulnerabilities (excluding informational observations).</p>"]
    for f in findings:
        host_list = f.get("hosts") or []
        if len(host_list) > OBS_MAX_HOSTS_SHOWN:
            hosts = ", ".join(host_list[:OBS_MAX_HOSTS_SHOWN]) + f" (+{len(host_list) - OBS_MAX_HOSTS_SHOWN} more)"
        else:
            hosts = ", ".join(host_list) if host_list else "Not specified"
        rtxt = _FB_RISK_TEXT.get(f.get("risk", ""), "#000000")
        obs_parts.append(f"<p class='obs-name'>&#9632; {_esc(f.get('name', ''))}</p>")
        risk = f.get("risk", "")
        risk_bg = _RISK_BG.get(risk, "#808080")
        risk_text = "#000000" if risk in {"Medium", "Low"} else "#ffffff"
        obs_parts.append(
            "<table class='kv'><colgroup><col style='width:130px'/><col/></colgroup><tbody>"
            f"<tr><th>Risk</th><td class='risk-cell' bgcolor='{risk_bg}' style='background-color:{risk_bg};text-align:center;font-weight:bold;color:{risk_text}'>{_esc(risk)}</td></tr>"
            f"<tr><th>IP address</th><td>{_esc(hosts)}</td></tr>"
            f"<tr><th>Description</th><td>{_esc(desc_fn(f))}</td></tr>"
            f"<tr><th>Impact</th><td>{_esc(impact_fn(f))}</td></tr>"
            f"<tr><th>Mitigation</th><td>{_esc(mit_fn(f))}</td></tr>"
            "</tbody></table>")
    observation = "".join(obs_parts)

    # --- 6. Key contacts ---
    contacts_parts = ["<h2 class='section'>6. KEY CONTACTS</h2>"]
    for c in (site.get("key_contacts") or []):
        line = " &nbsp; ".join(x for x in (_esc(c.get("name")), _esc(c.get("title")), _esc(c.get("email"))) if x)
        contacts_parts.append(f"<p class='body'>&#9632; {line}</p>")
    contacts = "".join(contacts_parts)

    return {"cover": cover, "docctrl": docctrl, "intro": intro, "overview": overview,
            "infra": infra, "summary": summary, "observation": observation, "contacts": contacts}


def build_fallback_sections(ctx: dict[str, Any]) -> dict[str, str]:
    """Full HTML documents for each fallback page-group, ready to render one per Story."""
    return {k: _fb_doc(v) for k, v in _fallback_section_bodies(ctx).items()}


def build_fallback_toc(page_map: dict[str, int] | None = None) -> str:
    """Table-of-contents page (its own Story). page_map maps section key -> page number."""
    return _fb_doc(_fallback_toc_body(page_map))


def _fallback_toc_body(page_map: dict[str, int] | None = None) -> str:
    """TOC markup shared by the section renderer and the single-document fallback."""
    page_map = page_map or {}
    rows = []
    for i, (label, key) in enumerate(_FB_TOC_ENTRIES, start=1):
        pg = page_map.get(key, "")
        from reportlab.pdfbase.pdfmetrics import stringWidth

        prefix = f"{i}.   {label}"
        available = 505  # printable content width after page margins
        title_width = stringWidth(prefix, "Helvetica", 11)
        page_width = stringWidth(str(pg), "Helvetica", 11)
        dot_width = stringWidth(".", "Helvetica", 11) or 3
        spacer_width = stringWidth("   ", "Helvetica", 11)
        dots = "." * max(3, int((available - title_width - page_width - spacer_width) / dot_width))
        rows.append(f"<p class='toc-row'>{_esc(prefix)}{dots}&nbsp;&nbsp;&nbsp;{_esc(pg)}</p>")
    toc = ("<p class='toc-title-band' style='background-color:#7f7f7f;color:#ffffff'>TABLE OF CONTENTS</p>"
           f"{''.join(rows)}"
           "<div class='toc-footer-band' style='background-color:#b5b5b5'>&nbsp;</div>")
    return toc


def build_fallback_summary_pages(ctx: dict[str, Any], *, per_page: int = SUMMARY_ROWS_PER_PAGE) -> list[str]:
    """Build bounded summary pages so colored table cells cannot bleed across pages."""
    findings = ctx.get("findings") or []
    fs = ctx.get("finding_summary") or {}
    chunks = [findings[i:i + per_page] for i in range(0, len(findings), per_page)] or [[]]
    pages: list[str] = []
    for page_idx, chunk in enumerate(chunks):
        title = "4. SUMMARY OF VULNERABILITY ASSESSMENT" + (" (CONTINUED)" if page_idx else "")
        body = [f"<h2 class='section'>{title}</h2>"]
        if page_idx == 0:
            labels = ("Critical", "High", "Medium", "Low", "Info", "Total")
            severity_bg = {"Critical": COLOR_CRITICAL, "High": COLOR_HIGH, "Medium": COLOR_MEDIUM,
                           "Low": COLOR_LOW, "Info": COLOR_INFO, "Total": "#ffffff"}
            severity_fg = {"Critical": "#ffffff", "High": "#ffffff", "Medium": "#000000",
                           "Low": "#000000", "Info": "#ffffff", "Total": "#000000"}
            body.append("<table class='sev'><colgroup>" + "".join("<col style='width:87px'/>" for _ in labels)
                        + "</colgroup><tbody><tr>" + "".join(
                            f"<th bgcolor='#eeeeee' style='background-color:#eeeeee'>{x}</th>" for x in labels
                        ) + "</tr><tr>")
            body.extend(
                f"<td class='sev-{key.lower()}' bgcolor='{severity_bg[key]}' "
                f"style='background-color:{severity_bg[key]};color:{severity_fg[key]}'>{_esc(fs.get(key, 0))}</td>"
                for key in labels[:-1]
            )
            body.append(f"<td class='sev-total'>{_esc(fs.get('total', len(findings)))}</td></tr></tbody></table>")
            if fs.get("actionable") is not None:
                body.append(f"<p class='body'><strong>Actionable findings:</strong> {_esc(fs.get('actionable'))} &nbsp; | &nbsp; "
                            f"<strong>Informational observations:</strong> {_esc(fs.get('informational', fs.get('Info', 0)))}</p>")
        rows = []
        for idx, f in enumerate(chunk, start=page_idx * per_page + 1):
            risk = f.get("risk", "")
            bg = _RISK_BG.get(risk, "#808080")
            fg = "#000000" if risk in {"Medium", "Low"} else "#ffffff"
            rows.append(f"<tr><td class='srno'>{idx}</td><td class='risk-cell' bgcolor='{bg}' style='background-color:{bg};color:{fg}'>"
                        f"{_esc(str(risk).upper())}</td><td><strong>{_esc(f.get('name', ''))}</strong></td></tr>")
        body.append("<table class='summary'><colgroup><col style='width:70px'/><col style='width:120px'/><col style='width:335px'/></colgroup>"
                    "<thead><tr><th bgcolor='#d9d9d9' style='background-color:#d9d9d9'>Sr No.</th>"
                    "<th bgcolor='#d9d9d9' style='background-color:#d9d9d9'>Risk</th>"
                    "<th bgcolor='#d9d9d9' style='background-color:#d9d9d9'>Name</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
        if page_idx == len(chunks) - 1 and findings:
            body.append("<p class='body'><strong>NOTES:</strong> Kindly implement the changes mentioned in the solution set attached with the "
                        "Vulnerability Assessment Report. The changes will help you enhance your security posture.</p>")
        pages.append("".join(body))
    return [_fb_doc(page) for page in pages]


def build_fallback_observation_pages(ctx: dict[str, Any]) -> list[str]:
    """Render one complete finding table per Story/page to keep its borders closed."""
    findings = ctx.get("findings") or []
    desc_fn = ctx.get("_finding_description") or (lambda f: f.get("description") or f.get("name") or "")
    impact_fn = ctx.get("_impact_text") or (lambda f: "")
    mit_fn = ctx.get("_mitigation_text") or (lambda f: f.get("remediation") or "")
    if not findings:
        return [_fb_doc("<h2 class='section'>5. VULNERABILITY OBSERVATION</h2><p class='body'><em>No observations recorded for this case.</em></p>")]
    pages = []
    for idx, f in enumerate(findings):
        title = "5. VULNERABILITY OBSERVATION" if idx == 0 else "5. VULNERABILITY OBSERVATION (CONTINUED)"
        host_list = f.get("hosts") or []
        hosts = ", ".join(host_list[:OBS_MAX_HOSTS_SHOWN]) if host_list else "Not specified"
        if len(host_list) > OBS_MAX_HOSTS_SHOWN:
            hosts += f" (+{len(host_list) - OBS_MAX_HOSTS_SHOWN} more)"
        risk = f.get("risk", "")
        bg = _RISK_BG.get(risk, "#808080")
        fg = "#000000" if risk in {"Medium", "Low"} else "#ffffff"
        body = [f"<h2 class='section'>{title}</h2>"]
        if idx == 0:
            body.append("<p class='body'>List of all identified vulnerabilities (excluding informational observations).</p>")
        body.append(f"<p class='obs-name'>&#9632; {_esc(f.get('name', ''))}</p>")
        body.append("<table class='kv'><colgroup><col style='width:130px'/><col style='width:395px'/></colgroup><tbody>"
                    f"<tr><th>Risk</th><td class='risk-cell' bgcolor='{bg}' style='background-color:{bg};color:{fg}'>{_esc(risk)}</td></tr>"
                    f"<tr><th>IP address</th><td>{_esc(hosts)}</td></tr>"
                    f"<tr><th>Description</th><td>{_esc(desc_fn(f))}</td></tr>"
                    f"<tr><th>Impact</th><td>{_esc(impact_fn(f))}</td></tr>"
                    f"<tr><th>Mitigation</th><td>{_esc(mit_fn(f))}</td></tr></tbody></table>")
        pages.append(_fb_doc("".join(body)))
    return pages


def build_fallback_report_html(ctx: dict[str, Any]) -> str:
    """Single-document fallback HTML (cover, doc control, TOC, then sections 1-6).

    Used when section-by-section rendering is unavailable; the sectioned renderer
    in render_gap_pdf is preferred because it puts each section on its own page.
    """
    b = _fallback_section_bodies(ctx)
    page_map = {key: i for i, key in enumerate(("intro", "overview", "infra"), start=4)}
    summary_pages = build_fallback_summary_pages(ctx)
    observation_pages = build_fallback_observation_pages(ctx)
    page_map["summary"] = 6
    page_map["observation"] = 6 + len(summary_pages)
    page_map["contacts"] = page_map["observation"] + len(observation_pages)
    toc_body = _fallback_toc_body(page_map)
    body = b["cover"] + b["docctrl"] + toc_body + b["intro"] + b["overview"] + b["infra"]
    body += "".join(f"<div style='page-break-before:always'>{page}</div>" for page in summary_pages)
    body += "".join(f"<div style='page-break-before:always'>{page}</div>" for page in observation_pages)
    body += b["contacts"]
    return _fb_doc(body)


def build_styled_gap_report_html(ctx: dict[str, Any], *, include_cover: bool = True) -> str:
    site = ctx["site"]
    client = ctx["client"]
    findings = ctx["findings"]
    author = str(site.get("author") or "").strip()
    version = site.get("document_version", "1.0")
    company = rebrand_company(site.get("company_name") or REPORT_COMPANY)
    intro = ctx.get("intro") or ""
    report_date = ctx.get("report_date") or ""

    pages: list[str] = []
    page_no = 2 if not include_cover else 1

    if include_cover:
        pages.append(_cover_page(client, company, report_date))
        page_no = 2

    pages.append(
        _document_control_page(
            client=client,
            author=author,
            version=version,
            report_date=report_date,
            department=str(site.get("department") or site.get("branch_locations") or ""),
            page_no=page_no,
        )
    )
    page_no += 1

    toc_page_no = page_no
    page_no += 1

    pages.append(
        _page_wrap(
            _intro_paragraphs(intro),
            page_no,
            section_bars=["1. INTRODUCTION"],
        )
    )
    page_no += 1

    site_overview_html = _site_overview_reference_body(site, client, report_date)
    site_infra_html = _site_infrastructure_reference_body(site)
    site_body = site_overview_html + _section_bar("3. SITE INFRASTRUCTURE") + site_infra_html

    pages.append(
        _page_wrap(
            site_body,
            page_no,
            section_bars=["2. SITE OVERVIEW"],
        )
    )
    page_no += 1

    summary_bodies = _summary_pages(findings, ctx.get("finding_summary"))
    for i, summary_body in enumerate(summary_bodies):
        title = (
            "4. SUMMARY OF VULNERABILITY ASSESSMENT"
            if i == 0
            else "4. SUMMARY OF VULNERABILITY ASSESSMENT (CONTINUED)"
        )
        pages.append(_page_wrap(summary_body, page_no, section_bars=[title]))
        page_no += 1

    for body, section, flow in _finding_details_pages(findings, ctx):
        pages.append(_page_wrap(body, page_no, section_bars=section, flow=flow))
        page_no += 1

    contacts = site.get("key_contacts") or []
    pages.append(
        _page_wrap(
            _contacts_html(contacts),
            page_no,
            section_bars=["6. KEY CONTACTS"],
            page_break_after=False,
        )
    )
    page_no += 1

    # V1.10.7: the "Service Coverage and Limitations" section is no longer part of
    # the report; per-host service coverage stays available as the separate
    # "Service coverage CSV" export on the Reports page.

    toc_html = _toc_page(toc_page_no, _compute_toc_page_map(findings_count=len(findings), findings=findings, ctx=ctx))
    pages.insert(1 if not include_cover else 2, toc_html)

    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<!-- gap-report-template-v3-data-quality -->"
        f"<title>Gap Assessment Report — {_esc(client)}</title>"
        f"<style>{GAP_REPORT_CSS}</style></head><body>"
        f"{''.join(pages)}"
        "</body></html>"
    )
