"""V1.10.7: Polaron branding (name + logo) and no Service Coverage section in gap reports."""
from __future__ import annotations

import io

import pytest

import app.services.gap_assessment_report as gap
from app.services import gap_report_template as tpl

OLD_NAMES = ["AETHERIS TECHNOLOGIES PVT LTD.", "Aetheris Technologies Pvt Ltd", "AETHERIS TECHNOLOGIES PVT. LTD.",
             "aetheris technologies pvt. ltd"]


@pytest.mark.parametrize("old", OLD_NAMES)
def test_whole_value_becomes_the_new_name(old):
    assert tpl.rebrand_company(old) == "Polaron Technologies Pvt Ltd"


def test_names_inside_text_keep_sentence_punctuation():
    intro = "conducted by AETHERIS TECHNOLOGIES PVT LTD. on IP's as per project scope."
    assert tpl.rebrand_company(intro) == "conducted by Polaron Technologies Pvt Ltd on IP's as per project scope."
    end = "This assessment was performed by Aetheris Technologies Pvt Ltd. The scope follows."
    assert tpl.rebrand_company(end) == "This assessment was performed by Polaron Technologies Pvt Ltd. The scope follows."
    # unrelated text (e-mail addresses, other words) is untouched
    assert tpl.rebrand_company("nitin@aetheris.in") == "nitin@aetheris.in"
    assert tpl.rebrand_company(None) is None and tpl.rebrand_company(5) == 5


def test_default_intro_and_saved_overviews_use_the_new_name(monkeypatch):
    assert "Polaron Technologies Pvt Ltd" in gap.DEFAULT_GAP_INTRO and "AETHERIS" not in gap.DEFAULT_GAP_INTRO
    monkeypatch.setattr(gap, "ensure_gap_site_column", lambda db: None)
    monkeypatch.setattr(gap, "load_case_row", lambda db, cid: {
        "id": cid, "title": "RRP", "gap_site_json": {
            "company_name": "AETHERIS TECHNOLOGIES PVT LTD",
            "introduction": "Assessment conducted by AETHERIS TECHNOLOGIES PVT LTD. on IP's as per project scope.",
            "client_name": "RRP Electronics"}})
    site = gap.load_gap_site(object(), "c1")
    assert site["company_name"] == "Polaron Technologies Pvt Ltd"
    assert site["introduction"].startswith("Assessment conducted by Polaron Technologies Pvt Ltd on IP's")
    monkeypatch.setattr(gap, "load_case_row", lambda db, cid: {"id": cid, "title": "RRP", "gap_site_json": {}})
    assert gap.load_gap_site(object(), "c2")["company_name"] == "Polaron Technologies Pvt Ltd"


def _ctx(company="Aetheris Technologies Pvt Ltd"):
    return {"client": "RRP Electronics", "findings": [], "intro": "Intro text", "report_date": "16-10-2026",
            "assessment": {"verified": True},
            "site": {"company_name": company, "author": "Bhagyesh Sawant"},
            "service_coverage_jobs": [{"job_id": "j1", "status": "completed", "service_coverage": {"10.0.0.1": {}},
                                       "policy_snapshots": {}}]}


def test_html_cover_uses_polaron_name_and_logo_and_has_no_coverage_section():
    html_doc = tpl.build_styled_gap_report_html(_ctx(), include_cover=True)
    flat = html_doc.replace("\xa0", " ")
    assert "Polaron Technologies Pvt Ltd" in flat
    assert "Aetheris Technologies" not in flat and "AETHERIS TECHNOLOGIES" not in flat
    assert 'class="cover-logo"' in html_doc and 'alt="Polaron Technologies Pvt Ltd"' in html_doc
    assert "SERVICE COVERAGE AND LIMITATIONS" not in flat.upper()
    assert "Service Coverage and Limitations" not in flat


def test_logo_asset_is_the_polaron_logo():
    path = tpl._cover_asset_path(tpl.REPORT_LOGO_FILE)
    assert path is not None and path.name == "polaron_logo.png"
    from PIL import Image

    with Image.open(path) as im:
        w, h = im.size
    assert w > 2 * h  # wide Polaron wordmark, not the old square Aetheris badge


def test_pdf_cover_draws_the_new_company_line():
    fitz = pytest.importorskip("fitz")
    pdf = tpl.render_gap_cover_pdf("RRP Electronics", "AETHERIS TECHNOLOGIES PVT LTD", "16-10-2026")
    assert pdf and fitz.open(stream=pdf, filetype="pdf").page_count == 1


def test_docx_has_logo_new_name_and_no_coverage_section():
    docx = pytest.importorskip("docx")
    data = gap.render_gap_docx(_ctx("AETHERIS TECHNOLOGIES PVT. LTD."))
    doc = docx.Document(io.BytesIO(data))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Polaron Technologies Pvt Ltd" in text
    assert "AETHERIS TECHNOLOGIES" not in text.upper()  # contact e-mails are data and stay as entered
    assert "Service Coverage and Limitations" not in text
    assert len(doc.inline_shapes) == 1  # the logo on the cover


def test_llm_prompt_names_polaron():
    from app.services import gap_report_llm

    assert "Polaron Technologies Pvt Ltd" in gap_report_llm._SYSTEM_PROMPT
    assert "Aetheris" not in gap_report_llm._SYSTEM_PROMPT
