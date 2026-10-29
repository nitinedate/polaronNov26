from __future__ import annotations


def test_evidence_path_platform_detection_prefers_strong_android_markers():
    from app.services.mobile_platform_agents import detect_mobile_platform_from_evidence_paths

    paths = [
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/storage/emulated/0/WhatsApp/Databases/msgstore.db.crypt14",
        "/data/system/packages.xml",
    ]
    assert detect_mobile_platform_from_evidence_paths(paths) == "android"


def test_evidence_path_platform_detection_prefers_strong_ios_markers():
    from app.services.mobile_platform_agents import detect_mobile_platform_from_evidence_paths

    paths = [
        "/private/var/mobile/Containers/Shared/AppGroup/WhatsApp/ChatStorage.sqlite",
        "/MobileSync/Backup/ABC/Manifest.db",
        "/private/var/mobile/Library/SMS/sms.db",
    ]
    assert detect_mobile_platform_from_evidence_paths(paths) == "ios"


def test_conflicting_platform_markers_do_not_guess():
    from app.services.mobile_platform_agents import detect_mobile_platform_from_evidence_paths

    assert detect_mobile_platform_from_evidence_paths([
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/private/var/mobile/WhatsApp/ChatStorage.sqlite",
    ]) is None


def test_mobile_report_order_contains_evidence_details_after_extraction_summary():
    from app.services.report_renderer import MOBILE_SECTION_ORDER

    assert "evidence_details" in MOBILE_SECTION_ORDER
    assert MOBILE_SECTION_ORDER.index("evidence_details") == MOBILE_SECTION_ORDER.index("extraction_summary") + 1


def test_mobile_evidence_details_contains_hash_and_platform(monkeypatch):
    from app.services import mobile_report_service as svc

    monkeypatch.setattr(svc, "fetchone", lambda *a, **k: {
        "type": "android_mobile",
        "files_extracted": 42,
        "disk_source": {
            "evidence_platform": "Android",
            "acquisition_mode": "import",
            "evidence_source_id": "SRC-1",
        },
    })
    monkeypatch.setattr(svc, "_fetch_evidence_segments", lambda *a, **k: [
        {"original_name": "phone.ufd", "size_bytes": 1024 * 1024, "sha256": "abc123"}
    ])
    md = svc.gather_mobile_evidence_details_markdown(object(), "job-1", {"chain_of_custody_ref": "COC-9"})
    assert "EVIDENCE DETAILS" in md
    assert "Android" in md
    assert "phone.ufd" in md
    assert "abc123" in md
    assert "COC-9" in md


def test_video_quality_bucket_can_prepare_poor_frames(monkeypatch):
    from PIL import Image
    import io
    from app.services import forensic_media_review as media
    from app.services import ocr_gpu

    frame = Image.new("RGB", (640, 480), "white")
    buf = io.BytesIO()
    frame.save(buf, format="JPEG")
    blob = buf.getvalue()

    monkeypatch.setattr(media, "video_frames", lambda path: iter([
        (blob, {"timestamp_seconds": 1.5}, {"sampled": True})
    ]))
    monkeypatch.setattr(media, "media_needs_ocr", lambda source: (True, 10.0))
    monkeypatch.setattr(ocr_gpu, "_raster_needs_actual_ocr", lambda img: True)

    result = ocr_gpu.cpu_prepare_ocr_item(b"dummy-video", path="/evidence/poor.mp4", allow_photos=True)
    assert result["status"] == "needs_gpu"
    assert result["engine"] == "glm-ocr-video"
    assert result["segments"][0]["video_timestamp_seconds"] == 1.5


def test_quality_bucket_is_part_of_ocr_keep_policy():
    from app.services.ocr_gpu import _ocr_eligible_keep_sql

    sql = _ocr_eligible_keep_sql()
    assert "ocr_quality_bucket" in sql


def test_ocr_empty_bucket_reports_100_percent(monkeypatch):
    from app.services import ocr_gpu
    from app.services import pipeline_progress

    captured = {}
    monkeypatch.setattr(ocr_gpu, "count_pending_ocr", lambda db, job_id: 0)
    monkeypatch.setattr(ocr_gpu, "fetchone", lambda *a, **k: {"c": 0})
    monkeypatch.setattr(pipeline_progress, "write_merged_pipeline_progress", lambda db, job_id, patch, writer: captured.update(patch))
    ocr_gpu.write_ocr_live_progress(object(), "job-1")
    assert captured["completed"] == 1
    assert captured["total"] == 1
    assert "100%" in captured["label"]


def test_ocr_progress_reopens_when_new_bucket_items_arrive(monkeypatch):
    from app.services import ocr_gpu
    from app.services import pipeline_progress

    captured = {}
    monkeypatch.setattr(ocr_gpu, "count_pending_ocr", lambda db, job_id: 5)
    monkeypatch.setattr(ocr_gpu, "fetchone", lambda *a, **k: {"c": 10})
    monkeypatch.setattr(pipeline_progress, "write_merged_pipeline_progress", lambda db, job_id, patch, writer: captured.update(patch))
    ocr_gpu.write_ocr_live_progress(object(), "job-1")
    assert captured["completed"] == 10
    assert captured["total"] == 15


def test_mobile_exports_show_evidence_details_page():
    import io
    from zipfile import ZipFile

    from app.services.report_docx_export import build_report_docx
    from app.services.report_pdf_export import build_report_pdf

    sections = [
        {"section_key": "cover_page", "content_md": "## MOBILE FORENSIC ANALYSIS REPORT\n\n**Fixture Phone**"},
        {"section_key": "evidence_details", "content_md": "## EVIDENCE DETAILS\n\n| Field | Value |\n| --- | --- |\n| Mobile platform | Android |"},
    ]
    order = ["cover_page", "evidence_details"]
    docx = build_report_docx(sections, order=order, mobile=True)
    with ZipFile(io.BytesIO(docx)) as archive:
        xml = archive.read("word/document.xml").decode("utf-8", "ignore")
        assert "EVIDENCE DETAILS" in xml
        assert "Android" in xml

    pdf = build_report_pdf(sections, order=order, mobile=True)
    import fitz

    doc = fitz.open(stream=pdf, filetype="pdf")
    text = "\n".join(page.get_text() for page in doc)
    assert "EVIDENCE DETAILS" in text
    assert "Android" in text
