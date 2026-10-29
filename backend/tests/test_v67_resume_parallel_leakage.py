from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_company_leakage_classifies_shared_confidential_document(monkeypatch):
    from app.services.company_leakage import _classify
    monkeypatch.setenv("COMPANY_LEAKAGE_MIN_SCORE", "55")
    result = _classify(
        "POLARON TECHNOLOGIES - CONFIDENTIAL customer list and pricing strategy. Do not distribute.",
        path=r"Users\\Nitin\\WhatsApp\\Media\\Documents\\sent\\customer-list.pdf",
        company_terms=["Polaron Technologies"],
    )
    assert result is not None
    assert result["channel"] == "whatsapp"
    assert result["risk_score"] >= 55
    assert "confidential_marking" in result["categories"]


def test_company_leakage_neutral_picture_text_is_not_flagged(monkeypatch):
    from app.services.company_leakage import _classify
    monkeypatch.setenv("COMPANY_LEAKAGE_MIN_SCORE", "55")
    assert _classify(
        "Birthday dinner photo 2026 with friends",
        path=r"DCIM\\Camera\\IMG_0001.jpg",
        company_terms=["Polaron Technologies"],
    ) is None


def test_direction_marks_sent_material_outgoing():
    from app.services.company_leakage import _direction
    assert _direction(r"Mail\\Sent Items\\proposal.pdf", {}) == "outgoing"
    assert _direction(r"WhatsApp\\Media\\Documents\\file.pdf", {"direction": "outgoing"}) == "outgoing"



def test_outgoing_chat_attachment_strengthens_leak_candidate(monkeypatch):
    from app.services.company_leakage import _classify
    monkeypatch.setenv("COMPANY_LEAKAGE_MIN_SCORE", "55")
    result = _classify(
        "CONFIDENTIAL architecture diagram",
        path=r"Media\diagram.png",
        company_terms=[],
        channel_hint="whatsapp",
        direction_hint="outgoing",
    )
    assert result is not None
    assert result["channel"] == "whatsapp"
    assert result["direction"] == "outgoing"


def test_restart_recovery_resets_stale_sidecars_and_keeps_checkpoints():
    src = (ROOT / "backend/app/services/restart_resume.py").read_text(encoding="utf-8")
    assert "pipeline_sidecar_runs" in src
    assert "status='pending'" in src
    assert "pipeline_work_items" in src
    assert "parse_status='pending'" in src
    # Recovery must not delete OCR/chunk results.
    assert "DELETE FROM ocr_results" not in src
    assert "DELETE FROM rag_chunks" not in src


def test_ocr_cuda_is_quality_bucket_only():
    src = (ROOT / "backend/app/services/ocr_gpu.py").read_text(encoding="utf-8")
    assert 'OCR_PENDING_CANDIDATE_SQL = f"({OCR_QUALITY_BUCKET_SQL})"' in src
    assert "CUDA OCR is the poor-quality bucket" in src


def test_parallel_scheduler_runs_only_safe_cpu_db_sidecars():
    src = (ROOT / "backend/app/services/safe_parallel.py").read_text(encoding="utf-8")
    assert "prechunk" in src
    assert "company_leakage" in src
    assert "artifact_inventory" in src
    assert "active_stage not in {'recovery','ocr','media_review'}" in src
    assert "media_review_sidecar" not in src


def test_artifact_indexes_cover_browse_ocr_and_leakage():
    src = (ROOT / "backend/app/services/evidence_browse_indexes.py").read_text(encoding="utf-8")
    for name in (
        "ix_job_artifacts_job_ext_id",
        "ix_job_artifacts_job_ocr_status_id",
        "ix_job_artifacts_quality_unchecked",
        "ix_job_artifacts_company_leakage",
    ):
        assert name in src
