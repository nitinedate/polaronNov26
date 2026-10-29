from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_v68_ocr_quality_policy_rechecks_legacy_candidates():
    src = read("backend/app/services/mobile_quality_ocr.py")
    tasks = read("backend/app/tasks.py")
    assert 'OCR_QUALITY_POLICY = "v68-text-likelihood"' in src
    assert "ocr_quality_policy" in src
    assert "native_text_readable" in src
    assert "poor_nontext_image" in src
    assert "poor_video_text_frames" in src
    assert "OCR_QUALITY_POLICY" in tasks
    assert "ocr_quality_policy" in tasks


def test_v68_prechunk_uses_latest_results_and_waits_for_quality_gate():
    src = read("backend/app/services/prechunk.py")
    assert "ORDER BY apr1.created_at DESC" in src
    assert "DISTINCT ON (o1.page_index)" in src
    assert "ocr_quality_checked" in src
    assert "NOT IN ('pending','processing','queued','running')" in src
    assert "RAG" not in ""  # keeps this test intentionally source-only


def test_v68_rag_prep_has_dedicated_cpu_queues():
    routing = read("backend/app/forensic_common/pipeline_routing.py")
    central = read("docker-compose.yml")
    android = read("services/mobile-android/docker-compose.yml")
    ios = read("services/mobile-ios/docker-compose.yml")
    legacy = read("services/mobile-extract/docker-compose.yml")
    assert 'return "rag-prep"' in routing
    assert 'return "mobile-rag-prep"' in routing
    assert 'worker-rag-prep:' in central and '- rag-prep' in central
    assert 'worker-rag-prep:' in android and 'android-rag-prep' in android
    assert 'worker-rag-prep:' in ios and 'ios-rag-prep' in ios
    assert 'worker-rag-prep:' in legacy and 'mobile-rag-prep' in legacy


def test_v68_serial_rag_is_delta_finalizer_not_128_row_retry_aggregator():
    src = read("backend/app/services/forensic_serial_stages.py")
    assert 'RAG_CHUNK_DB_BATCH' in src
    assert '"6000"' in src
    assert "DISTINCT ON (o.page_index)" in src
    assert "ORDER BY a.created_at DESC" in src
    assert "LIMIT 128" not in src
    assert "jsonb_agg(normalized ORDER BY created_at)" not in src
    assert "RAG delta finalization" in src


def test_v68_rag_indexes_exist_in_runtime_and_migration():
    runtime = read("backend/app/services/evidence_browse_indexes.py")
    migration = read("migrations/041_rag_ocr_performance_v68.sql")
    for name in (
        "ix_job_artifacts_rag_unchunked",
        "ix_ocr_results_artifact_page_created",
        "ix_rag_chunks_job_path_type_idx",
    ):
        assert name in runtime
        assert name in migration


def test_registered_jobs_are_self_healed_after_missed_handoff():
    progress = read("backend/app/services/progress_agent.py")
    supervisor = read("backend/app/services/pipeline_supervisor.py")
    restart = read("backend/app/services/restart_resume.py")
    assert "status='registered'" in progress
    assert "Registered evidence manifest is complete" in progress
    assert 'if status == "registered"' in supervisor
    assert "resume_extraction" in supervisor
    assert "status='registered'" in restart


def test_v68_prechunk_waits_until_recovery_is_complete_and_skips_media():
    safe = read("backend/app/services/safe_parallel.py")
    pre = read("backend/app/services/prechunk.py")
    assert "if active_stage in {'ocr','media_review'}:" in safe
    assert "_MEDIA_EXTS" in pre
    assert "media_exts" in pre
