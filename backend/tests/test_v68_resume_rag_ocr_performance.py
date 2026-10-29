from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_registered_jobs_are_supervised_and_restart_recovered():
    progress = (ROOT / 'backend/app/services/progress_agent.py').read_text(encoding='utf-8')
    restart = (ROOT / 'backend/app/services/restart_resume.py').read_text(encoding='utf-8')
    supervisor = (ROOT / 'backend/app/services/pipeline_supervisor.py').read_text(encoding='utf-8')
    assert "status='registered' AND EXISTS(SELECT 1 FROM evidence_files" in progress
    assert "status='registered' AND EXISTS(SELECT 1 FROM evidence_files" in restart
    assert 'Registered evidence is ready but extraction has no active owner' in supervisor
    assert 'Registered evidence manifest is complete but no extraction worker owns the job' in progress


def test_supervisor_mobile_recovery_routes_explicit_platform_queue():
    src = (ROOT / 'backend/app/services/pipeline_supervisor.py').read_text(encoding='utf-8')
    assert 'reconcile_mobile_platform_from_registered_evidence' in src
    assert 'extract_queue_for_job' in src
    assert 'build_extracted_mobile_task.apply_async' in src


def test_server_local_mobile_intake_preserves_mobile_domain():
    src = (ROOT / 'backend/app/services/host_evidence.py').read_text(encoding='utf-8')
    assert 'registered_mobile = source_type == "mobile"' in src
    assert '"mobile" if registered_mobile else "disk"' in src
    assert 'if not registered_mobile:' in src


def test_native_text_rejects_clear_documents_before_ocr():
    from app.services.mobile_quality_ocr import _normalized_text_is_usable
    assert _normalized_text_is_usable({'text': 'Quarterly internal report ' * 20}) is True
    assert _normalized_text_is_usable({'text': 'x'}) is False
    src = (ROOT / 'backend/app/services/mobile_quality_ocr.py').read_text(encoding='utf-8')
    assert 'native_text_readable' in src
    assert "coalesce(ja.ocr_status,'') <> 'done'" in src
    assert 'poor_count >= required' in src


def test_rag_fast_path_uses_larger_gpu_batches_and_less_duplicate_work():
    env = (ROOT / '.env').read_text(encoding='utf-8')
    assert 'RAG_BATCH_SIZE=64' in env
    assert 'RAG_BATCH_SIZE_CAP=64' in env
    assert 'RAG_DB_FETCH_BATCH=3000' in env
    assert 'RAG_CPU_PREP_WORKERS=6' in env
    assert 'RAG_FP16=true' in env
    assert 'RAG_CONTENT_DEDUP=true' in env
    assert 'RAG_VECTOR_CACHE_ITEMS=20000' in env
    assert 'RAG_CHUNK_DB_BATCH=6000' in env
    assert 'RAG_CHUNK_SIZE=3200' in env
    assert 'RAG_CHUNK_OVERLAP=240' in env
    src = (ROOT / 'backend/app/services/dual_rag_index.py').read_text(encoding='utf-8')
    assert 'duplicate = bool(nlow and (olow in nlow or nlow in olow))' in src
    assert 'seen_chunks' in src


def test_rag_gpu_policy_uses_64_batch_on_12gb_class_gpu():
    src = (ROOT / 'backend/app/services/perf_policy.py').read_text(encoding='utf-8')
    assert 'if vram_total >= 11000:' in src
    assert 'hw_rag_ceiling = 64' in src


def test_parallel_leakage_can_overlap_recovery_without_cuda():
    src = (ROOT / 'backend/app/services/safe_parallel.py').read_text(encoding='utf-8')
    assert "if active_stage in {'recovery','ocr'}:" in src
    assert "claim_sidecar(db,job_id,'company_leakage'" in src


def test_v68_artifact_and_rag_hot_indexes_exist():
    src = (ROOT / 'backend/app/services/evidence_browse_indexes.py').read_text(encoding='utf-8')
    for name in ('ix_job_artifacts_job_parse_status_id','ix_job_artifacts_job_stage_status_id','ix_job_artifacts_rag_ready'):
        assert name in src
    migration = (ROOT / 'migrations/039_firm_pipeline_rag_artifact_performance.sql').read_text(encoding='utf-8')
    assert 'ix_rag_chunks_job_path_type_idx' in migration


def test_registered_manifest_reconciles_platform_before_progress_ownership():
    src = (ROOT / 'backend/app/services/progress_agent.py').read_text(encoding='utf-8')
    assert "if str(row.get('status') or '') == 'registered':" in src
    assert 'reconcile_mobile_platform_from_registered_evidence' in src
    assert 'SELECT id,type,disk_source,status,error,updated_at FROM jobs' in src


def test_system_pause_can_resume_but_user_pause_remains_held():
    progress = (ROOT / 'backend/app/services/progress_agent.py').read_text(encoding='utf-8')
    restart = (ROOT / 'backend/app/services/restart_resume.py').read_text(encoding='utf-8')
    assert '_is_auto_resumable_pause' in progress
    assert 'Paused by user — stop request is active' in progress
    assert '_is_auto_resumable_pause' in restart


def test_resume_dispatch_sets_task_id_and_visible_virtual_disk_owner():
    src = (ROOT / 'backend/app/services/pipeline_supervisor.py').read_text(encoding='utf-8')
    assert 'set_celery_task_id(db, job_id, async_result.id)' in src
    assert "mark_pipeline_agent_running(" in src
    assert "'virtual_disk_agent'" in src


def test_prechunk_uses_searchable_projection_and_dedupes_ocr():
    src = (ROOT / 'backend/app/services/prechunk.py').read_text(encoding='utf-8')
    assert '_extract_text_from_normalized' in src
    assert 'if o in b or b in o:' in src
    assert 'seen_chunks' in src


def test_fp16_and_five_second_watchdog_are_enabled():
    embed = (ROOT / 'backend/app/services/embedding_gpu.py').read_text(encoding='utf-8')
    env = (ROOT / '.env').read_text(encoding='utf-8')
    assert "os.environ.get('RAG_FP16', 'true')" in embed
    assert '_model.half()' in embed
    assert 'PROGRESS_AGENT_INTERVAL_SECONDS=5' in env


def test_rag_unique_embedding_plan_preserves_all_rows_without_duplicate_cuda_work():
    from app.services.rag_text import unique_text_plan, expand_unique_values
    texts = ["same", "alpha", "same", "beta", "alpha"]
    unique, positions = unique_text_plan(texts)
    assert unique == ["same", "alpha", "beta"]
    vectors = [[1], [2], [3]]
    assert expand_unique_values(vectors, positions) == [[1], [2], [1], [3], [2]]


def test_resume_watchdog_and_ocr_bucket_hot_indexes_exist():
    progress = (ROOT / 'backend/app/services/progress_agent.py').read_text(encoding='utf-8')
    browse = (ROOT / 'backend/app/services/evidence_browse_indexes.py').read_text(encoding='utf-8')
    migration = (ROOT / 'migrations/042_resume_watchdog_rag_v68.sql').read_text(encoding='utf-8')
    assert 'ix_jobs_progress_watch' in progress and 'ix_jobs_progress_watch' in migration
    assert 'ix_job_artifacts_ocr_bucket_pending' in browse and 'ix_job_artifacts_ocr_bucket_pending' in migration
    assert 'ix_job_artifacts_rag_stable_pending' in browse and 'ix_job_artifacts_rag_stable_pending' in migration


def test_safe_parallel_has_resource_admission_control():
    src = (ROOT / 'backend/app/services/safe_parallel.py').read_text(encoding='utf-8')
    assert 'cpu_sidecar_headroom' in src
    assert 'SIDECAR_CPU_MAX_PCT' in src
    assert 'SIDECAR_MEMORY_MAX_PCT' in src
    assert 'deferred_for_resources' in src
