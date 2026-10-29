"""Focused source contracts for the two forensic processing profiles."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_mode_is_saved_before_background_queue():
    s = (ROOT / 'backend/app/routers/jobs.py').read_text()
    fn = s[s.index('def ingest_host_path('):s.index('@router.', s.index('def ingest_host_path(')+1)]
    assert fn.index('processing_profile') < fn.index('processing_queued = False')
    # 2026-10-22: the atomic jsonb_set moved into processing_profile.set_job_processing_profile.
    assert 'set_job_processing_profile(db, job_id, profile)' in fn
    svc = (ROOT / 'backend/app/services/processing_profile.py').read_text()
    assert 'jsonb_set' in svc[svc.index('def set_job_processing_profile('):]

def test_extraction_uses_selected_mode_on_every_filter_pass():
    s = (ROOT / 'backend/app/services/extracted_disk.py').read_text()
    # V2026-10-21: Standard has its own extraction mode (was "defensible", which
    # on Windows extracted nearly the same file set as Deep).
    assert '"standard": "standard", "deep": "full"' in s
    assert s.count('_filter_nodes(all_nodes, settings, os_info=os_info, mode_override=mode)') == 2
    assert 'merged["processing_profile"] = prior["processing_profile"]' in s

def test_signature_carve_not_mandatory_in_standard():
    s = (ROOT / 'backend/app/services/catalog_artifact_runner.py').read_text()
    assert 'do_signature_carve = processing_profile != "standard"' in s
    assert 'if not mobile_job and do_signature_carve:' in s
    assert 'if processing_profile != "standard":\n            ensure_signature_carve_inventory' in s

def test_frontend_offers_only_two_profiles():
    s = (ROOT / 'frontend/src/components/forensic/HostEvidencePanel.tsx').read_text()
    assert 'Standard forensic' in s and 'Deep examination' in s
    # 2026-10-22: the current choice is read from a ref (stale-closure fix).
    assert s.count('processing_profile: processingProfileRef.current,') == 2


def test_standard_extraction_enables_vendor_tree_exclusion_per_job():
    s = (ROOT / 'backend/app/services/extracted_disk.py').read_text()
    assert 'standard_mode = mode == "standard"' in s
    assert 'classify_os_vendor_standard(rel, size_bytes=size, os_family=family)' in s
    f = (ROOT / 'backend/app/services/extract_filters.py').read_text()
    assert 'def standard_vendor_asset_rule(' in f
    assert 'if mode_l == "standard":' in f


def test_standard_skips_graph_and_entity_regex_but_deep_keeps_them():
    s = (ROOT / 'backend/app/services/forensic_serial_stages.py').read_text()
    graph = s[s.index('    if stage == "graph":'):s.index('    if stage == "validation":')]
    assert 'STANDARD_SKIPPED_STAGES["graph"]' in graph and '"status": "skipped"' in graph
    assert 'sync_job_graph_serial' in graph  # Deep path retained
    assert '"entity_statistics": "not computed (Standard profile)"' in s
    assert 'schedule_disk_vectors' in s  # Deep path retained


def test_vector_barrier_is_deep_only_and_standard_limitations_recorded():
    s = (ROOT / 'backend/app/services/forensic_serial_stages.py').read_text()
    assert 'profile != "standard" and get_settings().rag_embedding_enabled' in s
    assert 'result["profile_limitations"] = list(STANDARD_LIMITATIONS)' in s


def test_standard_media_review_is_user_space_and_counts_stay_in_scope():
    s = (ROOT / 'backend/app/services/forensic_media_review.py').read_text()
    assert 'predicate = f"({predicate}) AND {USER_SPACE_PATH_SQL}"' in s
    assert 'job_artifact_id IN (SELECT id FROM job_artifacts WHERE job_id=:jid AND {predicate})' in s
    assert '"out_of_scope_vendor_media": out_of_scope' in s


def test_legacy_jobs_behave_as_deep():
    import sys
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.services.processing_profile import profile_from_disk_source
    assert profile_from_disk_source({}) == 'legacy'
    assert profile_from_disk_source('{"processing_profile": "standard"}') == 'standard'
    assert profile_from_disk_source({"processing_profile": "DEEP"}) == 'deep'
    assert profile_from_disk_source({"processing_profile": "turbo"}) == 'legacy'


def test_user_space_media_predicate():
    import sys
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.services.processing_profile import is_user_space_path
    assert is_user_space_path('Users/alice/Pictures/a.jpg')
    assert is_user_space_path('$Recycle.Bin/S-1-5-21/$RABC.png')
    assert is_user_space_path('Data/exports/photo.png')  # non-OS volume roots stay in scope
    assert not is_user_space_path('Windows/Web/Wallpaper/Windows/img0.jpg')
    assert not is_user_space_path('Program Files/WindowsApps/App/Assets/logo.png')
    assert not is_user_space_path('ProgramData/Microsoft/Windows/SystemData/x.jpg')
