from pathlib import Path


def test_quality_triage_has_dedicated_routes():
    text = Path('app/celery_factory.py').read_text(encoding='utf-8')
    assert 'quality_ocr_triage_task' in text
    assert 'quality-triage' in text
    assert 'android-quality' in text or 'f"{prefix}-quality"' in text


def test_disk_and_mobile_have_quality_workers():
    root = Path('..')
    assert 'worker-quality:' in (root / 'docker-compose.yml').read_text(encoding='utf-8')
    assert 'quality-triage' in (root / 'docker-compose.yml').read_text(encoding='utf-8')
    assert 'worker-quality:' in (root / 'services/mobile-android/docker-compose.yml').read_text(encoding='utf-8')
    assert 'android-quality' in (root / 'services/mobile-android/docker-compose.yml').read_text(encoding='utf-8')
    assert 'worker-quality:' in (root / 'services/mobile-ios/docker-compose.yml').read_text(encoding='utf-8')
    assert 'ios-quality' in (root / 'services/mobile-ios/docker-compose.yml').read_text(encoding='utf-8')


def test_parse_fills_bucket_without_starting_gpu():
    text = Path('app/services/artifact_parse.py').read_text(encoding='utf-8')
    assert 'dispatch=False' in text
    assert 'quality_ocr_triage_task.delay' in text


def test_recovery_starts_gpu_ocr_sidecar():
    text = Path('app/services/forensic_serial_stages.py').read_text(encoding='utf-8')
    assert 'parallel_with' in text
    assert 'recovery' in text
    assert 'dispatch_ocr_agent(schema, job_id)' in text


def test_ocr_worker_may_run_while_recovery_is_authoritative():
    text = Path('app/tasks.py').read_text(encoding='utf-8')
    # V1.11.0 widened the overlap: OCR may also run while artifacts are registered.
    assert "stage IN ('materialize','parse','recovery')" in text
    assert 'if not parallel_recovery:' in text


def test_ui_snapshot_exposes_sidecar_ocr_running_and_done():
    from app.services.forensic_serial_pipeline import snapshot_from_rows

    rows = []
    for seq, stage in enumerate([
        'intake','source_prepare','extraction','materialize','parse','recovery','ocr',
        'media_review','inventory','chunk','enrichment','graph','validation'
    ], 1):
        status = 'done' if seq <= 5 else ('running' if stage == 'recovery' else 'pending')
        details = {}
        if stage == 'ocr':
            details = {
                'parallel_active': True,
                'parallel_complete': False,
                'parallel_with': 'recovery',
                'parallel_completed': 20,
                'parallel_total': 100,
            }
        rows.append({'stage': stage, 'sequence_no': seq, 'status': status, 'total_items': 1,
                     'completed_items': 1 if status == 'done' else 0, 'failed_items': 0,
                     'skipped_items': 0, 'attempt': 0, 'details': details})
    snap = snapshot_from_rows(rows, {})
    ocr = next(s for s in snap['stages'] if s['id'] == 'ocr')
    assert ocr['status'] == 'running'
    assert ocr['pct'] == 20
