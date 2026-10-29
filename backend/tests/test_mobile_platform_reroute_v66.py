from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_verified_platform_overwrites_stale_labels():
    from app.services.mobile_platform_agents import persist_owner_on_disk_source
    ds = persist_owner_on_disk_source(
        {
            'owner_agent': 'androidagent',
            'mobile_os': 'android',
            'axiom_platform': 'Android',
            'evidence_platform': 'Android',
        },
        'ios',
    )
    assert ds['owner_agent'] == 'iosagent'
    assert ds['mobile_os'] == 'ios'
    assert ds['axiom_platform'] == 'iOS'
    assert ds['evidence_platform'] == 'iOS'


def test_iphone_filename_detects_ios():
    from app.services.mobile_platform_agents import detect_mobile_platform
    assert detect_mobile_platform('CASE-20261005-APPLEIPHON_E-800028_Y22_FFS.zip') == 'ios'


def test_mobile_dispatch_uses_explicit_verified_queue():
    text = (ROOT / 'backend/app/routers/jobs.py').read_text(encoding='utf-8')
    assert 'extract_queue_for_job(db, job_id)' in text
    assert 'task.apply_async(args=(schema, job_id), queue=queue)' in text


def test_wrong_worker_self_heals_to_other_platform_queue():
    text = (ROOT / 'backend/app/tasks.py').read_text(encoding='utf-8')
    assert 'target_queue = "ios-build" if exc.platform == "ios" else "android-build"' in text
    assert 'queue=target_queue' in text
