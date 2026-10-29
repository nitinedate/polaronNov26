from app.services.scanner_agent_jobs import agent_build_label


def test_recent_agent_build_not_legacy():
    assert agent_build_label('1.5.9+v47.2') == 'v47.2'
    assert agent_build_label('agent 1.5.9 + V47.2') == 'v47.2'
    assert agent_build_label('v45.4') == 'v45.4'


def test_missing_build_not_claimed_legacy():
    assert agent_build_label('1.5.9') == 'build unreported'
    assert agent_build_label('') == 'unknown'
    assert agent_build_label('1.5.3+v44.9') == 'legacy (pre-v45.4)'


def test_historical_job_progress_does_not_repeat_stale_legacy_label():
    from app.services.scan_orchestrator import scan_job_progress
    job = {
        "status": "completed",
        "orchestration_json": {
            "edge_agent": True,
            "degraded_hosts": ["192.0.2.5"],
            "edge_agent_version": "1.5.9-v47.2",
            "edge_agent_build": "legacy (pre-V45.4)",
        },
    }
    progress = scan_job_progress(None, job)
    assert "1 host(s) incomplete" in progress["progress_label"]
    assert "v47.2" in progress["progress_label"]
    assert "legacy" not in progress["progress_label"]
