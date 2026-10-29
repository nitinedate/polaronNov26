from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_serial_parse_uses_evidence_focused_queue():
    text = (ROOT / 'backend/app/services/forensic_serial_stages.py').read_text(encoding='utf-8')
    assert 'prepare_forensic_parse_queue(db, job_id)' in text
    assert 'forensic_only=True' in text


def test_parse_does_not_commit_every_artifact():
    text = (ROOT / 'backend/app/services/artifact_parse.py').read_text(encoding='utf-8')
    bad = '''if pending_commits >= commit_batch:\n            _flush_artifact_writes()\n        # jobs-row heartbeat must never share a transaction with artifact-row locks.\n        _flush_artifact_writes()'''
    assert bad not in text
    assert 'do not commit once per artifact' in text


def test_quality_reads_are_shard_coalesced():
    text = (ROOT / 'backend/app/services/mobile_quality_ocr.py').read_text(encoding='utf-8')
    assert 'iter_files_from_part(part_uri' in text
    assert 'iter_spilled_files_from_part(part_uri' in text
    assert "metadata->>'extracted_part_uri'" in text


def test_performance_defaults_raised():
    env = (ROOT / '.env').read_text(encoding='utf-8')
    assert 'PARSE_WORKERS=12' in env
    assert 'PARSE_DB_COMMIT_BATCH=250' in env
    assert 'PARSE_DRAIN_BATCH_LIMIT=1200' in env
    assert 'QUALITY_TRIAGE_BATCH=800' in env
    assert 'DYNAMIC_PERF_LOCK=FORENSIC_WORKER_CONCURRENCY,MAX_CONCURRENT_DISK_BUILDS' in env
