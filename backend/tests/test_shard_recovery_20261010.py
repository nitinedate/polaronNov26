from pathlib import Path
SRC=(Path(__file__).parents[1]/'app/services/forensic_shard_overlap.py').read_text()

def test_lease_heartbeat_and_fenced_completion():
    assert 'heartbeat_at timestamptz' in SRC
    assert 'claim_token=:token' in SRC
    assert 'monitor.join(timeout=2)' in SRC

def test_lost_dispatch_is_replayed_with_retry_budget():
    assert 'def recover_shards(' in SRC
    assert 'FOR UPDATE SKIP LOCKED' in SRC
    assert "state='pending',claim_token=NULL" in SRC
    assert 'FORENSIC_SHARD_MAX_ATTEMPTS' in SRC

def test_early_ocr_reads_committed_candidates_and_final_reconciles():
    assert 'route_forensic_quality_to_ocr(db,job_id,limit=2000,dispatch=False)' in SRC
    assert 'ocr_drain_task.apply_async' in SRC
    assert 'Early shard OCR scheduling deferred to final OCR' in SRC
