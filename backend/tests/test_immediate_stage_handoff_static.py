"""Static safety regression for control-path edits, runs without a live database."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'app' / 'services'

def test_pending_stage_dispatches_immediately():
    src = (ROOT / 'progress_agent.py').read_text()
    assert "if active.get('status') == 'pending':" in src
    assert "dispatch_current_stage(db, job_id, schema_name=schema_name)" in src

def test_dispatch_claim_is_persisted_before_celery_publish():
    src = (ROOT / 'forensic_serial_pipeline.py').read_text()
    start = src.index('def dispatch_current_stage(')
    body = src[start:src.index('@contextmanager',start)]
    assert body.index('db.commit()') < body.index('forensic_serial_stage_task.apply_async(')
    assert "FOR UPDATE" in body

def test_speculative_ocr_failure_not_silent():
    src = (ROOT / 'forensic_serial_stages.py').read_text()
    start = src.index('def _recovery(')
    body = src[start:src.index('def _',start+5)]
    assert 'OCR early dispatch deferred' in body
    assert 'raise StageWaiting' not in body.split('# Disk filesystem-level recovery')[0]
