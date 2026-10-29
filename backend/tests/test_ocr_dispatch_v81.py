from pathlib import Path

def test_ocr_claim_has_reclaim_window_and_safe_json():
    src = (Path(__file__).resolve().parents[1] / 'app/tasks.py').read_text()
    assert "jsonb_build_object('early_ocr_dispatched', true, 'early_ocr_dispatch_at', NOW())" in src
    assert "NOW() - INTERVAL '30 seconds'" in src
    assert "ocr_status='pending'" in src
