from pathlib import Path


def test_early_ocr_is_claimed_atomically():
    code = (Path(__file__).parents[1] / 'app/tasks.py').read_text()
    stages = (Path(__file__).parents[1] / 'app/services/forensic_serial_stages.py').read_text()
    # A JSON literal ":true" inside text() is a SQLAlchemy bind named true.
    assert "jsonb_build_object('early_ocr_dispatched', true)" in code
    assert '{"early_ocr_dispatched":true}' not in code
    assert "jsonb_build_object('quality_triage_started', true)" in stages
    assert 'quality_triage_started\\":true' not in stages
    assert "coalesce(details->>'early_ocr_dispatched','false')<>'true'" in code
    assert "stage='parse' AND status='running'" in code


def test_ocr_can_process_committed_artifacts_during_parse():
    code = (Path(__file__).parents[1] / 'app/tasks.py').read_text()
    # V1.11.0 widened the overlap: OCR may also run while artifacts are registered.
    assert "stage IN ('materialize','parse','recovery')" in code
    assert "queue_for_stage('ocr')" in code
    assert "if not parallel_recovery:" in code


def test_final_authoritative_ocr_still_present():
    pipeline = (Path(__file__).parents[1] / 'app/services/forensic_serial_pipeline.py').read_text()
    stages = (Path(__file__).parents[1] / 'app/services/forensic_serial_stages.py').read_text()
    assert '("ocr", "GPU OCR"' in pipeline
    assert 'if count_pending_ocr(db, job_id)' in stages
