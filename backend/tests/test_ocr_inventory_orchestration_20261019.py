"""Static safety regression for OCR early concurrency and single inventory owner."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1] / 'app'

def test_ocr_progress_during_native_parse():
    s=(ROOT/'services'/'ocr_gpu.py').read_text()
    assert "stage IN ('materialize','parse','recovery')" in s
    assert '"parallel_with": str(concurrent_stage["stage"])' in s

def test_inventory_not_rescheduled_during_ocr():
    s=(ROOT/'services'/'safe_parallel.py').read_text()
    assert "launch('artifact_inventory'" not in s
    assert "run_axiom_artifact_inventory" in (ROOT/'services'/'forensic_serial_stages.py').read_text()

def test_early_ocr_is_displayed_parallel_without_claiming_second_stage():
    s=(ROOT/'tasks.py').read_text()
    assert "'parallel_with': 'early_ocr'" in s
    assert "AND status='pending'" in s
