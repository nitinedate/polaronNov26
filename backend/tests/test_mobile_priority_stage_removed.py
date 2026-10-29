"""Mobile normalization uses source-grounded coverage, no redundant priority recount."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_no_mobile_priority_coverage_recount():
    src = (ROOT / 'app/services/forensic_serial_mobile.py').read_text()
    assert 'mobile_priority_coverage(db, job_id)' not in src
    assert 'persist_coverage_snapshot(db, job_id, items, counts)' in src

def test_mobile_parsers_and_recovery_remain():
    src = (ROOT / 'app/services/forensic_serial_mobile.py').read_text()
    assert 'get_plugin_registry()' in src
    assert 'if stage == "recovery":' in src
    assert '_persist_artifacts_bulk' in src

def test_priority_queue_is_scheduling_not_second_parse():
    src = (ROOT / 'app/services/forensic_serial_mobile.py').read_text()
    assert 'bundle_priority(' in src
    assert 'ORDER BY priority, id' in src

def test_historical_mobile_views_remain():
    src = (ROOT / 'app/services/forensic_priority_evidence.py').read_text()
    assert 'def priority_evidence_page(' in src
    assert 'def add_record_links(' in src
