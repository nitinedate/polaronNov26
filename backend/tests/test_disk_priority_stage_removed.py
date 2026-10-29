"""Contract: disk serial pipeline must not re-read all sources for priority evidence."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_disk_stage_does_not_run_priority_scan():
    tree = ast.parse((ROOT / 'app/services/forensic_serial_stages.py').read_text())
    stage = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'execute_stage')
    calls = {n.func.id for n in ast.walk(stage) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert 'run_disk_priority_evidence' not in calls

def test_disk_chunk_does_not_require_priority_reparse():
    src = (ROOT / 'app/services/forensic_serial_stages.py').read_text()
    assert 'chunk_disk_priority_records(db, job_id)' not in src
    assert 'missing_priority' not in src

def test_native_parser_still_has_completion_barrier():
    src = (ROOT / 'app/services/forensic_serial_stages.py').read_text()
    assert "if stage == \"parse\":" in src
    assert 'parse_status IN (\'pending\',\'parsing\')' in src

def test_mobile_priority_path_preserved():
    src = (ROOT / 'app/services/forensic_serial_stages.py').read_text()
    assert 'run_mobile_stage(' in src
    assert 'priority_record_table' in src
