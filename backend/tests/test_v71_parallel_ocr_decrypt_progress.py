from pathlib import Path
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding='utf-8')


def test_parallelism_defaults_to_ten_slots():
    src = read('backend/app/services/forensic_serial_policy.py')
    assert 'min(10, _CPU_COUNT)' in src
    assert 'PIPELINE_PARALLEL_SLOTS' in src
    assert '"10"' in src


def test_safe_parallel_scheduler_covers_dependency_free_stages():
    src = read('backend/app/services/safe_parallel.py')
    # V1.11.0: the scheduler also covers registration (parse shards, early GPU OCR)
    # and enrichment (early graph nodes); every earlier stage is still covered.
    assert "{'materialize','parse','recovery','ocr','media_review','inventory','chunk','enrichment'}" in src
    assert 'PIPELINE_PARALLEL_SLOTS' in src
    assert 'forensic-pipeline-cpu' in src
    assert 'prechunk' in src and 'company_leakage' in src and 'artifact_inventory' in src


def test_hybrid_ocr_uses_gpu_and_cpu_small_document_lane():
    cfg = read('backend/app/config.py')
    ocr = read('backend/app/services/ocr_gpu.py')
    assert 'ocr_parallel_buckets: int = Field(default=2' in cfg
    assert 'ocr_gpu_only: bool = Field(default=False' in cfg
    assert 'ocr_cpu_small_file_max_bytes' in cfg
    assert "IN ('.pdf','.txt','.csv','.rtf')" in ocr
    assert 'ocr_bucket_task.apply_async' in ocr
    assert 'queue=cpu_queue' in ocr
    assert 'ocr_drain_task.delay(schema_name, job_id)' in ocr


def test_progress_agent_reports_active_io_instead_of_fake_99():
    import sys
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.services.progress_agent import _remaining_summary
    state = {'remaining': {'io_active': 1}, 'checks_available': True, 'operation': 'writing extracted shard'}
    msg = _remaining_summary(state)
    assert 'active I/O / final write' in msg
    assert 'writing extracted shard' in msg
    shard = _remaining_summary({
        'remaining': {'io_active': 1}, 'checks_available': True,
        'operation': 'Shard scan 12/36 files · 1.5 GB / 4.0 GB (37% of shard) · 80 MB/s',
    })
    assert shard.startswith('Shard scan 12/36')
    assert 'active I/O' not in shard


def test_progress_agent_handoff_is_immediate_after_stage_queue():
    src = read('backend/app/services/forensic_serial_pipeline.py')
    assert 'schedule_safe_sidecars(db, job_id' in src
    assert 'Do not wait for the next supervisor tick' in src
    cfg = read('backend/app/config.py')
    assert 'pipeline_supervisor_interval_sec: float = Field(default=10.0' in cfg


def test_key_manifest_is_machine_readable_without_logging_secrets(tmp_path):
    import sys
    sys.path.insert(0, str(ROOT / 'backend'))
    from app.services.mobile_acquire.decryption_key_manifest import read_decryption_key_manifest, find_decryption_key_manifest
    p = tmp_path / 'decryption_keys.txt'
    p.write_text('# private\nWHATSAPP_KEY_HEX=001122\nWHATSAPP_DECRYPTION_READY=true\n', encoding='utf-8')
    vals = read_decryption_key_manifest(p)
    assert vals['WHATSAPP_KEY_HEX'] == '001122'
    assert vals['WHATSAPP_DECRYPTION_READY'] == 'true'
    assert find_decryption_key_manifest(tmp_path) == p


def test_mobile_derivation_logs_and_persists_export_decrypted_copy():
    src = read('backend/app/services/mobile_forensic/whatsapp_derivation.py')
    assert 'DECRYPTING {path}' in src
    assert 'DECRYPTED {path}' in src
    assert 'Path("decrypted")/"whatsapp"' in src
    assert 'export_decrypted_path' in src
    assert 'WHATSAPP_KEY_HEX' in src
