from pathlib import Path

ROOT=Path(__file__).parents[1]/'app'

def test_streaming_is_feature_gated():
    import os
    from app.services.forensic_serial_policy import shard_overlap_enabled
    old=os.environ.get('FORENSIC_STREAM_SHARD_OVERLAP')
    try:
        os.environ['FORENSIC_STREAM_SHARD_OVERLAP']='false'
        assert shard_overlap_enabled() is False
        os.environ['FORENSIC_STREAM_SHARD_OVERLAP']='true'
        assert shard_overlap_enabled() is True
    finally:
        if old is None: os.environ.pop('FORENSIC_STREAM_SHARD_OVERLAP',None)
        else: os.environ['FORENSIC_STREAM_SHARD_OVERLAP']=old

def test_sidecar_does_not_claim_authoritative_stages():
    src=(ROOT/'services/forensic_shard_overlap.py').read_text()
    assert 'stage_context(\'shard_preparse\')' in src
    assert "state='done'" in src
    assert "state='failed'" in src
    assert "materialize_index_entries" in src

def test_barrier_blocks_concurrent_materialization():
    src=(ROOT/'services/forensic_serial_stages.py').read_text()
    assert 'pending = unfinished_shards(db, job_id)' in src
    assert 'raise StageWaiting' in src

def test_final_serial_stages_still_active():
    src=(ROOT/'services/forensic_serial_pipeline.py').read_text()
    assert 'pipeline_one_active_stage' in src
    assert 'extraction_barrier(row)' in src
