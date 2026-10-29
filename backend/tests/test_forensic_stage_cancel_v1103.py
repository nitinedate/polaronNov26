"""V1.10.3: a cancelled parse stage resumes; a second evidence directory does not block it."""
from datetime import datetime, timedelta, timezone

from app.services.forensic_serial_pipeline import extraction_barrier
from app.services.progress_agent import classify_stage


def _waiting(err):
    return {"stage": "parse", "status": "waiting", "error": err,
            "updated_at": datetime.now(timezone.utc) - timedelta(minutes=5)}


def test_cancelled_stage_resumes_without_using_the_retry_budget():
    for err in ("Stage process cancelled by progressAgent",
                "Stage process cancelled by SIGTERM (stage owner alive); resuming from committed items",
                "Stage process exited without a result (exit -15)",
                "Stage process stopped by a SIGTERM from outside its owner and progressAgent (worker container "
                "stop/restart, Docker Desktop or host shutdown). Stage process cancelled by SIGTERM (stage owner "
                "alive); resuming from committed items",
                "Stage process interrupted by progressAgent or user pause (job paused (examiner, thermal or "
                "capacity protection))"):
        assert classify_stage({}, _waiting(err))[0] == "retry_dependency", err


def test_saved_directories_continue_while_the_next_directory_extracts():
    row = {"extracted_disk_uri": "s3://disk/manifest.json", "files_total": 650000, "files_extracted": 520000,
           "extraction_checkpoint": {"completed_shards": [0]},
           "disk_source": {"directory_append": {"owner": "abc", "heartbeat_at": 1.0},
                           "files_extracted": 499752, "index_uri": "s3://disk/index.jsonl.zst",
                           "segment_paths": ["E:/Ex-1 Vedant Khankar Desktop 1TB/disk.E01"]}}
    ok, reason = extraction_barrier(row)
    assert ok, reason


def test_a_real_extraction_gap_still_blocks():
    row = {"extracted_disk_uri": "s3://disk/manifest.json", "files_total": 10, "files_extracted": 5,
           "disk_source": {}}
    assert extraction_barrier(row)[0] is False
