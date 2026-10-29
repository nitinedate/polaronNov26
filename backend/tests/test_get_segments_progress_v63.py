from unittest.mock import MagicMock, patch

from app.services.pipeline_orchestrator import patch_segment_registration_orchestration


def test_segment_registration_progress_reaches_100_and_advances():
    db = MagicMock()
    prior = {
        "orchestration": {
            "agents": {
                "drive_mount_agent": {"state": "done", "pct": 100},
                "download_agent": {"state": "done", "pct": 100},
                "list_folder_agent": {"state": "done", "pct": 100},
                "segments_agent": {"state": "running", "pct": 10},
            }
        }
    }
    captured = {}

    def fake_execute(_db, sql, params=None):
        captured.update(params or {})

    with patch("app.services.pipeline_orchestrator.fetchone", return_value={"pipeline_progress": prior}), patch(
        "app.services.pipeline_orchestrator.execute", side_effect=fake_execute
    ):
        patch_segment_registration_orchestration(
            db, "job-v63", processed=4, total=4, complete=True
        )

    pp = __import__("json").loads(captured["pp"])
    seg = pp["orchestration"]["agents"]["segments_agent"]
    assert seg["state"] == "done"
    assert seg["pct"] == 100
    assert seg["completed"] == 4
    assert seg["total"] == 4
    assert pp["phase"] == "virtual_disk"


def test_segment_registration_progress_is_ratio_not_fixed_10():
    db = MagicMock()
    prior = {"orchestration": {"agents": {}}}
    captured = {}

    def fake_execute(_db, sql, params=None):
        captured.update(params or {})

    with patch("app.services.pipeline_orchestrator.fetchone", return_value={"pipeline_progress": prior}), patch(
        "app.services.pipeline_orchestrator.execute", side_effect=fake_execute
    ):
        patch_segment_registration_orchestration(
            db, "job-v63", processed=2, total=4, current_name="evidence.ufd"
        )

    pp = __import__("json").loads(captured["pp"])
    seg = pp["orchestration"]["agents"]["segments_agent"]
    assert seg["state"] == "running"
    assert seg["pct"] == 50
    assert "2/4" in seg["detail"]
    assert "evidence.ufd" in seg["detail"]
