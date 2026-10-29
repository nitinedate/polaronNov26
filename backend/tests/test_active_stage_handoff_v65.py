import json
from unittest.mock import MagicMock, patch

from app.services.pipeline_orchestrator import mark_pipeline_agent_running


def test_queue_handoff_marks_virtual_disk_running_and_closes_prior_cards():
    db = MagicMock()
    prior = {
        "phase": "segments",
        "orchestration": {
            "agents": {
                "drive_mount_agent": {"state": "done", "pct": 100},
                "download_agent": {"state": "pending", "pct": 0},
                "list_folder_agent": {"state": "done", "pct": 100},
                "segments_agent": {"state": "done", "pct": 100},
                "virtual_disk_agent": {"state": "pending", "pct": 0},
            },
            "current_agent_id": "download_agent",
            "current_agent_label": "Download",
            "current_agent_state": "pending",
        },
    }
    captured = {}

    def fake_execute(_db, sql, params=None):
        captured.update(params or {})

    with patch("app.services.pipeline_orchestrator.fetchone", return_value={"pipeline_progress": prior}), patch(
        "app.services.pipeline_orchestrator.execute", side_effect=fake_execute
    ):
        mark_pipeline_agent_running(
            db,
            "job-v65",
            "virtual_disk_agent",
            detail="Virtual disk in process — worker queued",
            pct=1,
        )

    pp = json.loads(captured["pp"])
    orch = pp["orchestration"]
    assert orch["current_agent_id"] == "virtual_disk_agent"
    assert orch["current_agent_state"] == "running"
    assert orch["agents"]["virtual_disk_agent"]["state"] == "running"
    assert orch["agents"]["virtual_disk_agent"]["pct"] == 1
    assert orch["agents"]["download_agent"]["state"] == "done"
    assert orch["agents"]["segments_agent"]["state"] == "done"
    assert pp["phase"] == "virtual_disk"


def test_handoff_restores_missing_agent_entries_from_partial_ledger():
    db = MagicMock()
    captured = {}
    prior = {"orchestration": {"agents": {"segments_agent": {"state": "done", "pct": 100}}}}

    with patch("app.services.pipeline_orchestrator.fetchone", return_value={"pipeline_progress": prior}), patch(
        "app.services.pipeline_orchestrator.execute", side_effect=lambda _db, sql, params=None: captured.update(params or {})
    ):
        mark_pipeline_agent_running(db, "job-v65", "virtual_disk_agent", detail="Starting")

    pp = json.loads(captured["pp"])
    assert pp["orchestration"]["agents"]["virtual_disk_agent"]["state"] == "running"
    assert pp["orchestration"]["current_agent_label"] == "Virtual disk"
