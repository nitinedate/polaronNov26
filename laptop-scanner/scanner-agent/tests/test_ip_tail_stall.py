from agent.main import ip_tail_should_harvest


def test_frozen_94_percent_is_harvested() -> None:
    assert ip_tail_should_harvest(94, 90, stall_sec=90, stall_pct=90) is True


def test_climbing_scan_is_not_harvested() -> None:
    assert ip_tail_should_harvest(94, 20, stall_sec=90, stall_pct=90) is False
    assert ip_tail_should_harvest(50, 600, stall_sec=90, stall_pct=90) is False


def test_stall_can_be_disabled() -> None:
    assert ip_tail_should_harvest(98, 600, stall_sec=0, stall_pct=90) is False


def test_empty_tail_is_not_sealed() -> None:
    from agent.main import seal_tail_harvest

    details = {"vulnerabilities": [], "evidence": {"report_id": None, "hosts_assessed": 0}}
    assert seal_tail_harvest(details, "192.168.0.163", reason="stalled") is False
    assert details.get("status") != "completed"


def test_partial_report_must_not_be_sealed_or_cancelled() -> None:
    from agent.main import seal_tail_harvest

    details = {
        "status": "running", "progress": 95,
        "vulnerabilities": [{"host": "192.168.0.163", "plugin_id": "test-nvt"}],
        "evidence": {
            "report_id": "b5ebead4-ebd5-4b91-b972-a3698b34549e",
            "hosts_assessed": 1,
            "assessed_hosts": ["192.168.0.163"],
            "task_status": "running",
            "assessment_complete": False,
        },
    }
    assert seal_tail_harvest(details, "192.168.0.163", reason="frozen at 95%") is False
    assert details["status"] == "running"
    assert details["evidence"]["task_status"] == "running"
    assert details["evidence"]["assessment_complete"] is False


def test_default_tail_timeout_is_disabled(monkeypatch) -> None:
    from agent.main import _env_stall_sec
    monkeypatch.delenv("HIGH_PROGRESS_STALL_SEC", raising=False)
    assert _env_stall_sec() == 0
    monkeypatch.setenv("HIGH_PROGRESS_STALL_SEC", "not-a-number")
    assert _env_stall_sec() == 0
