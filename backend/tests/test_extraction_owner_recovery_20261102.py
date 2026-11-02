"""Regression suite for the registered->processing/Redis lease deadlock."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace


def test_reserved_celery_tasks_do_not_claim_an_active_extraction(monkeypatch):
    from app.services.job_locks import extract_celery_work_active

    class Inspect:
        def active(self):
            return {"worker-1": []}
        def reserved(self):
            raise AssertionError("reserved does not own extraction")

    monkeypatch.setitem(sys.modules, "app.celery_app", SimpleNamespace(
        celery=SimpleNamespace(control=SimpleNamespace(inspect=lambda timeout: Inspect()))
    ))
    assert extract_celery_work_active("case-1") is False


def test_current_recovery_task_is_not_counted_as_prior_owner(monkeypatch):
    from app.services.job_locks import extract_celery_work_active

    class Inspect:
        def active(self):
            return {"worker-1": [
                {"id": "self-id", "name": "app.tasks.build_extracted_disk_task", "args": "['firm', 'case-1']"}
            ]}

    monkeypatch.setitem(sys.modules, "app.celery_app", SimpleNamespace(
        celery=SimpleNamespace(control=SimpleNamespace(inspect=lambda timeout: Inspect()))
    ))
    assert extract_celery_work_active("case-1") is True
    assert extract_celery_work_active("case-1", exclude_task_id="self-id") is False
    assert extract_celery_work_active("case-1", exclude_task_id="someone-else") is True


def test_missing_worker_inspection_is_not_evidence_of_death(monkeypatch):
    from app.services.job_locks import extract_celery_work_active

    class Inspect:
        def active(self):
            return None
    monkeypatch.setitem(sys.modules, "app.celery_app", SimpleNamespace(
        celery=SimpleNamespace(control=SimpleNamespace(inspect=lambda timeout: Inspect()))
    ))
    assert extract_celery_work_active("case-1") is None


def test_retry_registration_does_not_rewind_running_orchestration(monkeypatch):
    from app.services import pipeline_orchestrator

    monkeypatch.setattr(pipeline_orchestrator, "fetchone", lambda *args, **kwargs: {
        "status": "building_disk", "pipeline_progress": {"phase": "extract"},
    })
    monkeypatch.setattr(pipeline_orchestrator, "execute", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("Do not rewind the active job progress")
    ))
    assert pipeline_orchestrator.patch_segment_registration_orchestration(
        object(), "case-1", processed=31, total=31, complete=True
    ) is None


def test_repeated_folder_registration_does_not_rehash_or_relist(monkeypatch, tmp_path):
    from app.services import host_evidence

    folder = tmp_path / "first"
    folder.mkdir()
    image = folder / "image.E01"
    image.write_bytes(b"EWF mock - not used by the registration fast path")
    existing = {
        "id": "evidence-1", "job_id": "case-1", "host_path": str(image),
        "original_name": "image.E01", "status": "registered", "created_at": datetime.now(timezone.utc),
    }
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "prepare_client_evidence_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "resolve_host_path", lambda *args, **kwargs: folder)
    monkeypatch.setattr(host_evidence, "_collect_segment_files", lambda *args, **kwargs: [image])
    monkeypatch.setattr(host_evidence, "_listing_display_path", lambda folder: str(folder))
    monkeypatch.setattr(host_evidence, "fetchall", lambda db, sql, params: [existing])
    monkeypatch.setattr(host_evidence, "fetchone", lambda *args, **kwargs: {"disk_source": {"axiom_platform": "Windows"}})
    monkeypatch.setattr(host_evidence, "_log_folder_listing", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("Should not list the image directory again")
    ))
    monkeypatch.setattr(host_evidence, "fingerprint_host_segment", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("Should not hash a previously registered E01 again")
    ))
    monkeypatch.setattr(host_evidence, "persist_job_evidence_folder", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("Should not replace the active source directory")
    ))
    monkeypatch.setattr(host_evidence, "registered_image_roster", lambda *args, **kwargs: [
        {"directory": str(folder), "segments": 1}
    ])
    class Session:
        def commit(self):
            pass
    result = host_evidence.register_segments(Session(), "case-1", path=str(folder))
    assert result["already_registered"] is True
    assert len(result["accepted"]) == 1
    assert result["readiness"]["ready"] is True
    assert result["axiom_platform"] == "Windows"


def test_sql_registration_status_transition_preserves_running_job():
    from app.services import host_evidence

    source = Path(host_evidence.__file__).read_text()
    assert "WHEN status IN ('created','pending','uploaded','awaiting_segments','registered')" in source
    assert "ELSE status" in source


def test_supervisor_claims_before_publishing_the_task():
    from app.services import pipeline_supervisor

    source = Path(pipeline_supervisor.__file__).read_text()
    claim = source.index("WHERE id=:jid AND status='registered' RETURNING id")
    enqueue = source.index("async_result = build_extracted_disk_task.apply_async", claim)
    assert claim < enqueue
