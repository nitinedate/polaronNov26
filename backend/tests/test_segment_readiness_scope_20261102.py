"""Regressions for POST /evidence/ingest-path 500: local import shadowing.

Use real readiness and real temporary E01/E02 files, but fake PostgreSQL
writes to keep this test safe to run without a production database.
"""

from pathlib import Path

import pytest


class FakeSession:
    def __init__(self):
        self.info = {}
        self.commits = 0

    def commit(self):
        self.commits += 1

    def flush(self):
        pass


@pytest.fixture
def registration_backend(monkeypatch, tmp_path):
    from app.services import host_evidence
    from app.services import pipeline_orchestrator, mobile_os, artifact_selection_catalog

    first = tmp_path / "CaseA" / "image"
    second = tmp_path / "CaseB" / "image"
    for folder in (first, second):
        folder.mkdir(parents=True)
        for n in ("disk.E01", "disk.E02"):
            (folder / n).write_bytes(f"{folder.parent.name}-{n}".encode())

    rows = []
    updates = []

    monkeypatch.setattr(host_evidence, "prepare_client_evidence_path", lambda *a, **kw: None)
    monkeypatch.setattr(host_evidence, "resolve_host_path", lambda path, **kw: Path(path))
    monkeypatch.setattr(host_evidence, "_folder_listing_completed_for_path", lambda *a: True)
    monkeypatch.setattr(host_evidence, "persist_job_evidence_folder", lambda *a: None)
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *a, **kw: None)
    monkeypatch.setattr(host_evidence, "_commit_register_progress", lambda *a: None)
    monkeypatch.setattr(host_evidence, "_log_registered_images", lambda *a: None)
    monkeypatch.setattr(host_evidence, "registered_image_roster", lambda *a: [{"label": "image", "segments": len(rows)}])
    monkeypatch.setattr(host_evidence, "_is_client_path", lambda *a: False)
    monkeypatch.setattr(pipeline_orchestrator, "patch_segment_registration_orchestration", lambda *a, **kw: None)
    monkeypatch.setattr(mobile_os, "load_job_disk_source", lambda row: row.get("disk_source") or {})
    monkeypatch.setattr(mobile_os, "extract_mobile_meta", lambda ds: {})
    monkeypatch.setattr(artifact_selection_catalog, "persist_job_axiom_platform", lambda *a: "Windows")

    def fetchall(db, query, values):
        if "FROM evidence_files" in query:
            return [dict(row) for row in rows]
        raise AssertionError(query)

    def fetchone(db, query, values):
        if "INSERT INTO evidence_files" in query:
            row = {
                "original_name": values["orig"], "host_path": values["host"],
                "status": "registered", "storage_uri": values["uri"],
                "sha256": values["sha256"], "size_bytes": values["size"],
                "group_id": values["group_id"], "id": str(len(rows) + 1),
                "job_id": values["job_id"], "created_at": "2026-11-02T00:00:00Z",
            }
            rows.append(row)
            return dict(row)
        if "FROM evidence_files" in query:
            return next((dict(row) for row in rows if row["host_path"] == values["host_path"]), None)
        if "FROM jobs" in query:
            return {"type": "host_disk", "disk_source": {}}
        raise AssertionError(query)

    monkeypatch.setattr(host_evidence, "fetchall", fetchall)
    monkeypatch.setattr(host_evidence, "fetchone", fetchone)
    monkeypatch.setattr(host_evidence, "execute", lambda db, sql, values: updates.append((sql, values)))
    return host_evidence, FakeSession(), first, second, rows, updates


def test_new_directory_uses_module_import_and_keeps_separate_same_named_sources(registration_backend):
    service, db, first, second, rows, updates = registration_backend
    a = service.register_segments(db, "job-id", path=str(first), selected_names=["disk.E01", "disk.E02"])
    assert len(a["accepted"]) == 2
    assert a["readiness"]["ready"] is True

    b = service.register_segments(db, "job-id", path=str(second), selected_names=["disk.E01", "disk.E02"])
    assert len(b["accepted"]) == 2
    assert b["readiness"]["ready"] is True
    assert len(rows) == 4
    disk_sets = b["readiness"]["disk_sets"]
    assert len(disk_sets) == 2
    assert {str(entry["source_directory"]) for entry in disk_sets} == {str(first), str(second)}
    assert any("segment_readiness=CAST" in statement for statement, values in updates)


def test_fast_path_uses_same_readiness_without_writes_or_rehash(registration_backend, monkeypatch):
    service, db, first, second, rows, updates = registration_backend
    service.register_segments(db, "job-id", path=str(first))
    service.register_segments(db, "job-id", path=str(second))
    updates.clear()
    monkeypatch.setattr(service, "fingerprint_host_segment", lambda path: pytest.fail("re-registration hashed evidence"))
    result = service.register_segments(db, "job-id", path=str(first))
    assert result["already_registered"] is True
    assert len(result["accepted"]) == 2
    assert result["readiness"]["ready"] is True
    assert updates == []
    assert len(rows) == 4


def test_no_conditional_import_shadows_top_level_segment_readiness():
    import ast
    from app.services import host_evidence

    tree = ast.parse(Path(host_evidence.__file__).read_text())
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register_segments")
    nested_imports = [
        alias.name for node in ast.walk(func) if isinstance(node, ast.ImportFrom)
        for alias in node.names
    ]
    assert "segment_readiness" not in nested_imports
