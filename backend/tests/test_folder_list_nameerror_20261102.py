"""Regressions for the Get segments / list-folder 500 on 2026-11-02."""
from pathlib import Path

import pytest


class FakeSession:
    def commit(self):
        pass


def test_list_folder_succeeds_without_undefined_skip_or_recursive_call(monkeypatch, tmp_path):
    from app.services import host_evidence

    folder = tmp_path / "CaseA"
    folder.mkdir()
    writes = []
    stored = []
    entries = [
        {"kind": "file", "name": "image.E01", "relative_path": "image.E01", "size_bytes": 12},
        {"kind": "file", "name": "image.E02", "relative_path": "image.E02", "size_bytes": 13},
    ]
    monkeypatch.setattr(host_evidence, "_walk_folder_entries", lambda path: entries)
    monkeypatch.setattr(host_evidence, "_list_folder_workers", lambda: 8)
    monkeypatch.setattr(host_evidence, "_listing_display_path", lambda path: str(path))
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda db, job, message, **kw: writes.append((message, kw)))
    monkeypatch.setattr(host_evidence, "write_disk_logs_batch", lambda db, job, rows, **kw: writes.extend((r["message"], kw) for r in rows))
    monkeypatch.setattr(host_evidence, "persist_job_evidence_folder", lambda db, job, path: stored.append(path))
    result = host_evidence._log_folder_listing(FakeSession(), "job-1", folder)
    assert result["count"] == 2
    assert result["segment_count"] == 2
    assert result["segments"] == ["image.E01", "image.E02"]
    assert stored == [str(folder)]
    assert sum("Folder listing complete" in message for message, _ in writes) == 1


def test_completed_listing_lookup_is_job_and_directory_scoped(monkeypatch):
    from app.services import host_evidence

    calls = []

    def fake_fetchone(db, statement, params):
        calls.append(params)
        assert "metadata->>'complete' = 'true'" in statement
        return {"ok": 1} if params["path"] == "D:/Evidence/CaseA" else None

    monkeypatch.setattr(host_evidence, "fetchone", fake_fetchone)
    assert host_evidence._folder_listing_completed_for_path(FakeSession(), "job-1", "D:/Evidence/CaseA")
    assert not host_evidence._folder_listing_completed_for_path(FakeSession(), "job-1", "D:/Evidence/CaseB")
    assert calls == [
        {"job_id": "job-1", "path": "D:/Evidence/CaseA"},
        {"job_id": "job-1", "path": "D:/Evidence/CaseB"},
    ]


@pytest.mark.parametrize("skip,listed,expected_listing_calls", [
    (False, False, 1),  # brand-new directory requires an audit
    (False, True, 0),   # Step 2 already listed this directory
    (True, False, 0),   # explicit recovery skips expensive listing
])
def test_register_segments_honors_skip_and_completed_listing(monkeypatch, tmp_path, skip, listed, expected_listing_calls):
    from app.services import host_evidence

    folder = tmp_path / "CaseA"
    folder.mkdir()
    seg = folder / "image.E01"
    seg.write_bytes(b"dummy")
    calls = []
    monkeypatch.setattr(host_evidence, "prepare_client_evidence_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "resolve_host_path", lambda *args, **kwargs: folder)
    monkeypatch.setattr(host_evidence, "_collect_segment_files", lambda *args, **kwargs: [seg])
    monkeypatch.setattr(host_evidence, "_listing_display_path", lambda path: str(path))
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "fetchall", lambda *args, **kwargs: [])
    monkeypatch.setattr(host_evidence, "fetchone", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "_folder_listing_completed_for_path", lambda *args, **kwargs: listed)
    monkeypatch.setattr(host_evidence, "_log_folder_listing", lambda *args, **kwargs: calls.append("listed"))
    monkeypatch.setattr(host_evidence, "persist_job_evidence_folder", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "_commit_register_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "execute", lambda *args, **kwargs: None)
    monkeypatch.setattr(host_evidence, "readable_segment_paths", lambda paths: ([], [str(seg)]))

    # Stop just after the listing decision so registration does not touch
    # sample image bytes or PostgreSQL tables.
    with pytest.raises(ValueError, match="no longer readable"):
        host_evidence.register_segments(FakeSession(), "job-1", path=str(folder), skip_folder_list=skip)
    assert len(calls) == expected_listing_calls


def test_list_folder_endpoint_uses_leaf_listing_not_registration():
    from app.services import host_evidence

    source = Path(host_evidence.__file__).read_text()
    start = source.index("def _log_folder_listing(")
    end = source.index("def _folder_listing_completed_for_path(", start)
    assert "if not skip_folder_list" not in source[start:end]
    assert "_log_folder_listing(db, job_id, folder)" not in source[start:end]


def test_public_list_folder_service_returns_segment_metadata(monkeypatch, tmp_path):
    from app.services import host_evidence

    folder = tmp_path / "CaseA"
    folder.mkdir()
    seen = []
    monkeypatch.setattr(host_evidence, "prepare_client_evidence_path", lambda *a, **kw: None)
    monkeypatch.setattr(host_evidence, "resolve_host_path", lambda *a, **kw: folder)
    monkeypatch.setattr(host_evidence, "_walk_folder_entries", lambda path: [
        {"kind": "file", "name": "evidence.E01", "relative_path": "evidence.E01", "size_bytes": 12},
    ])
    monkeypatch.setattr(host_evidence, "_listing_display_path", lambda path: str(path))
    monkeypatch.setattr(host_evidence, "write_disk_log", lambda *a, **kw: None)
    monkeypatch.setattr(host_evidence, "write_disk_logs_batch", lambda *a, **kw: None)
    monkeypatch.setattr(host_evidence, "persist_job_evidence_folder", lambda db, job, path: seen.append(path))
    result = host_evidence.list_folder_contents(FakeSession(), "job-1", path=str(folder))
    assert result["segment_count"] == 1
    assert result["segments"] == ["evidence.E01"]
    assert seen == [str(folder)]
