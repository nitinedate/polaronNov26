"""A path extracted twice is registered twice, and special characters stay storable."""

from app.services.evidence_paths import inventory_path, storage_text
from app.services.forensic_serial_stages import prepare_extracted_members
from app.services.mobile_forensic.storage import _dumps


def test_identical_index_lines_collapse_and_distinct_copies_stay():
    manifest = {"parts_map": {"1": "s3://parts/1", "3": "s3://parts/3", "7": "s3://parts/7"}}
    entries = [
        {"path": "Windows/note.txt", "part_id": 3, "offset": 10, "sha256": "a"},
        {"path": "Windows/note.txt", "part_id": 3, "offset": 10, "sha256": "a"},
        {"path": "ProgramData/Backup$KES$11.0.0.0/ListCache.xml", "part_id": 3, "offset": 100},
        {"path": "ProgramData/Backup$KES$11.0.0.0/ListCache.xml", "part_id": 7, "offset": 200},
        {"path": "Edge/LOG", "part_id": 1, "offset": 1},
        {"path": "Edge/LOG", "part_id": 1, "offset": 2},
    ]
    members = prepare_extracted_members(entries, manifest)
    assert len(members) == 5
    paths = [row["path"] for row in members]
    assert paths[0] == "Windows/note.txt"
    assert paths[1] == "ProgramData/Backup$KES$11.0.0.0/ListCache.xml"
    assert paths[2] == "ProgramData/Backup$KES$11.0.0.0/ListCache#copy-1.xml"
    assert paths[3] == "Edge/LOG"
    assert paths[4] == "Edge/LOG#copy-1"
    assert members[2]["source_path"].endswith("ListCache.xml")
    assert members[2]["part_uri"] == "s3://parts/7"
    assert inventory_path("a.dat", 0) == "a.dat"


def test_storage_text_keeps_dollar_names_and_drops_illegal_characters():
    assert storage_text("Backup$KES$11.0.0.0/~ListCache.~xml~2") == "Backup$KES$11.0.0.0/~ListCache.~xml~2"
    assert storage_text("a\x00b") == "ab"
    assert "\ud800" not in storage_text("a\ud800b")
    payload = _dumps({"title": "caf\u0000e", "note": "x\ud800y", "path": "Backup$KES$/ListCache.xml"})
    assert "\\u0000" not in payload
    assert "\x00" not in payload
    assert "Backup$KES$/ListCache.xml" in payload


def test_existing_browse_index_is_not_rebuilt(monkeypatch):
    from app.db import sql_helpers
    from app.services.evidence_browse_indexes import index_already_present

    monkeypatch.setattr(sql_helpers, "fetchone", lambda *_a, **_k: {"ok": 1})
    assert index_already_present(
        None, "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path ON job_artifacts (job_id, file_path)"
    )
    monkeypatch.setattr(sql_helpers, "fetchone", lambda *_a, **_k: None)
    assert not index_already_present(None, "CREATE INDEX IF NOT EXISTS ix_missing ON job_artifacts (job_id)")
