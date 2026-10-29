"""The next evidence directory starts only after the current extract is saved."""

from app.services.next_evidence_directory import pending_directories, restrict_to_next_directory


def _files():
    return [
        {"host_path": "/host/g/case/Desktop 1TB/image.E01", "sha256": "a"},
        {"host_path": "/host/g/case/Desktop 1TB/image.E02", "sha256": "b"},
        {"host_path": "/host/g/case/Desktop 250GB/image.E01", "sha256": "c"},
    ]


def test_saved_extract_leaves_the_other_directory_pending():
    pending = pending_directories(
        _files(),
        [
            "/host/g/case/Desktop 1TB/image.E01",
            "/host/g/case/Desktop 1TB/image.E02",
        ],
    )
    assert [item["label"] for item in pending] == ["Desktop 250GB"]


def test_unpublished_extract_does_not_queue_a_second_directory():
    assert pending_directories(_files(), []) == []


def test_single_directory_is_not_split():
    files = _files()[:2]
    assert pending_directories(files, [files[0]["host_path"]]) == []
    kept, note = restrict_to_next_directory(files)
    assert note is None
    assert kept == files


def test_first_pass_opens_only_the_first_directory():
    kept, note = restrict_to_next_directory(_files())
    assert [row["host_path"] for row in kept] == [
        "/host/g/case/Desktop 1TB/image.E01",
        "/host/g/case/Desktop 1TB/image.E02",
    ]
    assert note is not None
    assert "Directory 1 of 2" in note
    assert "after this extraction is saved" in note


def test_follow_up_is_armed_before_the_next_pipeline_stage():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    phase3 = (root / "app" / "tasks.py").read_text(encoding="utf-8")
    serial = (root / "app" / "services" / "forensic_serial_pipeline.py").read_text(encoding="utf-8")
    phase3_fn = phase3.split("def phase3_pipeline_sync", 1)[1].split("def rag_index_sync", 1)[0]
    assert phase3_fn.index("extract_pending_directories") < phase3_fn.index("_serial_handoff")
    serial_fn = serial.split("def start_serial_pipeline", 1)[1].split("def queue_for_stage", 1)[0]
    assert serial_fn.index("unfinished_directory_reason") < serial_fn.index("extraction_barrier")
