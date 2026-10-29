"""Multiple evidence directories are separate images, then one filter."""

from app.services.disk import segment_key
from app.services.virtual_disk import evidence_directory_groups, ewf_segment_number


def test_one_directory_stays_on_the_single_image_path():
    files = [
        {"host_path": "/evidence/desktop/image.E01", "sha256": "a"},
        {"host_path": "/evidence/desktop/image.E02", "sha256": "b"},
        {"host_path": "/evidence/desktop/notes.txt", "sha256": "c"},
    ]
    assert evidence_directory_groups(files) is None


def test_two_directories_stay_separate_and_keep_registration_order():
    files = [
        {"host_path": "/evidence/desktop-1tb/image.E01", "sha256": "a"},
        {"host_path": "/evidence/desktop-1tb/image.E02", "sha256": "b"},
        {"host_path": "/evidence/desktop-250gb/image.E01", "sha256": "c"},
        {"host_path": "/evidence/desktop-250gb/image.E08", "sha256": "d"},
    ]
    groups = evidence_directory_groups(files)
    assert groups is not None
    assert [group["directory"] for group in groups] == [
        "/evidence/desktop-1tb",
        "/evidence/desktop-250gb",
    ]
    assert groups[0]["paths"] == [
        "/evidence/desktop-1tb/image.E01",
        "/evidence/desktop-1tb/image.E02",
    ]
    assert groups[1]["paths"] == [
        "/evidence/desktop-250gb/image.E01",
        "/evidence/desktop-250gb/image.E08",
    ]


def test_encase_letter_segments_continue_after_e99():
    assert ewf_segment_number("image.E01") == 1
    assert ewf_segment_number("image.E99") == 99
    assert ewf_segment_number("image.EAA") == 100
    assert ewf_segment_number("image.EAM") == 112
    assert segment_key("Ex-1 Vedant Khankar Desktop 1TB.EAM") == (
        "Ex-1 Vedant Khankar Desktop 1TB.ewf",
        112,
        "ewf",
    )
    assert segment_key("Ex-1 Vedant Khankar Desktop 1TB.E01")[1] == 1
    assert segment_key("program.exe") is None


def test_extract_combines_directories_before_the_filter():
    source = open(
        "app/services/extracted_disk.py",
        encoding="utf-8",
    ).read()
    combine_at = source.index("Combined {directory_count} directories")
    filter_at = source.index("nodes, filter_stats = _filter_nodes(", combine_at)
    assert combine_at < filter_at
    assert "Applying the filter once" in source
