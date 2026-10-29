"""Additional read-only removable media checks."""
from pathlib import Path
import app.services.drive_mount_agent as dma
import app.services.hostdrive_agent as hda


def test_all_ready_storage_types_are_accepted():
    helper = {"volumes": [
        {"letter": "G", "drive_type": "fixed", "ready": True, "label": "USB NVMe"},
        {"letter": "H", "drive_type": "removable", "ready": True, "label": "Pen drive"},
        {"letter": "F", "drive_type": "fixed", "ready": True, "label": "USB HDD"},
        {"letter": "J", "drive_type": "fixed", "ready": False},
        {"letter": "D", "drive_type": "cdrom", "ready": False},
    ], "drives": ["G", "H", "F", "J", "D"]}
    assert dma.windows_attached_letters(helper) == ["G", "H", "F"]


def test_invalid_drive_letters_not_accepted():
    helper = {"volumes": [], "drives": ["G:/../../etc", "AB", "/dev/sda", "G:"]}
    assert dma.windows_attached_letters(helper) == ["G"]


def test_segment_family_regex_handles_base36_ewf_names():
    for filename in ("disk.E01", "disk.E99", "disk.EAA", "disk.EXAA", "disk.001"):
        assert dma._EVIDENCE_FILENAME.search(filename)


def test_source_verification_checks_end_of_long_segment_set(tmp_path, monkeypatch):
    root = tmp_path / "host"
    folder = root / "g" / "Case"
    folder.mkdir(parents=True)
    names = [f"disk.E{i:02d}" for i in range(1, 99)]
    for name in names:
        (folder / name).write_bytes(b"segment")
    monkeypatch.setattr(dma, "_host_mount_prefix", lambda: root)
    monkeypatch.setattr(dma, "follow_host_junction", lambda p: p)
    monkeypatch.setattr(dma, "_is_stale_host_mount", lambda p: False)
    monkeypatch.setattr(hda, "lookup_exact_path", lambda _: {
        "ok": True, "entries": [
            {"name": name, "kind": "file", "size_bytes": 7} for name in names
        ]
    })
    assert dma.selected_media_readable(r"G:\Case")
    (folder / "disk.E98").write_bytes(b"swapped-larger")
    assert not dma.selected_media_readable(r"G:\Case")


def test_clicked_external_drive_is_preferred_in_folder_picker():
    root = Path(__file__).resolve().parents[2]
    panel = (root / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text()
    dialog = (root / "frontend/src/components/forensic/BrowseFolderDialog.tsx").read_text()
    assert 'setPreferredBrowseDrive(key.replace(/:$/, "").toUpperCase())' in panel
    assert 'preferredDrive={preferredBrowseDrive}' in panel
    assert 'const readyPreferred = windowsVolumes.some(' in dialog
