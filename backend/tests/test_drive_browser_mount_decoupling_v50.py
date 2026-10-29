from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_backend_browse_uses_helper_before_any_mount_refresh():
    src = (ROOT / "backend/app/services/hostdrive_agent.py").read_text(encoding="utf-8")
    block = src.split("def proxy_list_dir", 1)[1].split("def ", 1)[0]
    assert "lookup_exact_path(raw)" in block
    assert "ensure_path_mounted" not in block
    assert 'info["mount_required"] = True' in block


def test_folder_picker_does_not_remount_on_drive_click():
    src = (ROOT / "frontend/src/components/forensic/BrowseFolderDialog.tsx").read_text(encoding="utf-8")
    block = src.split("async function openWindowsPath", 1)[1].split("async function openWindowsLetter", 1)[0]
    assert "listOfficeServerDirectory(path, 15_000)" in block
    assert "runHostDriveAgentRefresh" not in block
    assert "does not upload evidence or restart Docker" in src


def test_exact_path_mount_is_still_required_before_processing():
    src = (ROOT / "frontend/src/components/forensic/HostEvidencePanel.tsx").read_text(encoding="utf-8")
    block = src.split("async function ingestAtResolvedPath", 1)[1].split("async function resolveServerLocalDiskSelection", 1)[0]
    assert "ensureOfficePathMounted(normalized)" in block
    assert 'phase: "mounting"' in block


def test_drive_watcher_is_passive_and_helper_version_bumped():
    helper = (ROOT / "scripts/host-drive-helper.ps1").read_text(encoding="utf-8-sig")
    ensure = (ROOT / "scripts/ensure-host-drive-helper.ps1").read_text(encoding="utf-8-sig")
    block = helper.split("function Start-DrivePresenceWatcher {", 1)[1].split("function Resolve-MobileOsHint", 1)[0]
    assert "refresh-drive-mounts" not in block.lower()
    assert "Start-RefreshDriveMountsAsync" not in block
    # V1.10.10 bumped the helper so a running 5.50 helper restarts with the
    # instant /drives endpoint.
    assert '$script:HelperVersion = "5.57"' in helper
    assert '$ExpectedHelperVersion = "5.57"' in ensure
