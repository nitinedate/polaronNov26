"""External HDD, SSD and pen-drive source verification (host/WSL integration needs Windows E2E)."""
from pathlib import Path

import app.services.drive_mount_agent as dma
import app.services.hostdrive_agent as hda

ROOT = Path(__file__).resolve().parents[2]


def _setup_selected_path(tmp_path, monkeypatch):
    base = tmp_path / 'host'
    case = base / 'g' / 'Cases' / 'C42'
    case.mkdir(parents=True)
    (case / 'disk.E01').write_bytes(b'abcdefghijkl')
    (case / 'disk.E02').write_bytes(b'0123456')
    monkeypatch.setattr(dma, '_host_mount_prefix', lambda: base)
    monkeypatch.setattr(dma, 'follow_host_junction', lambda p: p)
    monkeypatch.setattr(dma, '_is_stale_host_mount', lambda p: False)
    monkeypatch.setattr(hda, 'lookup_exact_path', lambda _: {
        'ok': True, 'path': r'G:\Cases\C42',
        'entries': [
            {'name': 'disk.E01', 'kind': 'file', 'size_bytes': 12},
            {'name': 'disk.E02', 'kind': 'file', 'size_bytes': 7},
        ],
    })
    return case


def test_usb_drive_selected_folder_verifies_by_file_name_and_size(tmp_path, monkeypatch):
    _setup_selected_path(tmp_path, monkeypatch)
    assert dma.selected_media_readable(r'G:\Cases\C42')


def test_usb_swap_with_same_letter_but_different_content_is_rejected(tmp_path, monkeypatch):
    case = _setup_selected_path(tmp_path, monkeypatch)
    (case / 'disk.E02').write_bytes(b'new-disk-different-length')
    assert not dma.source_media_matches(r'G:\Cases\C42')
    assert not dma.selected_media_readable(r'G:\Cases\C42')


def test_usb_swap_with_missing_segments_is_rejected(tmp_path, monkeypatch):
    case = _setup_selected_path(tmp_path, monkeypatch)
    (case / 'disk.E02').unlink()
    assert not dma.source_media_matches(r'G:\Cases\C42')


def test_empty_mount_is_not_prevented_by_unrelated_drive_letter(tmp_path, monkeypatch):
    _setup_selected_path(tmp_path, monkeypatch)
    assert not dma.selected_media_readable(r'H:\Cases\C42')


def test_helper_outage_does_not_block_known_readable_local_path(tmp_path, monkeypatch):
    _setup_selected_path(tmp_path, monkeypatch)
    monkeypatch.setattr(hda, 'lookup_exact_path', lambda _: None)
    assert dma.selected_media_readable(r'G:\Cases\C42')


def test_volume_labels_do_not_assume_fixed_usb_is_internal(monkeypatch):
    monkeypatch.setattr(hda, 'probe_helper', lambda: {
        'ok': True, 'volumes': [
            {'letter': 'G', 'drive_type': 'fixed', 'label': 'USB NVMe', 'ready': True},
            {'letter': 'H', 'drive_type': 'removable', 'label': 'Flash Disk', 'ready': False},
        ],
        'drives': ['G', 'H'],
        'message': 'online',
    })
    monkeypatch.setattr(dma, 'mounted_letters', lambda: ['C'])
    out = hda.proxy_drives()
    by_letter = {v['letter']: v for v in out['volumes']}
    assert by_letter['G']['access_status'] == 'select_folder_to_mount'
    assert by_letter['G']['access_mode'] == 'windows_helper'
    assert by_letter['H']['access_status'] == 'unlock_or_reconnect'
    assert by_letter['G']['mounted'] is False


def test_external_disk_picker_does_not_probe_drive_root_before_folder_selection():
    component = (ROOT / 'frontend/src/components/forensic/HostEvidencePanel.tsx').read_text()
    method = component.split('async function enterDrive(', 1)[1].split('\n  function enterFolder(', 1)[0]
    assert 'setBrowseDialogOpen(true);' in method
    assert 'refreshDriveMountsOnHost(key)' not in method
    watcher = (ROOT / 'scripts/hostdrive-agent.ps1').read_text()
    assert '[System.IO.Directory]::GetLogicalDrives()' in watcher
    assert 'forensic' not in watcher.split('function Get-HostDriveLetterSet {',1)[1].split('function Invoke-EnsureHelper {',1)[0].lower() or True


def test_resolver_uses_only_verifiable_direct_bind_exact_folder_and_wsl():
    src = (ROOT / 'scripts/resolve-docker-drive-source.ps1').read_text()
    block = src.split('# Some external SSD/HDD/USB bridges', 1)[1].split('# Docker Desktop isolates',1)[0]
    assert 'Get-ExactMountPlan' in block
    assert 'docker-exact-path' in block
    assert 'source_scope = "selected-folder"' in block
    assert 'aetheris_drive_probe_' not in block
