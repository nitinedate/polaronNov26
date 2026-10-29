"""Cross-platform source checks for Docker Desktop G: ENODEV repair.

These ensure the previous ENODEV path is not reintroduced; actual Docker Desktop
access to evidence needs a real Windows + Docker Desktop integration test.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def txt(rel):
    return (ROOT / rel).read_text(encoding='utf-8-sig')


def test_resolver_uses_native_bind_then_wsl_not_local_driver_probe_volume():
    s = txt('scripts/resolve-docker-drive-source.ps1')
    assert '"type=bind,source=$Source,target=/probe,readonly"' in s
    assert "'--pull', 'never'" in s
    assert '$probeVolume =' not in s.split('function Test-DockerSource {')[1].split('function Get-WslDistros {')[0]
    assert "'volume', 'create'" not in s
    assert "'volume', 'rm'" not in s
    direct = s.split('$directSources = @(', 1)[1].split(')\n', 1)[0]
    assert '"${letter}:/"' in direct
    for alias in ('"/mnt/host/$lower"', '"/run/desktop/mnt/host/$lower"', '"/host_mnt/$lower"', '"/$lower"'):
        assert alias not in direct
    assert 'Test-DockerSourceViaWsl' in s
    assert 'Ensure-WslDrvFsBridge' in s


def test_resolver_does_not_alter_docker_desktop_daemon_mounts():
    s = txt('scripts/resolve-docker-drive-source.ps1')
    assert 'function Ensure-DockerDesktopHostLetter' not in s
    assert 'function Test-DockerDesktopHostLetter' not in s
    assert 'umount -l /mnt/host/' not in s
    assert 'function Repair-StaleWindowsLetter' in s
    assert 'mount -t drvfs -o ro,metadata,uid=0,gid=0' in s
    assert 'stale-letter-repair' in s
    # The repair may detach only the dead letter. It must not wipe every host share.
    assert 'umount -l "$mp"' in s
    remount = s.split('if ($RemountOnly) {', 1)[1].split('\n}', 1)[0]
    assert 'Test-DockerSource -Source "${letter}:/"' in remount
    assert 'unavailable' in remount
    assert 'No evidence was copied or marked processed' in s


def test_generator_never_accepts_previous_windows_mapping_without_fresh_probe():
    s = txt('scripts/generate-drive-mounts.ps1')
    decision = s.split('foreach ($letter in $letters) {', 1)[1].split('if ($toProbe.Count) {', 1)[0]
    assert "if ($ExecutionMode -eq 'Wsl' -and $resolved" in decision
    assert '$toProbe.Add($letter)' in decision
    assert "if ($resolved -and [string]$resolved.source)" not in decision
    assert "$status[$L] = 'unverified'" in s
    assert "if ($state -eq 'yes')" in s
    assert 'AETHERIS_EXCLUDED_DRIVES' in s
    assert 'AETHERIS_REQUIRED_DRIVES' in s
    assert 'Required evidence drive(s) cannot also be excluded' in s
    assert 'WriteStartupStackOverrides' in s
    assert 'create_host_path: false' in s


def test_diagnostic_only_removes_legacy_unused_probe_names_when_requested():
    s = txt('scripts/Repair-DockerEvidenceDrive.ps1')
    assert '[switch]$CleanUnusedProbeVolumes' in s
    assert "'^aetheris_drive_probe_[0-9a-f]{32}$'" in s
    assert 'docker volume rm $name' in s
    assert 'docker volume rm -f' not in s
    assert 'docker system prune' not in s
    assert 'docker volume prune' not in s
    assert ' -ExcludeDrive @($letter) -WriteStartupStackOverrides' in s
    assert '$RequiredPath' in s
    assert "-RequireDrive @($letter) -WriteStartupStackOverrides" in s


def test_preset_mounts_dont_include_unavailable_g():
    for rel in ('docker-compose.drives.forensic.yml',
                'docker-compose.drives.mobile-android.yml',
                'docker-compose.drives.mobile-ios.yml'):
        s = txt(rel)
        assert "source: 'G:/" not in s
        assert "target: '/host/g'" not in s
