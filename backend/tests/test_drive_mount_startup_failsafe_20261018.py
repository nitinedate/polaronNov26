"""Regression contracts for stale G: (Docker Desktop 'no such device') startup.

Static coverage is intentionally platform-independent; actual Windows/Docker
bindability must additionally be checked on the deployment host.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8-sig")


def test_bootstrap_templates_contain_no_stale_removable_drive_mounts():
    expected = {
        "docker-compose.drives.generated.yml": {
            "api", "worker-disk", "worker-parse", "worker-mobile", "worker-report", "worker-agent"
        },
        "docker-compose.drives.forensic.yml": {
            "api", "worker-disk", "worker-parse", "worker-report", "worker-agent"
        },
        "docker-compose.drives.mobile-android.yml": {"api", "worker-build", "worker-parse"},
        "docker-compose.drives.mobile-ios.yml": {"api", "worker-build", "worker-parse"},
        "docker-compose.drives.mobile.yml": {"api", "worker-mobile"},
    }
    for file, services in expected.items():
        doc = yaml.safe_load(read(file))
        assert set(doc["services"]) == services
        for name in services:
            mounts = doc["services"][name]["volumes"]
            assert len(mounts) == 1
            mount = mounts[0]
            assert mount == {
                "type": "bind", "source": "C:/", "target": "/host/c",
                "read_only": True, "bind": {"create_host_path": False},
            }


def test_startup_regenerates_all_split_overrides_before_validating_compose():
    launcher = read("script_docker/start_docker.ps1")
    generator = read("scripts/generate-drive-mounts.ps1")
    lib = read("script_docker/start_docker.lib.ps1")
    assert "'-WriteStartupStackOverrides'" in launcher
    assert "[switch]$WriteStartupStackOverrides" in generator
    for file in ("docker-compose.drives.forensic.yml", "docker-compose.drives.mobile-android.yml",
                 "docker-compose.drives.mobile-ios.yml"):
        assert file in launcher and file in generator and file in lib
    top_level = launcher.split("if ($env:AETHERIS_START_DOCKER_FUNCTIONS_ONLY -eq '1') { return }", 1)[1]
    assert top_level.index("Invoke-DriveMountRefresh -Generator") < top_level.index("Assert-AllComposeFiles")
    assert top_level.index("Assert-AllComposeFiles") < top_level.index("Stop-PolaronStacks")
    assert "LastWriteTimeUtc" in launcher
    assert "Refusing stale drive mappings" in launcher
    assert "Keeping the previous drive mapping" not in launcher


def test_generator_rejects_unverified_drives_and_refuses_missing_required_drives():
    generator = read("scripts/generate-drive-mounts.ps1")
    probes = generator.split("function Invoke-DockerDriveProbes", 1)[1].split("function Get-PreviousMappedLetters", 1)[0]
    assert "--mount" in probes
    assert "type=bind,source={1}:/,target=/probe,readonly" in probes
    assert "$status[$L] = 'unverified'" in probes
    decision = generator.split("if ($toProbe.Count) {", 1)[1].split("if (-not $letters.Count)", 1)[0]
    assert "if ($state -eq 'yes')" in decision
    assert "$skippedDocker.Add($letter)" in decision
    assert "Required evidence drive(s)" in decision
    assert "Get-PreviousMappedLetters -Path $out" not in decision
    assert "last run mapped it" not in decision
    assert "create_host_path: false" in generator
    assert "read_only: true" in generator


def test_one_discovery_renders_matching_services_for_each_stack():
    generator = read("scripts/generate-drive-mounts.ps1")
    render = generator.split("function New-DriveComposeText", 1)[1]
    assert "foreach ($service in $TargetServices)" in render
    assert "Write-VerifiedDriveOverride -Path $out -Services $serviceNames" in render
    assert "WriteStartupStackOverrides" in render
    assert "Move-Item -LiteralPath $tempPath -Destination $Path -Force" in render
    for service in ("worker-disk", "worker-parse", "worker-report", "worker-agent", "worker-build"):
        assert service in render


def test_repair_script_is_non_destructive_and_permits_required_drives():
    script = read("scripts/Repair-MissingDriveMount.ps1")
    assert "-WriteStartupStackOverrides" in script
    assert "-RequireDrive $RequireDrive" in script
    assert "-ExcludeDrive $ExcludeDrive" in script
    assert "config --quiet" in script
    assert "down -v" not in script
    assert "docker volume rm" not in script
    assert "docker system prune" not in script
