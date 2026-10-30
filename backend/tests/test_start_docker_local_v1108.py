"""V1.10.8: start_docker_local mirrors prod (no HTTPS) and the drive scan cannot hang startup."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_local_launcher_matches_prod_without_https_on_port_3001():
    local = read("script_docker/start_docker_local.cmd")
    assert "-Profile local %*" in local
    assert "http://localhost:3001/" in local and "localhost:3000" not in local
    assert "Stops only Polaron stacks, then rebuilds and starts all application stacks." in local
    assert "https://" not in local.lower() and "certificate" not in local.lower().replace("no https / certificates", "")
    assert (ROOT / "script_docker" / "start_docker_local.cmd").read_bytes().count(b"\r\n") > 20  # CRLF for cmd.exe


def test_local_ready_message_uses_3001():
    ps = read("script_docker/start_docker.ps1")
    local_branch = ps.split("# V1.10.8: local uses the same stacks and gateway as prod, without HTTPS.", 1)[1][:400]
    assert "http://localhost:3001/" in local_branch and "localhost:3000" not in local_branch


def test_drive_refresh_runs_with_a_time_limit_and_falls_back():
    ps = read("script_docker/start_docker.ps1")
    assert "function Invoke-DriveMountRefresh" in ps
    assert "Invoke-DriveMountRefresh -Generator $driveGenerator -Public $isPublic" in ps
    assert "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $driveGenerator" not in ps
    body = ps.split("function Invoke-DriveMountRefresh", 1)[1].split("function Assert-DockerReady", 1)[0]
    assert "AETHERIS_DRIVE_SCAN_TIMEOUT_SEC" in body and "$proc.WaitForExit($timeoutSec * 1000)" in body
    assert "taskkill.exe /PID $proc.Id /T /F" in body
    assert "Keeping the previous drive mapping" in body
    assert "if ($code -eq 0 -or ($null -eq $code -and $fresh))" in body  # explicit precedence
    # Public profiles still fail on an explicit generator error; local may continue on the previous mapping.
    assert "if (-not $Public -and $previousUsable)" in body
    assert 'throw "Drive-mount generation failed (exit $code)."' in body


def test_drive_generator_bounds_every_blocking_probe():
    gen = read("scripts/generate-drive-mounts.ps1")
    assert "function Invoke-WithTimeout" in gen and "AETHERIS_DRIVE_PROBE_TIMEOUT_SEC" in gen
    assert "[RunspaceFactory]::CreateRunspacePool(1, 4)" in gen
    for label in ("Get-Volume", "Get-Partition", "Win32_LogicalDisk", "Get-PSDrive"):
        assert f"Label = '{label}'" in gen
    assert "$script:PresenceCache" in gen  # each letter is probed once
    assert "[System.IO.DriveType]::Network" in gen  # mapped network drives are skipped
    assert gen.count("images --format") == 1 and "function Get-DockerProbeContext" in gen
    assert "$proc.WaitForExit($timeoutSec * 1000)" in gen and "--name {0}" in gen
    # Existing contracts kept
    assert "([int][char]'A')..([int][char]'Z')" in gen
    assert "Write-Output \"Letters: $($letters -join ', ')\"" in gen


def test_startup_scripts_stay_ascii_and_keep_line_endings():
    # Windows PowerShell 5.1 reads BOM-less scripts as ANSI: non-ASCII text breaks parsing.
    for rel in ("script_docker/start_docker.ps1", "scripts/generate-drive-mounts.ps1", "script_docker/start_docker_local.cmd"):
        data = (ROOT / rel).read_bytes()
        assert all(b < 128 for b in data), rel
    assert b"\r\n" in (ROOT / "script_docker" / "start_docker.ps1").read_bytes()
    assert b"\r\n" not in (ROOT / "scripts" / "generate-drive-mounts.ps1").read_bytes()


# --- V1.10.8.1 ---------------------------------------------------------------------------------
def test_drive_probes_run_in_parallel_and_do_not_drop_known_drives():
    gen = read("scripts/generate-drive-mounts.ps1")
    assert "function Invoke-DockerDriveProbes" in gen
    assert "$probe = Invoke-DockerDriveProbes -Letters @($toProbe)" in gen
    assert "AETHERIS_DRIVE_DOCKER_PROBE_TIMEOUT_SEC" in gen
    # The project drive is proven readable by the stacks' own bind mounts.
    assert "$letter -eq 'C' -or $letter -eq $projectDrive" in gen
    # A slow Docker answer keeps a drive the previous mapping already had.
    assert "function Get-PreviousMappedLetters" in gen
    assert "$state -eq 'timeout' -and $previous.ContainsKey($letter)" in gen
    # Smallest probe image first.
    assert "@('alpine', 'busybox', 'aetheris-gateway', 'aetheris-forensic-api', 'aetheris-mobile-extract-api')" in gen
    # The examiner-selected drive is still kept for exact-path resolution.
    assert "$KeepRequiredForResolution -and ($requested -contains $letter)" in gen


def test_prod_pulls_libraries_once_then_builds_tags_and_checks_https():
    cmd = read("script_docker/start_docker_prod.cmd")
    assert "-Profile prod %*" in cmd
    assert "https://122.179.141.248/" in cmd
    assert "pull each library image once" in cmd
    assert "certbot-renewer" in cmd
    assert b"\r\n" in (ROOT / "script_docker" / "start_docker_prod.cmd").read_bytes()
    ps = read("script_docker/start_docker.ps1").replace("\r\n", "\n")
    assert "function Invoke-DownPolaronProjects" in ps
    assert "function Invoke-PullRequiredLibraries" in ps
    assert "function Invoke-BuildProdApplications" in ps
    assert "nvidia/cuda:12.6.3-runtime-ubuntu24.04" in ps
    assert "certbot/certbot:v5.8.0" in ps
    prod = ps.split("if ($Profile -eq 'prod') {\n        Invoke-PullRequiredLibraries", 1)[1]
    assert "Invoke-BuildProdApplications -BuildId $buildId" in prod
    assert "$script:AetherisImagePullPolicy = 'never'" in prod
    assert "Tag shared backend as $tag" in ps
    assert "'aetheris-mobile-android-app', 'aetheris-mobile-ios-app'" in ps
    assert "down', '--remove-orphans'" in ps
    assert "'down', '-v'" not in ps and "down -v" not in ps.split("function Invoke-DownPolaronProjects", 1)[1].split("function Test-DockerImagePresent", 1)[0]
    assert "certbot-renewer is not running" in ps
    lib = read("script_docker/start_docker.lib.ps1")
    assert "function Get-ComposePullFlag" in lib
    renew = read("script_docker/renew-certificates.sh")
    assert "certbot renew" in renew and "21600" in renew
    gateway = read("deployment/windows-ip-https/docker-compose.gateway-public-https.yml")
    assert "renew-certificates.sh" in gateway and "certbot/certbot:v5.8.0" in gateway


def test_stacks_stop_together_with_progress_and_a_hard_limit():
    ps = read("script_docker/start_docker.ps1")
    body = ps.split("function Stop-PolaronStacks", 1)[1].split("function Assert-StartupAssets", 1)[0]
    # one parallel stop for every Polaron container, not one blocking call per project
    assert body.count("@('stop', '--time', '45')") == 1 and "@('stop', '--time', '45') + @($all)" in body
    assert "& docker stop" not in body
    assert "still shutting down" in body and "AETHERIS_STOP_HARD_LIMIT_SEC" in body
    assert "& docker kill @left" in body
    assert "refusing to start competing containers" in body
    # never global stop / prune / volume removal (comments may mention them; commands may not)
    commands = [line.strip().lower() for line in body.splitlines()
                if not line.strip().startswith("#") and "docker" in line.lower()]
    assert not any("prune" in c or "down -v" in c or "volume rm" in c for c in commands)
