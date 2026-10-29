# Windows PowerShell 5.1 compatible. Dot-source after docker-engine-recovery.ps1.
if (-not (Get-Command Test-DockerRegistryDnsFailure -ErrorAction SilentlyContinue)) {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'script_docker\start_docker.lib.ps1')
}

function Test-DockerRegistryResolved {
    param([string]$Docker = 'docker')
    $probes = @(
        @{ Image = 'alpine:3'; Command = @('nslookup', 'registry-1.docker.io') },
        @{ Image = 'ubuntu:24.04'; Command = @('getent', 'hosts', 'registry-1.docker.io') }
    )
    foreach ($probe in $probes) {
        $have = Invoke-NativeCapture -Exe $Docker -Arguments @('image', 'inspect', $probe.Image, '--format', '{{.Id}}')
        if ($have.ExitCode -ne 0) { continue }
        $lookup = Invoke-NativeCapture -Exe $Docker -Arguments (@('run', '--rm', $probe.Image) + $probe.Command)
        if ($lookup.ExitCode -ne 0) { return $false }
        if ($lookup.Text -match 'no such host|NXDOMAIN|can''t find|not found') { return $false }
        return $true
    }
    try {
        $null = Resolve-DnsName registry-1.docker.io -Type A -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Ensure-DockerRegistryDns {
    param([string]$Docker = 'docker')
    if (Test-DockerRegistryResolved -Docker $Docker) {
        Write-Host '    Docker can resolve registry-1.docker.io.' -ForegroundColor Green
        return
    }
    Write-Host '    Docker cannot resolve registry-1.docker.io. Setting public DNS and restarting Docker Desktop once.' -ForegroundColor Yellow
    $daemonPath = Join-Path $env:USERPROFILE '.docker\daemon.json'
    $current = ''
    if (Test-Path -LiteralPath $daemonPath) { $current = [System.IO.File]::ReadAllText($daemonPath) }
    $updated = Merge-DockerDaemonDns -JsonText $current
    $dir = Split-Path -Parent $daemonPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($daemonPath, ($updated.Trim() + "`n"), (New-Object System.Text.UTF8Encoding $false))
    if (-not (Restart-DockerDesktopEngine -Docker $Docker -Reason 'restore Docker Hub DNS')) {
        throw 'Docker Desktop did not restart after the registry DNS repair. Start Docker Desktop, wait until it is running, then retry.'
    }
    if (-not (Test-DockerRegistryResolved -Docker $Docker)) {
        throw 'Docker still cannot resolve registry-1.docker.io. Check the machine DNS or VPN, then retry.'
    }
    Write-Host '    Docker can resolve registry-1.docker.io.' -ForegroundColor Green
}
function Assert-PolaronDockerReady {
    param(
        [string]$Docker = 'docker',
        [int]$TimeoutSec = 120,
        [switch]$AutoRecoverEngine
    )
    $probe = Invoke-NativeCapture -Exe $Docker -Arguments @('info', '--format', 'POLARON_ENGINE_OS={{.OSType}}')
    if ($probe.ExitCode -ne 0 -and $env:DOCKER_API_VERSION) {
        # Retry with normal client/server negotiation, only within this process.
        $forcedApi = $env:DOCKER_API_VERSION
        Remove-Item Env:DOCKER_API_VERSION -ErrorAction SilentlyContinue
        $retry = Invoke-NativeCapture -Exe $Docker -Arguments @('info', '--format', 'POLARON_ENGINE_OS={{.OSType}}')
        if ($retry.ExitCode -eq 0) {
            Write-Host "    Docker is ready with automatic API negotiation (removed process override $forcedApi)." -ForegroundColor Yellow
        } else {
            $env:DOCKER_API_VERSION = $forcedApi
        }
        $probe = $retry
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    if ($probe.ExitCode -ne 0) {
        Write-Host "    Waiting up to $TimeoutSec seconds for Docker Desktop's engine..." -ForegroundColor Yellow
    }
    while ($probe.ExitCode -ne 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $probe = Invoke-NativeCapture -Exe $Docker -Arguments @('info', '--format', 'POLARON_ENGINE_OS={{.OSType}}')
    }
    if ($probe.ExitCode -ne 0 -and $AutoRecoverEngine) {
        Write-Host '    Restarting Docker Desktop/WSL as requested by -AutoRecoverEngine.' -ForegroundColor Yellow
        if (Restart-DockerDesktopEngine -Docker $Docker) {
            $probe = Invoke-NativeCapture -Exe $Docker -Arguments @('info', '--format', 'POLARON_ENGINE_OS={{.OSType}}')
        }
    }
    if ($probe.ExitCode -ne 0) {
        throw ("Docker Desktop engine is unavailable. Last response: {0}`nRestart Docker Desktop from Troubleshoot, wait until the Linux engine is running, then retry. Run docker version and wsl --status if it persists. A 500 response alone does not prove an API version mismatch. Optional launcher flag: -AutoRecoverEngine (restarts Docker Desktop and all WSL distributions)." -f $probe.Text)
    }
    # Capture merges stderr warnings with stdout; read only the marked OS line.
    $osValues = @(
        foreach ($line in ($probe.Text -split "`r?`n")) {
            if ($line.Trim() -match '^POLARON_ENGINE_OS=(linux|windows)$') {
                $Matches[1].ToLowerInvariant()
            }
        }
    )
    $osValues = @($osValues | Select-Object -Unique)
    if ($osValues.Count -ne 1) {
        throw ("Docker answered, but its container operating system could not be read. Last response: {0}`nRun docker info --format '{{{{.OSType}}}}' and docker context show to inspect the selected engine." -f $probe.Text)
    }
    Write-Host "    Docker container operating system: $($osValues[0])" -ForegroundColor Green
    if ($osValues[0] -eq 'windows') {
        throw 'This project requires Linux containers. Switch Docker Desktop to Linux containers and retry.'
    }
    $compose = Invoke-NativeCapture -Exe $Docker -Arguments @('compose', 'version')
    if ($compose.ExitCode -ne 0) { throw "Docker Compose v2 is required. $($compose.Text)" }
    Enable-DockerDesktopProxyScheme -Docker $Docker
    Ensure-DockerRegistryDns -Docker $Docker
}
