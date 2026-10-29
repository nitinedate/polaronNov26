# HostDrive Agent - keeps the examiner host drive helper online and syncs
# newly attached HDD/USB/SSD letters into Docker bind mounts.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\hostdrive-agent.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\hostdrive-agent.ps1 -Once
#   powershell -ExecutionPolicy Bypass -File scripts\hostdrive-agent.ps1 -RefreshNow
#
# Install auto-start + browser protocol:
#   powershell -ExecutionPolicy Bypass -File scripts\install-hostdrive-agent.ps1

param(
    [switch]$Once,
    [switch]$RefreshNow,
    [switch]$EnsureOnly,
    [int]$WatchSeconds = 10,
    [int]$Port = 9876
)

if ($env:HOST_DRIVE_HELPER_PORT) {
    $Port = [int]$env:HOST_DRIVE_HELPER_PORT
}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensureScript = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$stateDir = Join-Path $env:LOCALAPPDATA "Aetheris"
$lettersFile = Join-Path $stateDir "hostdrive-agent-letters.txt"
$agentPidFile = Join-Path $stateDir "hostdrive-agent.pid"
$helperBase = "http://127.0.0.1:$Port"

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
Set-Content -Path $agentPidFile -Value $PID -Encoding ascii

function Test-HelperOnline {
    try {
        $h = Invoke-RestMethod -Uri "$helperBase/health" -TimeoutSec 2
        return [bool]$h.ok
    }
    catch {
        return $false
    }
}

function Get-HostDriveLetterSet {
    # Windows reports both fixed USB SSD enclosures and removable pen drives in
    # GetLogicalDrives(), regardless of USB bus/adapter or drive-letter order.
    # Query the drive table, not 26 Test-Path calls: a disconnected NAS mapping
    # or empty card-reader slot must never hang the 10-second watcher.
    $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($driveRoot in [System.IO.Directory]::GetLogicalDrives()) {
        if ($driveRoot -match '^([A-Za-z]):[\\/]') {
            [void]$found.Add($Matches[1].ToUpperInvariant())
        }
    }
    try {
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[A-Za-z]$' } |
            ForEach-Object { [void]$found.Add($_.Name.ToUpperInvariant()) }
    } catch { }
    return (@($found | Sort-Object) -join ',')
}

function Invoke-EnsureHelper {
    param([switch]$Always)
    if ((-not $Always) -and (Test-HelperOnline)) { return $true }
    if (-not $Always) { Write-Host "[HostDrive agent] Helper offline - starting..." }
    # ensure-host-drive-helper.ps1 also restarts a helper that belongs to a
    # different checkout or that loaded an older refresh job script.
    & powershell -NoProfile -ExecutionPolicy Bypass -File $ensureScript
    Start-Sleep -Seconds 1
    return (Test-HelperOnline)
}

function Invoke-RefreshMounts {
    if (-not (Test-HelperOnline)) {
        if (-not (Invoke-EnsureHelper)) {
            throw "Host drive helper is offline on $helperBase - cannot refresh mounts."
        }
    }
    Write-Host "[HostDrive agent] Refreshing drive mounts..."
    $resp = Invoke-RestMethod -Uri "$helperBase/refresh-drive-mounts" -Method POST `
        -ContentType "application/json" -Body "{}" -TimeoutSec 30
    if ($resp.started -or $resp.status -eq "running") {
        $deadline = (Get-Date).AddMinutes(8)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
            try {
                $st = Invoke-RestMethod -Uri "$helperBase/refresh-drive-mounts" -TimeoutSec 5
            }
            catch {
                continue
            }
            if ($st.status -eq "done") {
                Write-Host ("[HostDrive agent] {0}" -f $st.message)
                return $st
            }
            if ($st.status -eq "error") {
                if ($st.error) {
                    throw [string]$st.error
                }
                if ($st.message) {
                    throw [string]$st.message
                }
                throw "Drive mount refresh failed"
            }
        }
        throw "Drive mount refresh timed out"
    }
    Write-Host ("[HostDrive agent] {0}" -f $resp.message)
    return $resp
}

Write-Host "[HostDrive agent] root=$root port=$Port"

# Always run ensure at agent start so a stale helper from another checkout /
# older hotfix is replaced by the one that matches this script tree.
if (-not (Invoke-EnsureHelper -Always)) {
    Write-Error "Could not start host drive helper. Check scripts\host-drive-helper.ps1"
    exit 1
}

$drives = Get-HostDriveLetterSet
Write-Host "[HostDrive agent] Drives on this PC: $drives"
Set-Content -Path $lettersFile -Value $drives -Encoding ascii

if ($RefreshNow) {
    try {
        Invoke-RefreshMounts | Out-Null
    }
    catch {
        Write-Warning $_.Exception.Message
        if ($Once -or $EnsureOnly) { exit 1 }
    }
}

if ($EnsureOnly -or $Once) {
    Write-Host "[HostDrive agent] Helper online at $helperBase/health"
    exit 0
}

Write-Host "[HostDrive agent] Watching for new drives every ${WatchSeconds}s (Ctrl+C to stop)..."
while ($true) {
    try {
        if (-not (Test-HelperOnline)) {
            Invoke-EnsureHelper | Out-Null
        }
        $now = Get-HostDriveLetterSet
        $prev = ""
        if (Test-Path -LiteralPath $lettersFile) {
            $prev = (Get-Content -LiteralPath $lettersFile -Raw -ErrorAction SilentlyContinue).Trim()
        }
        if ($now -and $now -ne $prev) {
            # A newly attached disk is usable as soon as Windows assigns a letter.
            # This watcher does NOT call Invoke-RefreshMounts here. Rebuilding every
            # Docker service on plug-in is what made extraction time out. The
            # selected folder is mounted in place when extraction starts.
            # The new letter is still attached to the running Docker engine so
            # that folder mount does not wait for a Docker Desktop restart.
            $previous = @()
            if ($prev) { $previous = @($prev -split ',' | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ }) }
            $resolver = Join-Path $root "scripts\resolve-docker-drive-source.ps1"
            foreach ($letter in @($now -split ',' | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })) {
                if ($previous -contains $letter) { continue }
                Write-Host "[HostDrive agent] Mounting ${letter}: into the running Docker engine."
                & powershell -NoProfile -ExecutionPolicy Bypass -File $resolver -DriveLetter $letter -Root $root -EnsureMounted
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "[HostDrive agent] ${letter}: is visible to Windows but Docker could not mount it yet."
                }
            }
            Write-Host "[HostDrive agent] Drive set changed: '$prev' -> '$now'. Available immediately; extraction mounts that folder in place."
            Set-Content -Path $lettersFile -Value $now -Encoding ascii
        }
    }
    catch {
        Write-Warning ("[HostDrive agent] Watch loop: {0}" -f $_.Exception.Message)
    }
    Start-Sleep -Seconds ([Math]::Max(10, $WatchSeconds))
}
