<#
.SYNOPSIS
  Diagnose a Windows evidence drive that Docker Desktop reports as "no such device".
.DESCRIPTION
  Read-only drive checks; no evidence copying, disk formatting, Docker prune,
  database reset, or Docker Desktop-internal remounts. The source resolver tests
  direct sharing once and may test a WSL-integrated path, if available.
  Successful direct binds can regenerate split-stack Compose overlays; a WSL
  result must be applied by the live HostDrive refresh flow.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 -DriveLetter G -RequiredPath 'G:\Cases\Case001\image.E01'
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 -DriveLetter G -CleanUnusedProbeVolumes
.EXAMPLE
  # ONLY for an optional unused drive, not when evidence is on G:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-DockerEvidenceDrive.ps1 -DriveLetter G -ExcludeIfOptional
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter = 'G',
    [string]$RequiredPath = '',
    [switch]$ExcludeIfOptional,
    [switch]$CleanUnusedProbeVolumes
)

$ErrorActionPreference = 'Stop'
$letter = $DriveLetter.ToUpperInvariant()
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$generator = Join-Path $root 'scripts/generate-drive-mounts.ps1'
$resolver = Join-Path $root 'scripts/resolve-docker-drive-source.ps1'
$windowsRoot = "${letter}:\"

function Clean-Probes {
    $ErrorActionPreference = 'Continue' # Docker's stderr must not abort cleanup.
    # These are ONLY temporary volumes created by the old source resolver.
    # No -f or volume prune: Docker refuses a volume that is still in use.
    $names = @(& docker volume ls --format '{{.Name}}' 2>$null |
        Where-Object { "$_" -match '^aetheris_drive_probe_[0-9a-f]{32}$' })
    foreach ($name in $names) {
        Write-Host "Removing UNUSED temporary probe volume: $name"
        & docker volume rm $name 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not remove $name (possibly still in use). No force removal attempted."
        }
    }
    if (-not $names.Count) { Write-Host 'No legacy temporary probe volumes found.' }
}

if ($ExcludeIfOptional -and $RequiredPath) {
    throw '-ExcludeIfOptional is not permitted together with -RequiredPath. Do not hide a required evidence drive.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI missing; start Docker Desktop and check its installation.'
}
$priorErrorPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { $info = @(& docker info --format '{{.ServerVersion}}' 2>&1) }
finally { $ErrorActionPreference = $priorErrorPreference }
if ($LASTEXITCODE -ne 0) {
    throw ('Docker Desktop Linux engine unavailable: ' + ($info -join ' '))
}
Write-Host "Docker engine: $($info -join ' ')" -ForegroundColor Cyan
Write-Host "Windows drive: $windowsRoot" -ForegroundColor Cyan

if ($CleanUnusedProbeVolumes) { Clean-Probes }

# Optional drive can be omitted even if Windows reports the letter. This does
# NOT make data on the excluded drive accessible to the forensic containers.
if ($ExcludeIfOptional) {
    Write-Warning "Excluding unused optional drive ${letter}: from generated Compose overlays. Evidence on ${letter}: will NOT be accessible through this mapping."
    & $generator -ExcludeDrive @($letter) -WriteStartupStackOverrides
    if (-not $?) { throw 'Drive override regeneration failed.' }
    Write-Host 'Overrides regenerated without optional drive. Restart the product stacks normally.' -ForegroundColor Green
    exit 0
}

if (-not (Test-Path -LiteralPath $windowsRoot -PathType Container)) {
    throw "Windows itself cannot access ${letter}:. Reconnect/unlock the external disk or restore the drive letter, then retry."
}
try {
    $drive = [System.IO.DriveInfo]::new($windowsRoot)
    Write-Host "Drive type=$($drive.DriveType), ready=$($drive.IsReady)"
}
catch { Write-Warning "Windows drive info unavailable: $($_.Exception.Message)" }

if ($RequiredPath) {
    if ($RequiredPath -match '^([A-Za-z]):[\\/]') {
        $pathLetter = $Matches[1].ToUpperInvariant()
    }
    else { throw 'RequiredPath must be an absolute Windows drive path, e.g. G:\Cases\image.E01.' }
    if ($pathLetter -ne $letter) {
        throw "RequiredPath must be on ${letter}:"
    }
    if (-not (Test-Path -LiteralPath $RequiredPath)) {
        throw "Windows cannot access selected evidence path: $RequiredPath"
    }
    Write-Host "Selected evidence exists in Windows: $RequiredPath" -ForegroundColor Green
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('aetheris-drive-check-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $resolver,
        '-DriveLetter', $letter, '-Root', $root, '-OutputFile', $tmp)
    if ($RequiredPath) { $psArgs += @('-RequiredPath', $RequiredPath) }
    & powershell.exe @psArgs | Out-Null
    $nativeCode = $LASTEXITCODE
    if (-not (Test-Path -LiteralPath $tmp)) {
        throw 'Source resolver produced no diagnosis. Check Windows PowerShell/Docker Desktop logs.'
    }
    $result = Get-Content -LiteralPath $tmp -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($nativeCode -ne 0 -or -not $result.ok) {
        Write-Warning ([string]$result.error)
        Write-Host 'Recovery: disconnect/reconnect the external drive; restart Docker Desktop only after active jobs are checkpointed; then re-run this diagnostic.' -ForegroundColor Yellow
        Write-Host 'If direct sharing remains unavailable, configure Docker Desktop WSL Integration for a user WSL2 distro, and use HostDrive Select disk folder to validate the exact path.' -ForegroundColor Yellow
        exit 2
    }
    Write-Host "Docker can read evidence: $($result.mode) / $($result.source)" -ForegroundColor Green
    if ($result.mode -eq 'wsl-compose') {
        Write-Host 'WSL integrated source verified. In the running application, use Select disk folder / Refresh drive mounts to activate it in the forensic stack.' -ForegroundColor Cyan
        exit 0
    }
    if ($result.mode -eq 'docker-exact-path') {
        Write-Host 'Exact folder bind verified. Use the HostDrive UI refresh to activate this narrower read-only mount; do not generate a broad G:/ mapping.' -ForegroundColor Cyan
        exit 0
    }
    & $generator -RequireDrive @($letter) -WriteStartupStackOverrides
    if (-not $?) { throw 'Drive override regeneration failed after successful source probe.' }
    Write-Host 'Drive verified and Compose overrides regenerated. Start the product stacks with the normal launcher.' -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
