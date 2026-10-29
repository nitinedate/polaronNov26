<#
.SYNOPSIS
  Read-only assessment of disks, external HDDs, SSDs, and USB flash drives.
.DESCRIPTION
  Windows presents all usable filesystem media as drive paths independently of
  hardware bus. This command reports letters, filesystem, physical bus, media,
  readiness and optional Docker/WSL bind verification of an exact E01 folder.
  It NEVER modifies source media or copies evidence. No Docker prune/rebuild.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ForensicMedia.ps1
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-ForensicMedia.ps1 -EvidencePath 'G:\Case1\Disk.E01'
#>
[CmdletBinding()]
param([string]$EvidencePath = '', [switch]$Json)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$rows = @()
$volumes = @{}
try {
    foreach ($vol in @(Get-Volume -ErrorAction SilentlyContinue)) {
        $letter = "$( $vol.DriveLetter )".ToUpperInvariant()
        if ($letter -match '^[A-Z]$') { $volumes[$letter] = $vol }
    }
} catch {}
$physical = @{}
try {
    foreach ($part in @(Get-Partition -ErrorAction SilentlyContinue)) {
        $letter = "$( $part.DriveLetter )".ToUpperInvariant()
        if ($letter -notmatch '^[A-Z]$') { continue }
        try {
            $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
            $physical[$letter] = @{
                bus_type = [string]$disk.BusType
                media_type = [string]$disk.MediaType
                disk_number = [int]$disk.Number
                operational_status = "$( $disk.OperationalStatus )"
            }
        } catch {}
    }
} catch {}

# File-system mounted USB SSDs usually report DriveType.Fixed: do not reject
# them based on that value, and never assume an E: or G: letter is external.
foreach ($entry in [System.IO.DriveInfo]::GetDrives()) {
    $letter = [string]$entry.Name[0]
    if ($letter -notmatch '^[A-Za-z]$') { continue }
    $letter = $letter.ToUpperInvariant()
    $vol = if ($volumes.ContainsKey($letter)) { $volumes[$letter] } else { $null }
    $bus = if ($physical.ContainsKey($letter)) { $physical[$letter] } else { @{} }
    $ready = $false
    try { if ($entry.DriveType -ne [System.IO.DriveType]::Network) { $ready = [bool]$entry.IsReady } } catch {}
    $rows += [pscustomobject]@{
        drive = "${letter}:"
        label = $(if ($vol) { [string]$vol.FileSystemLabel } else { '' })
        filesystem = $(if ($vol) { [string]$vol.FileSystem } else { '' })
        windows_type = [string]$entry.DriveType
        physical_bus = $(if ($bus.bus_type) { $bus.bus_type } else { 'unknown' })
        physical_media = $(if ($bus.media_type) { $bus.media_type } else { 'unknown' })
        ready = $ready
        access = $(if ($ready) { 'Windows-readable' } else { 'Not ready: unlock, reconnect, or mount' })
    }
}

$result = [ordered]@{ drives = $rows; evidence = $null; status = 'Windows discovery complete' }
if ($EvidencePath) {
    $path = ($EvidencePath.Trim() -replace '/', '\')
    if ($path -notmatch '^([A-Za-z]):[\\/]') {
        throw 'EvidencePath must be a local Windows drive path, e.g. G:\Case1\disk.E01 (not a raw \\.\PhysicalDrive device).'
    }
    $letter = $Matches[1].ToUpperInvariant()
    $isReady = @($rows | Where-Object { $_.drive -eq "${letter}:" -and $_.ready }).Count -gt 0
    if (-not (Test-Path -LiteralPath $path) -or -not $isReady) {
        $result.evidence = @{ path = $path; windows_readable = $false; docker_readable = $false }
        $result.status = 'Source missing, locked, or not ready on Windows. No evidence was accessed.'
    }
    else {
        $result.evidence = @{ path = $path; windows_readable = $true; docker_readable = $false }
        $resolver = Join-Path $root 'scripts\resolve-docker-drive-source.ps1'
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            $tmp = Join-Path $env:TEMP ("forensic-media-" + [guid]::NewGuid().ToString('N') + '.json')
            try {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $resolver `
                    -DriveLetter $letter -RequiredPath $path -Root $root -OutputFile $tmp | Out-Null
                if (Test-Path -LiteralPath $tmp) {
                    $source = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
                    $result.evidence.docker_readable = [bool]$source.ok
                    $result.evidence.mode = [string]$source.mode
                    $result.evidence.source = $(if ($source.ok) { [string]$source.source } else { '' })
                    $result.evidence.detail = $(if ($source.ok) { [string]$source.message } else { [string]$source.error })
                }
            } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
        }
        $result.status = $(if ($result.evidence.docker_readable) {
            'Selected evidence can be mounted read-only. Verify source match inside worker before processing.'
        } else {
            'Evidence accessible on Windows but not verified by Docker. Reconnect/unlock the device or enable Docker Desktop WSL Integration; do not process until readable.'
        })
    }
}

if ($Json) { $result | ConvertTo-Json -Depth 6 }
else {
    $rows | Format-Table -AutoSize | Out-Host
    if ($result.evidence) { $result.evidence | Format-List | Out-Host }
    Write-Host $result.status
}
