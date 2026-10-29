<#
.SYNOPSIS
    Point MinIO's data folder (MINIO_DATA_DIR in .env) to a new location, for example D:/aetheris/minio.

.DESCRIPTION
    MinIO keeps the extracted evidence and artifacts of every job. This script changes only the
    MINIO_DATA_DIR line of the project's .env (a timestamped backup is kept first), refuses a location
    on a drive that is not connected, and creates the folder. Nothing else in .env is touched.

    Existing cases: if the new folder is empty, cases already in the database open without their
    stored files until the old MinIO data is copied there. Use -CopyFrom with the old folder (stop the
    stack first); the copy is checked by file count and size before .env is changed.

.EXAMPLE
    script_docker\Set-MinioDataDir.cmd
    # sets MINIO_DATA_DIR=D:/aetheris/minio

.EXAMPLE
    script_docker\Set-MinioDataDir.cmd -Path E:/storage/minio -CopyFrom F:/aetheris/minio
#>
[CmdletBinding()]
param(
    [string]$Path = 'D:/aetheris/minio',
    [string]$CopyFrom = '',
    [string]$Root = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
. (Join-Path $PSScriptRoot 'start_docker.lib.ps1')

function Get-FolderStats([string]$Folder) {
    $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Force -ErrorAction SilentlyContinue)
    $bytes = ($files | Measure-Object -Property Length -Sum).Sum
    return [pscustomobject]@{ Files = $files.Count; Bytes = [long]$(if ($bytes) { $bytes } else { 0 }) }
}

$envPath = Join-Path $Root '.env'
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "No .env in $Root. Run the startup once (it creates .env from .env.example), then run this again."
}

$target = ($Path.Trim().Trim('"').Trim("'") -replace '\\', '/').TrimEnd('/')
if (-not $target) { throw 'Give the new MinIO folder, for example -Path D:/aetheris/minio' }
$drive = Get-WindowsPathDrive -Path $target
if ($drive -and -not (Test-WindowsDrivePresent -Letter $drive)) {
    throw "Drive ${drive}: is not connected. Connect it first, or choose a folder on a connected drive."
}
$targetFs = if ([System.IO.Path]::IsPathRooted($target) -or $drive) { $target } else { Join-Path $Root $target }

# --- optional copy of the existing MinIO data ---------------------------------------------------
if ($CopyFrom) {
    $source = ($CopyFrom.Trim().Trim('"').Trim("'") -replace '\\', '/').TrimEnd('/')
    $sourceDrive = Get-WindowsPathDrive -Path $source
    if ($sourceDrive -and -not (Test-WindowsDrivePresent -Letter $sourceDrive)) {
        throw "Drive ${sourceDrive}: (the old MinIO data) is not connected. Connect it to copy the data."
    }
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Old MinIO folder not found: $source" }
    $running = @()
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $running = @(& docker ps --filter 'name=minio' --format '{{.Names}}' 2>$null | Where-Object { $_ })
    }
    if ($running.Count) {
        throw "MinIO is running ($($running -join ', ')). Stop the stack first so the copy is consistent, then run this again."
    }
    if ((Test-Path -LiteralPath $targetFs) -and @(Get-ChildItem -LiteralPath $targetFs -Force).Count) {
        throw "The new folder $target is not empty. Copy into an empty folder so no objects are mixed."
    }
    New-Item -ItemType Directory -Path $targetFs -Force | Out-Null
    Write-Host "Copying MinIO data $source -> $target ..."
    $robocopy = Get-Command robocopy -ErrorAction SilentlyContinue
    if ($robocopy) {
        & $robocopy.Source $source $targetFs /E /COPY:DAT /DCOPY:DAT /R:2 /W:2 /NP /NFL /NDL | Out-Host
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE); .env was not changed." }
    } else {
        Copy-Item -Path (Join-Path $source '*') -Destination $targetFs -Recurse -Force
    }
    $before = Get-FolderStats $source
    $after = Get-FolderStats $targetFs
    if ($before.Files -ne $after.Files -or $before.Bytes -ne $after.Bytes) {
        throw ("Copy check failed: {0} files / {1} bytes in the old folder, {2} / {3} in the new one. .env was not changed." -f
            $before.Files, $before.Bytes, $after.Files, $after.Bytes)
    }
    Write-Host ("Copy verified: {0} files, {1:N1} GB." -f $after.Files, ($after.Bytes / 1GB)) -ForegroundColor Green
}

New-Item -ItemType Directory -Path $targetFs -Force | Out-Null

# --- change only the MINIO_DATA_DIR line -------------------------------------------------------------
$raw = [System.IO.File]::ReadAllText($envPath)
$newline = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in ($raw -split "\r?\n")) { $lines.Add($line) }  # keeps a trailing empty line
$old = $null
$found = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*MINIO_DATA_DIR\s*=\s*(.*)$') {
        if (-not $found) {
            $old = $Matches[1].Trim()
            $lines[$i] = "MINIO_DATA_DIR=$target"
            $found = $true
        } else {
            $lines[$i] = "# $($lines[$i].TrimStart())  (superseded by MINIO_DATA_DIR above)"
        }
    }
}
if (-not $found) {
    if ($lines.Count -and $lines[$lines.Count - 1] -eq '') { $lines.Insert($lines.Count - 1, "MINIO_DATA_DIR=$target") }
    else { $lines.Add("MINIO_DATA_DIR=$target") }
}
$backup = "$envPath.bak-" + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $envPath -Destination $backup
[System.IO.File]::WriteAllText($envPath, ($lines -join $newline), [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host ("MINIO_DATA_DIR changed: {0} -> {1}" -f $(if ($old) { $old } else { '(not set: ./backup/minio)' }), $target) -ForegroundColor Green
Write-Host "Backup of the previous .env: $backup"
$stats = Get-FolderStats $targetFs
if (-not $stats.Files) {
    Write-Host ''
    Write-Host "Note: $target is empty, so MinIO starts with an empty store. Cases already in the database open" -ForegroundColor Yellow
    Write-Host "without their stored files until the old MinIO data is copied there:" -ForegroundColor Yellow
    Write-Host "  script_docker\Set-MinioDataDir.cmd -Path $target -CopyFrom <old folder>   (stack stopped)" -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'Start the application again (for example script_docker\start_docker_local.cmd).'
