# Checks for start_docker's dynamic-drive handling (pwsh or Windows PowerShell 5.1):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\start_docker_drive_checks.ps1
# Simulates a host with only C: and E: and an .env that keeps MinIO on F:.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'script_docker/start_docker.lib.ps1')
function Test-WindowsDrivePresent { param([string]$Letter) return @('C', 'E') -contains $Letter }
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("drivecheck-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$failures = 0
function Check($ok, $text) { if ($ok) { Write-Host "[ OK ] $text" } else { Write-Host "[FAIL] $text"; $script:failures++ } }
try {
    Set-Content -LiteralPath (Join-Path $root '.env') -Value @(
        'AETHERIS_BACKUP_DIR=./backup', '# Example: AETHERIS_BACKUP_DIR=F:/PolaronBackup', 'MINIO_DATA_DIR=F:/aetheris/minio')
    Check ((Get-WindowsPathDrive 'F:\aetheris\minio') -eq 'F') 'drive letter of an absolute path'
    Check (-not (Get-WindowsPathDrive '\\server\share') -and -not (Get-WindowsPathDrive './backup')) 'UNC and relative paths have no drive'
    $s = Find-EnvSettingForPath -Root $root -Path 'F:\aetheris\minio'
    Check ($s.Key -eq 'MINIO_DATA_DIR') 'the .env setting behind a bind source is found; comments are ignored'
    function New-Cfg($svc, $src, $dst) {
        [pscustomobject]@{ services = [pscustomobject]@{ $svc = [pscustomobject]@{ volumes = @([pscustomobject]@{ type = 'bind'; source = $src; target = $dst }) } } }
    }
    $message = ''
    try { Assert-DeploymentComposePaths -Root $root -Config (New-Cfg 'minio' 'F:\aetheris\minio' '/data') -ValidateOnly } catch { $message = $_.Exception.Message }
    Check ($message -like 'Drive F: is not connected*MINIO_DATA_DIR=F:/aetheris/minio*') 'data on a missing drive stops with the .env setting named'
    $message = ''
    try { Assert-DeploymentComposePaths -Root $root -Config (New-Cfg 'api' 'F:/' '/host/f') -ValidateOnly } catch { $message = $_.Exception.Message }
    Check ($message -like 'Drive F: was connected during the drive scan but is gone now*') 'a vanished evidence drive is explained'
    $message = ''
    try { Assert-DeploymentComposePaths -Root $root -Config (New-Cfg 'worker' $root '/app/data') -ValidateOnly } catch { $message = $_.Exception.Message }
    Check (-not $message) 'a path on a connected drive passes'
    # Set-MinioDataDir changes only that .env line (CRLF kept, duplicate neutralised, backup made).
    [System.IO.File]::WriteAllText((Join-Path $root '.env'),
        "JWT_SECRET=keep`r`n# Example: MINIO_DATA_DIR=F:/x`r`nMINIO_DATA_DIR=F:/aetheris/minio`r`nMINIO_DATA_DIR=G:/leftover`r`n")
    & (Join-Path $repo 'script_docker/Set-MinioDataDir.ps1') -Path './backup/minio-moved' -Root $root | Out-Null
    $after = [System.IO.File]::ReadAllText((Join-Path $root '.env'))
    Check ($after -eq "JWT_SECRET=keep`r`n# Example: MINIO_DATA_DIR=F:/x`r`nMINIO_DATA_DIR=./backup/minio-moved`r`n# MINIO_DATA_DIR=G:/leftover  (superseded by MINIO_DATA_DIR above)`r`n") 'Set-MinioDataDir changes only MINIO_DATA_DIR'
    Check (@(Get-ChildItem -LiteralPath $root -Filter '.env.bak-*' -Force).Count -eq 1) 'Set-MinioDataDir keeps a backup of .env'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failures) { exit 1 }
