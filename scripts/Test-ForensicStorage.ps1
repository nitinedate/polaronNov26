# Read-only diagnostic: does not delete objects, images, volumes or case data.
param([string]$ProjectRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
Push-Location $ProjectRoot
try {
    $composeFile = 'services/common/docker-compose.yml'
    $containerId = (& docker compose -f $composeFile --project-directory . ps -q minio | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $containerId) { throw 'Shared MinIO is not running. Start the common stack first.' }
    $inspection = (& docker inspect $containerId | ConvertFrom-Json)[0]
    $mount = $inspection.Mounts | Where-Object Destination -eq '/data' | Select-Object -First 1
    Write-Output "MinIO /data mount type: $($mount.Type)"
    Write-Output "MinIO /data host source: $($mount.Source)"
    Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, @{Name='FreeGiB';Expression={[math]::Round($_.Free/1GB,2)}}, @{Name='UsedGiB';Expression={[math]::Round($_.Used/1GB,2)}} | Format-Table
    Write-Output 'Review the drive containing the displayed MinIO host source, not only the evidence-source drive.'
    Write-Output 'If /data is a Docker volume, also check Docker Desktop disk capacity and the host drive holding it.'
    Write-Output 'For capacity repair and checkpoint resume, follow STORAGE_CAPACITY_V80.md.'
} finally { Pop-Location }
