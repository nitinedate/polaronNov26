<#
.SYNOPSIS
  Safely regenerate forensic/Android/iOS Docker Desktop evidence drive mounts.
.DESCRIPTION
  Does not stop containers, delete Docker volumes, copy evidence, or alter .env.
  Default behavior scans available Windows drives and retains ONLY sources
  Docker Desktop can bind. For evidence on an unreliable letter, use -RequireDrive
  to fail rather than silently proceeding without that evidence.
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-MissingDriveMount.ps1 -ExcludeDrive G
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Repair-MissingDriveMount.ps1 -RequireDrive G
#>
[CmdletBinding()]
param(
    [string[]]$ExcludeDrive = @(),
    [string[]]$RequireDrive = @()
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$generator = Join-Path $root 'scripts/generate-drive-mounts.ps1'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker Desktop CLI is not available. Start Docker Desktop first.'
}
if (-not (Test-Path -LiteralPath $generator -PathType Leaf)) {
    throw "Drive generator not found: $generator"
}
Push-Location $root
try {
    Write-Host 'Refreshing verified evidence drive mounts (existing evidence/data untouched)...' -ForegroundColor Cyan
    & $generator -ExcludeDrive $ExcludeDrive -RequireDrive $RequireDrive -WriteStartupStackOverrides
    if ($?) {
        foreach ($stack in @('forensic', 'mobile-android', 'mobile-ios')) {
            $base = Join-Path $root "services/$stack/docker-compose.yml"
            $overlay = Join-Path $root "docker-compose.drives.$stack.yml"
            & docker compose --project-directory $root --project-name "aetheris-$stack" -f $base -f $overlay config --quiet
            if ($LASTEXITCODE -ne 0) {
                throw "Compose validation failed for $stack. Review $overlay before starting."
            }
        }
        Write-Host ''
        Write-Host 'Drive overrides refreshed and Compose configuration validated.' -ForegroundColor Green
        Write-Host 'Restart with script_docker\start_docker_local.cmd, start_docker_nitin.cmd, or start_docker_prod.cmd.'
        Write-Host 'Evidence drives that Docker cannot access were NOT mounted; do not process cases stored on those drives.' -ForegroundColor Yellow
    } else {
        throw 'Drive generator failed; keeping existing services unchanged.'
    }
}
finally {
    Pop-Location
}
