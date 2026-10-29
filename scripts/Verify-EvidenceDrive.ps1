<#
Read-only evidence-drive verification and optional activation for Polaron.
Does NOT create synthetic success, copy files, restart Docker, or modify evidence.
Invoke in the existing project root after copying this script into scripts/.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$EvidencePath,
 [switch]$Activate,
 [switch]$Json
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$path=$EvidencePath.Trim() -replace '/','\'
if($path -notmatch '^([A-Za-z]):[\\/]') { throw 'Specify an absolute Windows drive path, e.g. G:\Cases\Disk.E01' }
$letter=$Matches[1].ToUpperInvariant()
if(-not (Test-Path -LiteralPath $path)) { throw "Windows cannot access evidence: $path. Do not process or initialize the disk." }
if(-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI unavailable.' }
$dockerInfo=@(& docker info --format '{{.ServerVersion}}' 2>&1)
if($LASTEXITCODE -ne 0){ throw ('Docker Linux engine unavailable: '+($dockerInfo -join ' ')) }
$scriptPath=Join-Path $root 'scripts\Test-ForensicMedia.ps1'
if(-not (Test-Path -LiteralPath $scriptPath)){ throw "Original project script missing: $scriptPath" }
$raw = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -EvidencePath $path -Json
if($LASTEXITCODE -ne 0){ throw 'Project evidence-mount resolver failed; review its logs.' }
$result=($raw -join "`n") | ConvertFrom-Json
if(-not $result.evidence.docker_readable){
 $result | ConvertTo-Json -Depth 8 | Write-Output
 throw 'FAILED CLOSED: Windows sees source but Docker has no verified read-only evidence bind. Check Docker Desktop WSL integration and inspect resolver attempts. No extraction started.'
}
if($Activate){
 # The refresh job changes live forensic worker containers: never force it from a probe.
 # Refresh must be initiated by existing HostDrive UI only after active jobs checkpoint.
 throw 'Verified mount source, but activation is intentionally not automatic. Checkpoint active cases, then use HostDrive > Refresh drive mounts.'
}
if($Json){$result|ConvertTo-Json -Depth 8}
else{ Write-Host 'PASS: Docker verified access to the selected evidence path.' -ForegroundColor Green; $result.evidence | Format-List | Out-Host }
