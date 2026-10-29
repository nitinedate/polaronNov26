# Run on the Windows Docker Desktop host as the same user that runs Docker Desktop.
# This watcher never copies evidence, edits the evidence source, force-restarts Docker,
# unmounts devices, or declares processing safe unless the existing resolver proves it.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$EvidencePath,
  [ValidateRange(10,3600)][int]$PollSeconds=30,
  [switch]$Once,
  [string]$StatusFile='',
  [string]$Root=''
)
$ErrorActionPreference='Stop'
if(-not $Root){$Root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
$resolver=Join-Path $Root 'scripts\resolve-docker-drive-source.ps1'
if(-not (Test-Path -LiteralPath $resolver)){throw "Missing resolver: $resolver"}
if($EvidencePath -notmatch '^([A-Za-z]):[\\/](.+)$'){throw 'EvidencePath must be an absolute Windows path.'}
$drive=$Matches[1].ToUpperInvariant()
if(-not $StatusFile){$StatusFile=Join-Path $Root 'logs\evidence-drive-mount-watch.json'}
$dir=Split-Path -Parent $StatusFile
if(-not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
function Write-Status($status){
  $json=$status|ConvertTo-Json -Depth 12
  $tmp=$StatusFile+'.tmp.'+[guid]::NewGuid().ToString('N')
  [IO.File]::WriteAllText($tmp,$json,[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $tmp -Destination $StatusFile -Force
  Write-Host ("[{0}] {1}: {2}" -f $status.timestamp_utc,$status.state,$status.detail)
}
$iteration=0
while($true){
  $iteration++
  $result=[ordered]@{
    timestamp_utc=(Get-Date).ToUniversalTime().ToString('o')
    iteration=$iteration
    evidence_path=$EvidencePath
    drive=$drive
    windows_accessible=$false
    docker_verified=$false
    mode='none'
    state='BLOCKED'
    detail='Not checked'
  }
  try{
    # Reject disappearance or a drive-letter reassignment; original case identity
    # must be revalidated independently by the forensic application before resuming.
    if(-not (Test-Path -LiteralPath $EvidencePath)){
      $result.detail='Selected evidence path not currently accessible on Windows.'
    } else {
      $item=Get-Item -LiteralPath $EvidencePath -ErrorAction Stop
      $result.windows_accessible=$true
      $result.is_file=(-not $item.PSIsContainer)
      if(-not $item.PSIsContainer){$result.file_length=[long]$item.Length}
      $temp=Join-Path $env:TEMP ('polaron_evidence_resolve_'+[guid]::NewGuid().ToString('N')+'.json')
      try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $resolver -DriveLetter $drive -RequiredPath $EvidencePath -Root $Root -OutputFile $temp | Out-Null
        if(Test-Path -LiteralPath $temp){
          $answer=Get-Content -LiteralPath $temp -Raw|ConvertFrom-Json
          $result.docker_verified=[bool]$answer.ok
          $result.mode=[string]$answer.mode
          if($answer.ok){
            $result.state='DOCKER_SOURCE_VERIFIED'
            $result.detail='Verified read-only container probe. Activate the same resolved source via HostDrive; verify evidence identity before processing.'
            $result.source=[string]$answer.source
            if($answer.distro){$result.distro=[string]$answer.distro}
          } else {$result.detail=[string]$answer.error}
        } else {$result.detail='Resolver did not produce a JSON result.'}
      } finally {Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
    }
  } catch {$result.detail=$_.Exception.Message}
  Write-Status $result
  if($Once){if($result.docker_verified){exit 0}else{exit 2}}
  Start-Sleep -Seconds $PollSeconds
}
