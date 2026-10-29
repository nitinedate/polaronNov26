param([string]$PublicUrl = "")
$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Write-Host "Polaron scanner API / gateway diagnostic" -ForegroundColor Cyan
Write-Host "Root: $Root"
Write-Host "This script is READ ONLY. No restart, down, prune, or volume removal."
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Error 'Docker CLI unavailable'; exit 2 }
& docker info --format '{{.ServerVersion}}' 2>&1 | Out-Host
Write-Host "`nRelevant containers / health:"
& docker ps -a --format '{{.Names}}`t{{.Status}}`t{{.Ports}}' 2>&1 | Select-String 'vuln|gateway|postgres|redis|NAME' | Out-Host
Write-Host "`nDirect vulnerability API health (localhost:8082):"
try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8082/health' -TimeoutSec 8 -UseBasicParsing; Write-Host "HTTP $($r.StatusCode)" }
catch { Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Yellow }
Write-Host "`nRecent vulnerability API container logs (last 100):"
$api = (& docker ps --format '{{.Names}}') | Where-Object { $_ -match 'vuln.*api' } | Select-Object -First 1
if ($api) { & docker logs --tail 100 $api 2>&1 | Out-Host } else { Write-Host 'No running vulnerability API container found' -ForegroundColor Yellow }
Write-Host "`nRecent gateway logs (last 100):"
$gw = (& docker ps --format '{{.Names}}') | Where-Object { $_ -match 'gateway.*gateway' } | Select-Object -First 1
if ($gw) { & docker logs --tail 100 $gw 2>&1 | Out-Host } else { Write-Host 'No running gateway container found' -ForegroundColor Yellow }
if ($PublicUrl) {
  $url = $PublicUrl.TrimEnd('/') + '/api/scanner-agent/jobs/next'
  Write-Host "`nPublic route reachability (unauthenticated 401/403/405 may be expected): $url"
  try { $r = Invoke-WebRequest -Uri $url -TimeoutSec 12 -UseBasicParsing; Write-Host "HTTP $($r.StatusCode)" }
  catch { Write-Host "Response: $($_.Exception.Message)" -ForegroundColor Yellow }
}
Write-Host "`nInterpretation: direct localhost failure means vuln API/downstream issue; direct success with public 502 points to gateway/upstream network."
Write-Host 'IMPORTANT: Check actual central IP. The agent logs show 122.179.140.167; other deployment configs use 122.179.141.248.'
