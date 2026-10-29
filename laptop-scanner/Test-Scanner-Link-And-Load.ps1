[CmdletBinding()]
param(
    [string]$ProjectRoot = $PSScriptRoot,
    [int]$ConnectTimeoutSeconds = 8
)
$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $ProjectRoot
Write-Host '=== Aetheris laptop scanner: safe connectivity and load check ==='
$envFile = Join-Path $ProjectRoot '.env'
if (-not (Test-Path -LiteralPath $envFile)) {
    Write-Warning 'No .env found. Use .env.example as a reference, but keep production credentials unchanged.'
    exit 2
}
$setting = Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^\s*CENTRAL_API_URL\s*=' } | Select-Object -Last 1
if (-not $setting) { Write-Error 'CENTRAL_API_URL is missing from .env'; exit 2 }
$urlText = (($setting -split '=', 2)[1]).Trim().Trim('"').Trim("'").TrimEnd('/')
try { $url = [Uri]$urlText } catch { Write-Error "Invalid CENTRAL_API_URL: $urlText"; exit 2 }
if ($url.Scheme -ne 'https') { Write-Warning 'Control-plane connection is not HTTPS.' }
Write-Host "Configured central server: $($url.Scheme)://$($url.Authority)"
if ($url.Host -eq '122.179.140.167') {
    Write-Warning 'The earlier production deployment used 122.179.141.248. Confirm which IP currently owns the production HTTPS gateway before changing .env. Do not auto-failover between sites.'
}
$port = if ($url.IsDefaultPort) { if ($url.Scheme -eq 'https') { 443 } else { 80 } } else { $url.Port }
Write-Host "Checking TCP $($url.Host):$port ..."
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $task = $tcp.ConnectAsync($url.Host, $port)
    if (-not $task.Wait([Math]::Max(1000, $ConnectTimeoutSeconds * 1000))) {
        Write-Warning 'TCP connect timed out. Check WAN route, router, firewall, ISP and central host resources.'
    } elseif ($tcp.Connected) { Write-Host '[OK] TCP connection established' }
    $tcp.Close()
} catch { Write-Warning ("TCP connection failed: " + $_.Exception.Message) }
Write-Host 'Checking HTTPS API endpoint (no agent token is transmitted) ...'
try {
    $response = Invoke-WebRequest -Uri "$urlText/api/health" -UseBasicParsing -TimeoutSec $ConnectTimeoutSeconds -ErrorAction Stop
    Write-Host "[OK] HTTPS status: $([int]$response.StatusCode)"
} catch {
    $status = $_.Exception.Response.StatusCode
    if ($null -ne $status) {
        Write-Host "HTTPS gateway reached, returned HTTP $([int]$status) (endpoint may be protected or unavailable)"
    } else {
        Write-Warning ("HTTPS probe failed: " + $_.Exception.Message)
    }
}
Write-Host '=== Docker container health ==='
docker compose ps
Write-Host '=== Container CPU and memory snapshot ==='
docker stats --no-stream
Write-Host '=== Last 35 scanner agent lines ==='
docker compose logs --tail 35 scanner-agent
Write-Host 'No containers were stopped or restarted and no volumes were altered.'
