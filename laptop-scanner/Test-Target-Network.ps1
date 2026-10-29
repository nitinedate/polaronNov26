# Read-only host/agent/OSPd TCP and routing comparison. Does not modify firewalls,
# scanner tasks, Docker containers, or target machines.
param(
    [Parameter(Mandatory = $true)][string]$TargetIP,
    [string]$Ports = '22,80,135,139,443,445,3389,8080,8443',
    [ValidateRange(0.1, 5.0)][double]$TimeoutSec = 2.0
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

[System.Net.IPAddress]$parsedIP = $null
if (-not [System.Net.IPAddress]::TryParse($TargetIP, [ref]$parsedIP)) {
    throw 'TargetIP must be an explicitly authorized literal IP address.'
}
$TargetIP = $parsedIP.ToString()
if ($Ports -notmatch '^[0-9, -]+$') { throw 'Invalid port list. Use numbers, commas and optional ranges.' }
$expanded = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($entry in ($Ports -split ',')) {
    $token = $entry.Trim()
    if (-not $token) { continue }
    if ($token -match '^([0-9]+)\s*-\s*([0-9]+)$') {
        $low = [int]$Matches[1]
        $high = [int]$Matches[2]
        if ($low -lt 1 -or $high -gt 65535 -or $low -gt $high -or ($high - $low) -ge 256) {
            throw "Invalid/oversized TCP port range: $token"
        }
        for ($p = $low; $p -le $high; $p++) { $null = $expanded.Add($p) }
    } elseif ($token -match '^[0-9]+$') {
        $port = [int]$token
        if ($port -lt 1 -or $port -gt 65535) { throw "Invalid TCP port: $port" }
        $null = $expanded.Add($port)
    } else { throw "Invalid TCP port entry: $token" }
    if ($expanded.Count -gt 256) { throw 'Maximum 256 diagnostic TCP ports.' }
}
if ($expanded.Count -eq 0) { throw 'At least one TCP port must be specified.' }
$portList = @($expanded | Sort-Object)
$normalizedPorts = $portList -join ','
$timeoutArg = $TimeoutSec.ToString('0.###', [System.Globalization.CultureInfo]::InvariantCulture)

Write-Host '=== 0. Windows route / interface evidence ==='
Write-Host ("Authorized target: {0}; TCP ports: {1}; per-port timeout: {2}s" -f $TargetIP, $normalizedPorts, $timeoutArg)
try {
    $locals = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.AddressState -eq 'Preferred' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength)
    $locals | Format-Table -AutoSize | Out-Host
    if (@($locals | Where-Object { $_.IPAddress -eq $TargetIP }).Count -gt 0) {
        Write-Warning 'The target is an address on this Windows host. This is not a remote client scan.'
    }
} catch { Write-Host ("Local interface lookup unavailable: {0}" -f $_.Exception.Message) }
try {
    Find-NetRoute -RemoteIPAddress $TargetIP -ErrorAction Stop |
        Select-Object InterfaceAlias, IPAddress, NextHop, RouteMetric |
        Format-List | Out-Host
} catch { Write-Host ("Route lookup unavailable: {0}" -f $_.Exception.Message) }
Write-Host 'ICMP is only supporting evidence; a firewall can block ping to a live host.'
try {
    $icmp = Test-Connection -ComputerName $TargetIP -Count 1 -Quiet -ErrorAction Stop
    Write-Host ("ICMP ping reply: {0}" -f $icmp)
} catch { Write-Host 'No ICMP reply (does not prove the host is down).' }

Write-Host '=== 1. Windows-host TCP connectivity ==='
$windowsResults = @()
foreach ($port in $portList) {
    $socket = [System.Net.Sockets.TcpClient]::new($parsedIP.AddressFamily)
    $request = $null
    $status = 'TIMEOUT_OR_FILTERED'
    try {
        $request = $socket.BeginConnect($parsedIP, $port, $null, $null)
        if ($request.AsyncWaitHandle.WaitOne([int]($TimeoutSec * 1000))) {
            try {
                $socket.EndConnect($request)
                $status = 'OPEN'
            } catch {
                $cause = $_.Exception
                while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
                if ($cause -is [System.Net.Sockets.SocketException]) {
                    switch ($cause.SocketErrorCode.ToString()) {
                        'ConnectionRefused' { $status = 'REFUSED_CLOSED' }
                        'NetworkUnreachable' { $status = 'NETWORK_UNREACHABLE' }
                        'HostUnreachable' { $status = 'HOST_UNREACHABLE' }
                        'TimedOut' { $status = 'TIMEOUT_OR_FILTERED' }
                        default { $status = "ERROR_$($cause.SocketErrorCode)" }
                    }
                } else { $status = 'ERROR_CONNECTION' }
            }
        }
    } catch { $status = "ERROR_$($_.Exception.GetType().Name)" }
    finally {
        if ($null -ne $request) { $request.AsyncWaitHandle.Close() }
        $socket.Close()
    }
    Write-Host ("{0}:{1}/tcp = {2}" -f $TargetIP, $port, $status)
    $windowsResults += [pscustomobject]@{ port = $port; status = $status }
}
try {
    Get-NetNeighbor -IPAddress $TargetIP -ErrorAction Stop |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State |
        Format-Table -AutoSize | Out-Host
} catch {
    Write-Host 'No direct neighbor entry (normal when traffic uses a router, and not proof of reachability).'
}

Write-Host '=== 2. Scanner-agent Docker-network TCP connectivity ==='
docker compose exec -T scanner-agent python -m agent.network_diagnostics $TargetIP --ports $normalizedPorts --timeout $timeoutArg
if ($LASTEXITCODE -ne 0) { throw 'Scanner-agent diagnostic failed. Check its container status and installed image.' }

Write-Host '=== 3. OSPd Docker-network TCP connectivity ==='
# Do NOT pass multiline Python code via "python3 -c $py" from PowerShell:
# Windows native-argument quoting strips string-literal quotes and corrupts f-strings.
# Piping ASCII-only Python source to "python3 -" avoids the issue entirely.
$ospdProbePath = Join-Path $PSScriptRoot 'scripts\ospd-network-probe.py'
if (-not (Test-Path -LiteralPath $ospdProbePath)) { throw "Missing OSPd probe source: $ospdProbePath" }
$ospdScript = Get-Content -LiteralPath $ospdProbePath -Raw -Encoding UTF8
$ospdScript | docker compose exec -T ospd-openvas python3 - $TargetIP --ports $normalizedPorts --timeout $timeoutArg
if ($LASTEXITCODE -ne 0) { throw 'OSPd diagnostic failed. Check the ospd-openvas container and network.' }

Write-Host '=== 4. Scanner container status ==='
docker compose ps scanner-agent ospd-openvas gvmd

if (@($windowsResults | Where-Object { $_.status -eq 'OPEN' }).Count -eq 0) {
    Write-Warning 'Windows reached no listening TCP service among the selected ports. Diagnose target identity, routing, power/network connection, and target firewall before changing scanner engines.'
}
Write-Host 'Compare all three locations. A TCP response is not proof of vulnerability checks or of a Critical/High finding.'
