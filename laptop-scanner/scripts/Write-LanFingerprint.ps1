# Writes the Windows host default gateway + /24 into .lan-fingerprint so the
# portable scanner-agent (in Docker NAT) can detect a mid-scan LAN move.
#
# V1.9.1: only ONE looping writer may run. Every Start-Laptop run used to start
# another hidden loop, and loops started by pre-1.8.0 packages kept writing the
# file WITHOUT host_ips. The agent then could not recognise the laptop's own IP
# and scanned it through the firewall (field jobs 320903ac, 64b549f1).
# start-laptop.ps1 now stops stale loops; this mutex stops duplicates.
# The file is rewritten IN PLACE on purpose: it is a single-file Docker bind
# mount, and replacing it by rename would leave the container on the old inode.
param(
    [string]$Root = "",
    [switch]$Once
)

if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
$out = Join-Path $Root '.lan-fingerprint'

function Get-LanFingerprint {
    $gw = ""
    $subnet = ""
    try {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object -Property RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if ($route) {
            $gw = [string]$route.NextHop
            $addr = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
                Select-Object -First 1
            if ($addr -and $addr.IPAddress) {
                $parts = $addr.IPAddress.Split('.')
                if ($parts.Count -eq 4) {
                    $subnet = "{0}.{1}.{2}.0/24" -f $parts[0], $parts[1], $parts[2]
                }
            }
        }
    } catch {
        $gw = ""
    }
    # V1.8.0: every IPv4 address of this laptop, so the scanner-agent can tell
    # when an authorized target is the scanner itself (scanned via loopback).
    $hostIps = @()
    try {
        $hostIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike '127.*' -and
                $_.IPAddress -notlike '169.254.*' -and
                ($_.AddressState -eq 'Preferred' -or "$($_.AddressState)" -eq '4')
            } |
            ForEach-Object { [string]$_.IPAddress } |
            Sort-Object -Unique)
    } catch {
        $hostIps = @()
    }
    $payload = @{
        gateway        = $gw
        subnet         = $subnet
        host_ips       = @($hostIps)
        source         = "host"
        writer_version = "1.9.1"
        writer_pid     = $PID
        updated_at     = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($out, $payload)
}

if ($Once) {
    Get-LanFingerprint
    exit 0
}

# Single looping writer per laptop-scanner folder.
$mutexName = 'Local\AetherisLanFingerprint_' + ([BitConverter]::ToString(
    [System.Security.Cryptography.SHA1]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant()))) -replace '-', '').Substring(0, 16)
$createdNew = $false
$script:writerMutex = New-Object System.Threading.Mutex($true, $mutexName, [ref]$createdNew)
if (-not $createdNew) {
    # Another current writer already owns this folder.
    exit 0
}

Get-LanFingerprint

while ($true) {
    Start-Sleep -Seconds 10
    try { Get-LanFingerprint } catch { }
}
