[CmdletBinding()]
param(
    # Proceed even if an OpenVAS scan appears to be running.
    [switch]$Force,
    # Do not edit .env (only recreate containers and verify).
    [switch]$SkipEnv
)
# Aetheris laptop scanner - apply V1.10.1 on an installed laptop.
#
# Run from the install folder after extracting laptop-scanner-v1.10.1 over it:
#   .\Apply-Scanner-v1.10.1.cmd
#
# What it does (each step is printed):
#  1. checks the extracted files really are V1.10.1;
#  2. refuses to continue while OpenVAS is scanning (use -Force to override);
#  3. backs up .env, then: removes SCAN_IP_BUDGET_SEC (obsolete), sets
#     OPENVAS_LOG_LEVEL 128 -> 127, updates a stale AGENT_VERSION, sets
#     AGENT_COMPUTER_NAME to this PC's name (V1.10.0: laptop identity);
#  4. re-runs configure-openvas (writes openvas.conf / openvas_log.conf);
#  5. recreates scanner-agent so it gets the read-only feed mount;
#  6. verifies: log_whole_attack, log level, feed mount, agent build.
# It never runs "docker restart" (that hangs this Docker engine) and never
# touches volumes, the agent token or the LAN fingerprint.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = '1.10.1'
$Build = '1.10.1-v61.0'

function Run-Docker([string[]]$A, [switch]$AllowFailure) {
    $old = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; $o = & docker.exe @A 2>&1; $c = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    $t = (@($o | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
    if (-not $AllowFailure -and $c -ne 0) { throw "docker command failed ($c): docker $($A -join ' ')`n$t" }
    [pscustomobject]@{ ExitCode = $c; Text = $t }
}

function Write-Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow; $script:Warnings++ }

function Update-EnvText([string]$Raw, [string]$TargetVersion, [string]$Computer = $env:COMPUTERNAME) {
    # Returns @{ Text = <new text>; Changes = <list of strings> }. Keeps the
    # file's own line endings and every other line exactly as it was.
    $nl = "`n"
    if ($Raw -match "`r`n") { $nl = "`r`n" }
    $lines = $Raw -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    $changes = New-Object System.Collections.Generic.List[string]
    $seenComputer = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*SCAN_IP_BUDGET_SEC\s*=') {
            $changes.Add("removed obsolete $($line.Trim())")
            continue
        }
        if ($line -match '^\s*OPENVAS_LOG_LEVEL\s*=\s*128\s*$') {
            $out.Add('OPENVAS_LOG_LEVEL=127')
            $changes.Add('OPENVAS_LOG_LEVEL 128 (DEBUG) -> 127')
            continue
        }
        if ($line -match '^\s*AGENT_VERSION\s*=\s*(.*)$') {
            $current = $Matches[1].Trim().Trim('"').Trim("'")
            if ($current -ne $TargetVersion) {
                $out.Add("AGENT_VERSION=$TargetVersion")
                $changes.Add("AGENT_VERSION $current -> $TargetVersion")
                continue
            }
        }
        if ($line -match '^\s*AGENT_COMPUTER_NAME\s*=\s*(.*)$') {
            # V1.10.0: a .env copied from another laptop carries that laptop's name.
            $current = $Matches[1].Trim().Trim('"').Trim("'")
            $seenComputer = $true
            if ($Computer -and $current -ne $Computer) {
                $out.Add("AGENT_COMPUTER_NAME=$Computer")
                $changes.Add("AGENT_COMPUTER_NAME $current -> $Computer")
                continue
            }
        }
        $out.Add($line)
    }
    if ($Computer -and -not $seenComputer) {
        while ($out.Count -gt 0 -and $out[$out.Count - 1] -eq '') { $out.RemoveAt($out.Count - 1) }
        $out.Add("AGENT_COMPUTER_NAME=$Computer")
        $out.Add('')
        $changes.Add("added AGENT_COMPUTER_NAME=$Computer (laptop identity for the central server)")
    }
    return @{ Text = ($out -join $nl); Changes = $changes }
}

if ($env:AETHERIS_APPLY_SELFTEST -eq '1') { return }   # lets tests dot-source the functions

$script:Warnings = 0
$root = $PSScriptRoot
$compose = $null
foreach ($n in @('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')) {
    $p = Join-Path $root $n
    if (Test-Path $p) { $compose = $p; break }
}
if (-not $compose) { throw "No docker-compose.yml next to this script ($root). Run the copy in the install folder." }
$envPath = Join-Path $root '.env'
if (-not (Test-Path $envPath)) { throw "No .env in $root - this does not look like an installed laptop scanner." }

Write-Host "==> Aetheris laptop scanner: apply V$Version ($root)"

# 1. The extracted files must be this version, or the recreate below would apply old settings.
$composeText = [IO.File]::ReadAllText($compose)
$initText = ''
$initPath = Join-Path (Join-Path (Join-Path $root 'scanner-agent') 'agent') '__init__.py'
if (Test-Path $initPath) { $initText = [IO.File]::ReadAllText($initPath) }
if ($composeText -notmatch 'gvm_vt_data:/var/lib/openvas/plugins:ro' -or $composeText -notmatch 'HOST_COMPUTERNAME') {
    throw "docker-compose.yml in $root is not the V$Version file. Extract laptop-scanner-v$Version into this folder first."
}
if ($initText -notmatch [regex]::Escape($Build)) {
    throw "scanner-agent\agent\__init__.py is not build $Build. Extract laptop-scanner-v$Version into this folder first."
}
Write-Ok "Files are V$Version (build $Build)."

# 2. Do not recreate containers in the middle of a scan.
$probe = Run-Docker @('compose', '-f', $compose, 'exec', '-T', 'ospd-openvas', 'sh', '-c',
    "grep -l -e 'scan-star[t]' -e 'openvas: testin[g]' /proc/[0-9]*/cmdline 2>/dev/null | wc -l") -AllowFailure
$running = 0
if ($probe.ExitCode -eq 0 -and ($probe.Text.Trim() -match '^\d+$')) { $running = [int]$probe.Text.Trim() }
if ($probe.ExitCode -ne 0) {
    Write-Warn "Could not check ospd-openvas for running scans (exit $($probe.ExitCode)). Make sure no scan is running."
} elseif ($running -gt 0) {
    if (-not $Force) {
        throw "OpenVAS is scanning right now ($running scan process(es)). Wait until the scan finishes, then run this again (or use -Force)."
    }
    Write-Warn "OpenVAS is scanning ($running process(es)); continuing because -Force was given."
} else {
    Write-Ok 'No OpenVAS scan is running.'
}

# 3. .env: back up, then apply the .env changes.
if ($SkipEnv) {
    Write-Host '[--] .env left unchanged (-SkipEnv).'
} else {
    $raw = [IO.File]::ReadAllText($envPath)
    $result = Update-EnvText $raw $Version
    if ($result.Changes.Count -gt 0) {
        $backup = "$envPath.bak-v$Version-" + (Get-Date -Format 'yyyyMMdd-HHmmss')
        Copy-Item -LiteralPath $envPath -Destination $backup
        [IO.File]::WriteAllText($envPath, $result.Text, (New-Object System.Text.UTF8Encoding($false)))
        Write-Ok ".env updated (backup: $(Split-Path $backup -Leaf)):"
        foreach ($c in $result.Changes) { Write-Host "       $c" }
    } else {
        Write-Ok '.env needs no changes.'
    }
    if ($raw -match '(?m)^\s*OPENVAS_LOG_WHOLE_ATTACK\s*=\s*(no|0|false|off)\s*$') {
        Write-Warn 'OPENVAS_LOG_WHOLE_ATTACK is off in .env: the agent cannot name the check a host waits on at 98%. Set it to yes if you want that.'
    }
}

# 4. configure-openvas is a one-shot container; only --force-recreate re-runs it.
Write-Host '==> Re-running configure-openvas (writes openvas.conf and openvas_log.conf)'
$up = Run-Docker @('compose', '-f', $compose, 'up', '-d', '--force-recreate', '--no-deps', 'configure-openvas') -AllowFailure
if ($up.Text) { Write-Host $up.Text }
if ($up.ExitCode -ne 0) { throw "docker compose up configure-openvas failed with exit code $($up.ExitCode)" }
$state = ''
for ($i = 0; $i -lt 30; $i++) {
    $st = Run-Docker @('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', 'aetheris-laptop-configure-openvas-1') -AllowFailure
    $state = $st.Text.Trim()
    if ($state -like 'exited*') { break }
    Start-Sleep -Seconds 2
}
if ($state -eq 'exited 0') { Write-Ok 'configure-openvas finished.' } else { Write-Warn "configure-openvas state: '$state' (expected 'exited 0')." }

$conf = Run-Docker @('compose', '-f', $compose, 'exec', '-T', 'ospd-openvas', 'sh', '-c',
    "grep -E '^log_whole_attack' /etc/openvas/openvas.conf; grep -m1 '^level' /etc/openvas/openvas_log.conf") -AllowFailure
if ($conf.Text -match 'log_whole_attack\s*=\s*yes') { Write-Ok 'openvas.conf: log_whole_attack = yes' } else { Write-Warn "openvas.conf has no 'log_whole_attack = yes' (read: $($conf.Text.Trim()))" }
if ($conf.Text -match '(?m)^level=127\s*$') { Write-Ok 'openvas_log.conf: level=127' } else { Write-Warn "openvas_log.conf is not level=127 (read: $($conf.Text.Trim()))" }
Write-Host '       OpenVAS starts a new process for each scan and reads both files then: no ospd-openvas restart needed.'

# 5. Recreate scanner-agent: the feed mount and new settings only apply to a new container.
Write-Host '==> Recreating scanner-agent'
$up = Run-Docker @('compose', '-f', $compose, 'up', '-d', '--force-recreate', '--no-deps', 'scanner-agent') -AllowFailure
if ($up.ExitCode -ne 0 -and $up.Text -match 'already in use by container') {
    Write-Warn 'Name conflict from an earlier interrupted recreate; removing the leftover container and retrying.'
    $orph = Run-Docker @('ps', '-aq', '--filter', 'name=_aetheris-laptop-scanner-agent') -AllowFailure
    $ids = @($orph.Text -split '\s+' | Where-Object { $_ -match '^[a-f0-9]{12,}$' })
    if ($ids.Count -gt 0) { $null = Run-Docker (@('rm', '-f') + $ids) -AllowFailure }
    $up = Run-Docker @('compose', '-f', $compose, 'up', '-d', '--force-recreate', '--no-deps', 'scanner-agent') -AllowFailure
}
if ($up.Text) { Write-Host $up.Text }
if ($up.ExitCode -ne 0) { throw "docker compose recreate scanner-agent failed with exit code $($up.ExitCode)" }

# 6. Verify the running agent.
$mounted = $false
for ($i = 0; $i -lt 15; $i++) {
    $ls = Run-Docker @('compose', '-f', $compose, 'exec', '-T', 'scanner-agent', 'sh', '-c',
        'ls /var/lib/openvas/plugins 2>/dev/null | head -n 3') -AllowFailure
    if ($ls.ExitCode -eq 0 -and $ls.Text.Trim()) { $mounted = $true; break }
    Start-Sleep -Seconds 2
}
if ($mounted) { Write-Ok 'Feed files are mounted in scanner-agent (/var/lib/openvas/plugins).' } else { Write-Warn 'Feed files are NOT visible in scanner-agent; the long-timeout caps stay off.' }

$seen = $false
$lines = @()
for ($i = 0; $i -lt 30; $i++) {
    $logs = Run-Docker @('compose', '-f', $compose, 'logs', '--tail', '400', 'scanner-agent') -AllowFailure
    $lines = @($logs.Text -split "`r?`n" | Where-Object { $_ -match 'AGENT BUILD|NVT timeout index|OPENVAS_LOG_SETUP' })
    if (@($lines | Where-Object { $_ -match [regex]::Escape($Build) }).Count -gt 0) { $seen = $true; break }
    Start-Sleep -Seconds 3
}
if ($seen) { Write-Ok "scanner-agent is running build $Build." } else { Write-Warn "Did not see 'AGENT BUILD $Build' in the scanner-agent log yet." }
foreach ($l in ($lines | Select-Object -Last 8)) { Write-Host "       $l" }
if (@($lines | Where-Object { $_ -match 'OPENVAS_LOG_SETUP' }).Count -gt 0) {
    Write-Host '       OPENVAS_LOG_SETUP lines describe scans already in openvas.log; they clear once a new scan has run and the agent restarts.'
}

Write-Host ''
if ($script:Warnings -gt 0) {
    Write-Host "Done with $($script:Warnings) warning(s) - see [WARN] lines above." -ForegroundColor Yellow
} else {
    Write-Host 'Done. Next scan: expect "NVT timeout index ... built", the "Base config" note about once an hour, and check names when a host waits at 98%.' -ForegroundColor Green
}
