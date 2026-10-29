# Generate docker-compose.drives.generated.yml with read-only bind mounts for
# every drive letter that is currently present on this Windows workstation.
#
# The generated override contains ONLY the dynamic drive mounts. It does not
# repeat the application's normal volumes, so it cannot accidentally replace
# worker data mounts from docker-compose.yml.
#
# Usage:
#   powershell -File scripts/generate-drive-mounts.ps1
#   powershell -File scripts/generate-drive-mounts.ps1 -RequireDrive G
#   docker compose -f docker-compose.yml -f docker-compose.drives.generated.yml up -d --force-recreate api worker-disk worker-mobile worker-report

param(
    [string[]]$AlwaysInclude = @(),
    [string[]]$RequireDrive = @(),
    [string[]]$ExcludeDrive = @(),
    [string]$SourceMapPath = "",
    [ValidateSet("Windows", "Wsl")][string]$ExecutionMode = "Windows",
    [string]$OutputPath = "",
    [string[]]$ServiceNames = @(),
    [switch]$KeepRequiredForResolution,
    # Main startup: generate ALL split-stack overrides from ONE verified inventory.
    [switch]$WriteStartupStackOverrides
)

# `powershell -File` only binds the first token of an array. Allow a comma-separated
# string so start-stack and HostDrive remount always write worker mounts too.
if ($ServiceNames -and $ServiceNames.Count -eq 1 -and "$($ServiceNames[0])" -match ',') {
    $ServiceNames = @(
        $ServiceNames[0] -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if ($OutputPath) {
    $out = if ([System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $root $OutputPath }
}
else {
    $out = Join-Path $root "docker-compose.drives.generated.yml"
}

function Normalize-DriveLetter {
    param([string]$Value)
    $text = ("$Value").Trim()
    if (-not $text) { return $null }
    if ($text -match '^([A-Za-z])(?::.*)?$') {
        return $Matches[1].ToUpper()
    }
    return $null
}


# V1.10.8: Windows storage/WMI queries (Get-Volume, Get-Partition,
# Win32_LogicalDisk) and Test-Path on an offline network share can block for
# minutes on some PCs (stuck USB card reader, disconnected mapped drive, busy
# Storage service). Startup then sat at "Refresh Windows drive/evidence mount
# configuration" with no output. Every probe below has a time limit, results
# are cached per letter, and progress is printed.
$script:ProbeTimeoutSec = 20
if ("$env:AETHERIS_DRIVE_PROBE_TIMEOUT_SEC" -match '^[0-9]+$' -and [int]$env:AETHERIS_DRIVE_PROBE_TIMEOUT_SEC -gt 0) {
    $script:ProbeTimeoutSec = [int]$env:AETHERIS_DRIVE_PROBE_TIMEOUT_SEC
}
$script:PresenceCache = @{}
$script:NetworkLetters = @{}
$script:DockerProbe = $null
$script:ProbePool = $null

function Get-ProbePool {
    # One small runspace pool for all probes: the Storage module is loaded once
    # instead of once per probe, and a probe stuck in the driver only blocks its
    # own runspace.
    if (-not $script:ProbePool) {
        $script:ProbePool = [RunspaceFactory]::CreateRunspacePool(1, 4)
        $script:ProbePool.Open()
    }
    return $script:ProbePool
}

function Write-ScanNote([string]$Message) {
    Write-Host ("    [drive scan] {0}" -f $Message)
}

function Invoke-WithTimeout {
    # Runs a script block in its own runspace and gives up after TimeoutSec.
    # Returns @{ Done = $true/$false; Output = @(...) }.
    param(
        [scriptblock]$Script,
        [object[]]$Arguments = @(),
        [int]$TimeoutSec = $script:ProbeTimeoutSec,
        [string]$Label = 'probe'
    )
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = Get-ProbePool
    $finished = $false
    try {
        [void]$ps.AddScript($Script.ToString())
        foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
        $handle = $ps.BeginInvoke()
        if (-not $handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds([double]$TimeoutSec))) {
            Write-ScanNote ("{0} did not answer within {1}s; skipped" -f $Label, $TimeoutSec)
            try { [void]$ps.BeginStop($null, $null) } catch { }
            return @{ Done = $false; Output = @() }
        }
        $finished = $true
        $result = @()
        try { $result = @($ps.EndInvoke($handle)) } catch { $result = @() }
        return @{ Done = $true; Output = $result }
    }
    catch {
        return @{ Done = $false; Output = @() }
    }
    finally {
        # Never Dispose a pipeline that is still blocked: Dispose would wait for it.
        if ($finished) { try { $ps.Dispose() } catch { } }
    }
}

function Convert-DaemonHostPathToWindowsBind {
    param([string]$Letter, [string]$Source)
    $fallback = "${Letter}:/"
    if (-not $Source) { return $fallback }
    if ($Source -match '^[A-Za-z]:[/\\]?$') {
        return ("{0}:/" -f $Source.Substring(0, 1).ToUpper())
    }
    if ($Source -match '^/(?:mnt/host|run/desktop/mnt/host|host_mnt|tmp/docker-desktop-root/mnt/host)/([A-Za-z])/?$') {
        return ("{0}:/" -f $Matches[1].ToUpper())
    }
    return $Source
}

function Read-DriveSourceMap {
    param([string]$Path)
    $map = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $map }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        $container = $obj
        if ($obj -and $obj.PSObject.Properties.Name -contains 'drives') {
            $container = $obj.drives
        }
        if ($container) {
            foreach ($prop in $container.PSObject.Properties) {
                $letter = Normalize-DriveLetter $prop.Name
                if (-not $letter) { continue }
                $value = $prop.Value
                $source = ""
                $mode = "legacy"
                if ($value -is [string]) {
                    $source = [string]$value
                }
                elseif ($value -and ($value.PSObject.Properties.Name -contains 'source')) {
                    $source = [string]$value.source
                    if ($value.PSObject.Properties.Name -contains 'mode' -and $value.mode) {
                        $mode = [string]$value.mode
                    }
                }
                if ($source) {
                    $map[$letter] = @{
                        source = $source
                        mode = $mode
                        wsl_distro = $(if ($value -and ($value.PSObject.Properties.Name -contains 'wsl_distro') -and $value.wsl_distro) { [string]$value.wsl_distro } else { '' })
                        wsl_mount = $(if ($value -and ($value.PSObject.Properties.Name -contains 'wsl_mount') -and $value.wsl_mount) { [string]$value.wsl_mount } else { '' })
                        mount_target = $(if ($value -and ($value.PSObject.Properties.Name -contains 'mount_target') -and $value.mount_target) { [string]$value.mount_target } else { '' })
                        source_scope = $(if ($value -and ($value.PSObject.Properties.Name -contains 'source_scope') -and $value.source_scope) { [string]$value.source_scope } else { '' })
                    }
                }
            }
        }
    }
    catch {
        Write-Warning ("Could not read drive source map {0}: {1}" -f $Path, $_.Exception.Message)
    }
    return $map
}

function Convert-ToYamlSingleQuoted {
    param([string]$Value)
    # YAML single-quoted scalars treat backslashes literally; double any single quote.
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-DaemonVolumeName {
    param([string]$Letter, [string]$Source)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Source)
        $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLower()
    }
    finally {
        $sha.Dispose()
    }
    return ("aetheris_hostdrive_{0}_{1}" -f $Letter.ToLower(), $hash.Substring(0, 12))
}

function Test-DriveLetterPresent {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    if ($script:PresenceCache.ContainsKey($L)) { return [bool]$script:PresenceCache[$L] }
    $present = $false
    # USB / JMicron disks often have a letter on Get-Volume/Get-Partition while
    # Win32_LogicalDisk and sometimes Test-Path still miss them.
    $vol = Invoke-WithTimeout -Label ("Get-Volume {0}:" -f $L) -Arguments @($L) -Script {
        param($x)
        $v = Get-Volume -DriveLetter $x -ErrorAction SilentlyContinue
        if ($v -and "$($v.DriveType)" -ne 'CD-ROM') { $true } else { $false }
    }
    if ($vol.Done -and @($vol.Output) -contains $true) { $present = $true }
    if (-not $present) {
        $part = Invoke-WithTimeout -Label ("Get-Partition {0}:" -f $L) -Arguments @($L) -Script {
            param($x)
            [bool](Get-Partition -DriveLetter $x -ErrorAction SilentlyContinue)
        }
        if ($part.Done -and @($part.Output) -contains $true) { $present = $true }
    }
    if (-not $present) {
        # Test-Path on a disconnected network share can block for a long time.
        $fs = Invoke-WithTimeout -Label ("Test-Path {0}:\" -f $L) -Arguments @($L) -Script {
            param($x)
            try {
                if (-not (Test-Path -LiteralPath "${x}:\")) { return $false }
                $info = [System.IO.DriveInfo]::new("${x}:\")
                if ($info.DriveType -eq [System.IO.DriveType]::CDRom -and -not $info.IsReady) { return $false }
                return $true
            }
            catch { return [bool](Test-Path -LiteralPath "${x}:\") }
        }
        if ($fs.Done -and @($fs.Output) -contains $true) { $present = $true }
    }
    $script:PresenceCache[$L] = $present
    return $present
}

function Get-HostDriveLetters {
    $found = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Write-ScanNote 'Listing Windows drive letters...'

    # Mapped network drives cannot be bind-mounted by Docker Desktop, and a
    # disconnected one blocks every file-system probe. DriveType comes from the
    # drive table without touching the share.
    try {
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            $name = "$($d.Name)".Substring(0, 1).ToUpper()
            if ($name -notmatch '^[A-Z]$') { continue }
            if ($d.DriveType -eq [System.IO.DriveType]::Network) { $script:NetworkLetters[$name] = $true }
        }
    }
    catch { }

    $sources = @(
        @{ Label = 'Get-Volume'; Script = {
            Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Za-z]$' } |
                ForEach-Object { "$($_.DriveLetter)".ToUpper() } } },
        # Get-Volume sees USB external disks that Win32_LogicalDisk omits.
        @{ Label = 'Get-Partition'; Script = {
            Get-Partition -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and "$($_.DriveLetter)" -match '^[A-Za-z]$' } |
                ForEach-Object { "$($_.DriveLetter)".ToUpper() } } },
        @{ Label = 'Win32_LogicalDisk'; Script = {
            Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.DeviceID -match '^[A-Za-z]:$' } |
                ForEach-Object { if ([int]$_.DriveType -eq 4) { 'NET:' + $_.DeviceID.Substring(0, 1).ToUpper() } else { $_.DeviceID.Substring(0, 1).ToUpper() } } } },
        @{ Label = 'Get-PSDrive'; Script = {
            Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^[A-Za-z]$' } |
                ForEach-Object { $_.Name.ToUpper() } } }
    )
    $allSourcesAnswered = $true
    foreach ($src in $sources) {
        $r = Invoke-WithTimeout -Label $src.Label -Script $src.Script
        if (-not $r.Done) { $allSourcesAnswered = $false; continue }
        foreach ($item in @($r.Output)) {
            $text = "$item"
            if ($text -match '^NET:([A-Z])$') { $script:NetworkLetters[$Matches[1]] = $true; [void]$found.Add($Matches[1]); continue }
            if ($text -match '^[A-Z]$') { [void]$found.Add($text) }
        }
    }

    # Letters Windows reports in its drive table but none of the sources above
    # listed get an individual check. When one of the sources timed out, every
    # remaining letter is checked individually (each check is time-bounded).
    $tableLetters = @{}
    try { foreach ($d in [System.IO.DriveInfo]::GetDrives()) { $tableLetters["$($d.Name)".Substring(0, 1).ToUpper()] = $true } } catch { }
    foreach ($code in ([int][char]'A')..([int][char]'Z')) {
        $letter = [string][char]$code
        if ($found.Contains($letter)) { continue }
        if ($script:NetworkLetters.ContainsKey($letter)) { continue }
        if ($allSourcesAnswered -and -not $tableLetters.ContainsKey($letter)) { continue }
        if (Test-DriveLetterPresent $letter) { [void]$found.Add($letter) }
    }

    $network = @($found | Where-Object { $script:NetworkLetters.ContainsKey($_) } | Sort-Object)
    if ($network.Count) {
        Write-ScanNote ("Skipping mapped network drive(s) {0}: Docker Desktop cannot bind-mount them. Pass -RequireDrive to force one." -f ($network -join ', '))
    }
    $local = @($found | Where-Object { -not $script:NetworkLetters.ContainsKey($_) } | Where-Object { Test-DriveLetterPresent $_ } | Sort-Object)
    Write-ScanNote ("Drive letters found: {0}" -f $(if ($local.Count) { $local -join ', ' } else { 'none' }))
    return $local
}

function Get-DockerProbeContext {
    if ($script:DockerProbe) { return $script:DockerProbe }
    $ctx = @{ Docker = $null; Image = $null }
    try { $ctx.Docker = (Get-Command docker -ErrorAction SilentlyContinue).Source } catch { $ctx.Docker = $null }
    if (-not $ctx.Docker) {
        $guess = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path -LiteralPath $guess) { $ctx.Docker = $guess }
    }
    if ($ctx.Docker) {
        # Listed once per run (it used to run once per drive).
        $r = Invoke-WithTimeout -Label 'docker images' -TimeoutSec ([Math]::Max(30, $script:ProbeTimeoutSec)) -Arguments @($ctx.Docker) -Script {
            param($docker)
            & $docker images --format "{{.Repository}}:{{.Tag}}" 2>$null |
                Where-Object { $_ -and $_ -ne "<none>:<none>" }
        }
        $images = @($r.Output | ForEach-Object { "$_" })
        # Smallest image first: a probe container should start in a second.
        foreach ($prefix in @('alpine', 'busybox', 'aetheris-gateway', 'aetheris-forensic-api', 'aetheris-mobile-extract-api')) {
            $ctx.Image = @($images | Where-Object { $_ -match ('^' + [regex]::Escape($prefix) + ':') })[0]
            if ($ctx.Image) { break }
        }
        if (-not $ctx.Image) { $ctx.Image = @($images | Select-Object -First 1)[0] }
        if (-not $ctx.Image -and "$env:AETHERIS_DRIVE_PROBE_PULL" -notmatch '^(?i)(0|false|no|off)$') {
            # A new machine (or one after an image prune) has no local image. Without one no optional drive can be
            # verified, so every drive except C: and the project drive was left out until a later start. Fetch the
            # small probe image once; the stack already uses alpine:3 for data moves. Offline: drives stay unverified.
            Write-ScanNote 'No local image to verify drives with; pulling alpine:3 once (AETHERIS_DRIVE_PROBE_PULL=false skips this)...'
            $pull = Invoke-WithTimeout -Label 'docker pull alpine:3' -TimeoutSec 180 -Arguments @($ctx.Docker) -Script {
                param($docker)
                & $docker pull alpine:3 2>&1 | Out-Null
                "exit=$LASTEXITCODE"
            }
            if ($pull.Done -and (@($pull.Output) -contains 'exit=0')) {
                $ctx.Image = 'alpine:3'
                Write-ScanNote 'Pulled alpine:3; every connected drive will be verified.'
            } else {
                Write-ScanNote 'Could not pull alpine:3 (offline?); optional drives stay unverified this time.'
            }
        }
    }
    $script:DockerProbe = $ctx
    return $ctx
}

function Test-DockerBindableWindowsDrive {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    # C: is always required for the stack; Docker Desktop shares it.
    if ($L -eq 'C') { return $true }
    $ctx = Get-DockerProbeContext
    if (-not $ctx.Docker) { return $false }
    if (-not $ctx.Image) { return $false }

    $src = "${L}:/"
    $name = "aetheris-drive-probe-{0}-{1}" -f $L.ToLower(), $PID
    $timeoutSec = [Math]::Max(30, $script:ProbeTimeoutSec)
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    try {
        # A docker run against an unreachable drive can hang inside Docker
        # Desktop file sharing; bound it and clean up the probe container.
        $argLine = 'run --rm --pull never --name {0} --mount "type=bind,source={1},target=/probe,readonly" --entrypoint /bin/true {2}' -f $name, $src, $ctx.Image
        $proc = Start-Process -FilePath $ctx.Docker -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $null = $proc.Handle  # keeps ExitCode readable after exit (Windows PowerShell 5.1)
        if (-not $proc.WaitForExit($timeoutSec * 1000)) {
            Write-ScanNote ("Docker did not finish reading {0}: within {1}s; drive skipped" -f $L, $timeoutSec)
            try { $proc.Kill() } catch { }
            try { Start-Process -FilePath $ctx.Docker -ArgumentList "rm -f $name" -NoNewWindow -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) -RedirectStandardError ([System.IO.Path]::GetTempFileName()) | Out-Null } catch { }
            return $false
        }
        $ok = ($proc.ExitCode -eq 0)
        Write-ScanNote ("Docker can read {0}: {1}" -f $L, $(if ($ok) { 'yes' } else { 'no' }))
        return $ok
    }
    catch {
        return $false
    }
    finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-DockerDriveProbes {
    # V1.10.8.1: probe all drives AT THE SAME TIME with one shared time limit.
    # One-by-one probes cost N x the limit, and on a busy Docker Desktop (the
    # old stacks are still running at this point) every probe was slow.
    # Returns @{ <letter> = 'yes' | 'no' | 'timeout' }.
    param([string[]]$Letters)
    $status = @{}
    if (-not $Letters -or -not $Letters.Count) { return $status }
    $ctx = Get-DockerProbeContext
    if (-not $ctx.Docker -or -not $ctx.Image) {
        # Never turn an unverified drive into a mounted forensic source. A stale
        # removable letter can appear in Windows while Docker Desktop cannot stat it.
        foreach ($L in $Letters) { $status[$L] = 'unverified' }
        Write-ScanNote 'No local Docker probe image available; skipping unverified optional drives.'
        return $status
    }
    $limitSec = 90
    if ("$env:AETHERIS_DRIVE_DOCKER_PROBE_TIMEOUT_SEC" -match '^[0-9]+$' -and [int]$env:AETHERIS_DRIVE_DOCKER_PROBE_TIMEOUT_SEC -gt 0) {
        $limitSec = [int]$env:AETHERIS_DRIVE_DOCKER_PROBE_TIMEOUT_SEC
    }
    Write-ScanNote ("Checking that Docker can read {0} (all at once, up to {1}s)..." -f ($Letters -join ', '), $limitSec)
    $running = @{}
    foreach ($L in $Letters) {
        $name = "aetheris-drive-probe-{0}-{1}" -f $L.ToLower(), $PID
        # --mount, unlike -v, MUST NOT create a nonexistent source directory.
        # The Docker engine checks the same Windows-drive bind used by Compose.
        $argLine = 'run --rm --pull never --name {0} --mount "type=bind,source={1}:/,target=/probe,readonly" --entrypoint /bin/true {2}' -f $name, $L, $ctx.Image
        $outFile = [System.IO.Path]::GetTempFileName()
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            $proc = Start-Process -FilePath $ctx.Docker -ArgumentList $argLine -NoNewWindow -PassThru `
                -RedirectStandardOutput $outFile -RedirectStandardError $errFile
            $null = $proc.Handle  # keeps ExitCode readable after exit (Windows PowerShell 5.1)
            $running[$L] = @{ Proc = $proc; Name = $name; Files = @($outFile, $errFile) }
        }
        catch {
            $status[$L] = 'no'
            Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
        }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($limitSec)
    $lastNote = [DateTime]::UtcNow
    while ($running.Count -and [DateTime]::UtcNow -lt $deadline) {
        foreach ($L in @($running.Keys)) {
            $p = $running[$L].Proc
            if ($p.HasExited) {
                $status[$L] = $(if ($p.ExitCode -eq 0) { 'yes' } else { 'no' })
                Write-ScanNote ("Docker can read {0}: {1}" -f $L, $(if ($status[$L] -eq 'yes') { 'yes' } else { 'no' }))
                Remove-Item -LiteralPath $running[$L].Files -Force -ErrorAction SilentlyContinue
                $running.Remove($L)
            }
        }
        if ($running.Count) {
            if (([DateTime]::UtcNow - $lastNote).TotalSeconds -ge 15) {
                Write-ScanNote ("still waiting for Docker on {0}..." -f (@($running.Keys | Sort-Object) -join ', '))
                $lastNote = [DateTime]::UtcNow
            }
            Start-Sleep -Milliseconds 250
        }
    }
    foreach ($L in @($running.Keys)) {
        $status[$L] = 'timeout'
        try { $running[$L].Proc.Kill() } catch { }
        try {
            Start-Process -FilePath $ctx.Docker -ArgumentList ("rm -f {0}" -f $running[$L].Name) -NoNewWindow `
                -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) -RedirectStandardError ([System.IO.Path]::GetTempFileName()) | Out-Null
        } catch { }
        Remove-Item -LiteralPath $running[$L].Files -Force -ErrorAction SilentlyContinue
    }
    return $status
}

function Get-PreviousMappedLetters {
    # Letters the last successful run mapped (target: '/host/<letter>').
    param([string]$Path)
    $set = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $set }
    try {
        foreach ($m in [regex]::Matches((Get-Content -LiteralPath $Path -Raw), "target:\s*'?/host/([a-zA-Z])'?")) {
            $set[$m.Groups[1].Value.ToUpper()] = $true
        }
    } catch { }
    return $set
}

$detected = @(Get-HostDriveLetters)
# Strict startup check, for example when an active case requires G:. Setting
# this makes a missing/unshareable drive an error instead of omitting it.
$envRequired = @(("$env:AETHERIS_REQUIRED_DRIVES" -split '[,;\s]+') | Where-Object { $_ })
$requested = @(
    @($AlwaysInclude) + @($RequireDrive) + $envRequired |
        ForEach-Object { Normalize-DriveLetter $_ } |
        Where-Object { $_ }
)

$missingRequested = @($requested | Where-Object { -not (Test-DriveLetterPresent $_) } | Sort-Object -Unique)
if ($missingRequested.Count) {
    throw "Requested drive(s) are not available in Windows: $($missingRequested -join ', ')"
}

# Optional persistent setting in the current PowerShell environment, e.g.
#   $env:AETHERIS_EXCLUDED_DRIVES = 'G'
# Never use it for a drive that contains the selected case evidence.
$envExcluded = @( ("$env:AETHERIS_EXCLUDED_DRIVES" -split '[,;\s]+') | Where-Object { $_ } )
$excluded = @(
    @($ExcludeDrive) + $envExcluded |
        ForEach-Object { Normalize-DriveLetter $_ } |
        Where-Object { $_ } |
        Sort-Object -Unique
)
$contradiction = @($requested | Where-Object { $excluded -contains $_ } | Sort-Object -Unique)
if ($contradiction.Count) {
    throw "Required evidence drive(s) cannot also be excluded: $($contradiction -join ', '). Unset AETHERIS_EXCLUDED_DRIVES or choose a different evidence path."
}

$letters = @(
    $detected + $requested |
        Where-Object { $_ -and (Test-DriveLetterPresent $_) -and ($excluded -notcontains $_) } |
        Sort-Object -Unique
)

# Resolve the source map before the generic Windows-root bind test.  The
# refresh job may already have proven a safer source for a removable drive
# (Docker daemon path, WSL-integrated path, or an exact selected folder).  Do
# not throw that verified source away merely because a second probe of G:/ is
# empty/stale -- that is the failure this recovery path is designed to heal.
$sourceMap = Read-DriveSourceMap -Path $SourceMapPath

$kept = New-Object System.Collections.Generic.List[string]
$skippedDocker = New-Object System.Collections.Generic.List[string]
$toProbe = New-Object System.Collections.Generic.List[string]
# The drive holding this project is bind-mounted by every stack already
# (./backend, ./frontend ...), so Docker can read it: no probe needed.
$projectDrive = if ("$root" -match '^([A-Za-z]):') { $Matches[1].ToUpper() } else { '' }
foreach ($letter in $letters) {
    $resolved = if ($sourceMap.ContainsKey($letter)) { $sourceMap[$letter] } else { $null }
    # An old successful source-state JSON does NOT prove the device is still
    # attached to Docker Desktop. In Windows mode, probe the real bind again.
    # WSL mode is used after refresh-drive-mounts-job has explicitly checked
    # the source from the integrated distro; a Windows G:/ probe would be
    # irrelevant there.
    if ($ExecutionMode -eq 'Wsl' -and $resolved -and [string]$resolved.source) {
        $kept.Add($letter) | Out-Null
        continue
    }
    # First-pass refresh discovery must not discard the examiner-selected drive
    # just because the whole drive root is not bindable. The resolver that runs
    # immediately afterwards can prove an exact selected-folder or WSL source.
    if ($KeepRequiredForResolution -and ($requested -contains $letter)) {
        $kept.Add($letter) | Out-Null
        continue
    }
    if ($letter -eq 'C' -or $letter -eq $projectDrive) {
        $kept.Add($letter) | Out-Null
        continue
    }
    $toProbe.Add($letter) | Out-Null
}
if ($toProbe.Count) {
    $probe = Invoke-DockerDriveProbes -Letters @($toProbe)
    foreach ($letter in $toProbe) {
        $state = [string]$probe[$letter]
        if ($state -eq 'yes') {
            $kept.Add($letter) | Out-Null
        }
        else {
            # On timeout, missing image, or bind failure, exclude the drive.
            # The previous mapping is NOT proof it is connected now.
            Write-ScanNote ("Excluding {0}: Docker probe returned {1}" -f $letter, $(if ($state) { $state } else { 'unknown' }))
            $skippedDocker.Add($letter) | Out-Null
        }
    }
}
$letters = @($kept | Sort-Object -Unique)
# Explicitly selected/required evidence cannot be silently lost. This guard
# applies to optional startup scans and manual remounts alike.
$unavailableRequired = @($skippedDocker | Where-Object { $requested -contains $_ })
if ($unavailableRequired.Count) {
    throw ("Required evidence drive(s) are visible in Windows but not bindable in Docker Desktop: {0}. Reconnect the drive or use the verified HostDrive/WSL remount; no substitute directory will be created." -f ($unavailableRequired -join ', '))
}
if ($skippedDocker.Count) {
    Write-Warning ("Unavailable OPTIONAL drive(s) omitted from Compose: {0}. If evidence is on one of these drives, reconnect it and refresh HostDrive before extraction. No evidence is marked processed." -f ($skippedDocker -join ', '))
}

if (-not $letters.Count) {
    throw "No ready Windows drive letters found."
}
$serviceNames = if ($ServiceNames -and $ServiceNames.Count) {
    $ServiceNames
} else {
    @('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report', 'worker-agent')
}

# Resolve the effective source and mount strategy once per drive. WSL DrvFs
# bridge paths are paths on Docker's Linux host, not Windows paths. When
# Compose is launched from Windows, using those paths directly as service bind
# sources can be client-normalized incorrectly. For that case we create a
# pre-created external local volume whose opaque `device` option is interpreted
# by the Docker engine itself. Any verified Linux-daemon path (for example
# /mnt/wsl or /run/desktop) uses that strategy; Windows/UNC sources remain
# normal bind mounts.
$driveMounts = @{}
foreach ($letter in $letters) {
    $entry = if ($sourceMap.ContainsKey($letter)) { $sourceMap[$letter] } else { $null }
    $lower = $letter.ToLower()
    if ($ExecutionMode -eq 'Wsl') {
        # When Compose itself runs inside a Docker-Desktop-integrated WSL distro,
        # use Linux-visible paths. A drive resolved through the explicit DrvFs
        # bridge keeps that exact mount point; ordinary drives use /mnt/<letter>.
        $source = if ($entry -and $entry.mode -eq 'wsl-compose' -and $entry.wsl_mount) {
            [string]$entry.wsl_mount
        } else {
            "/mnt/$lower"
        }
        $mode = if ($entry -and $entry.mode) { [string]$entry.mode } else { 'wsl-compose' }
        $daemonPath = $false
    }
    else {
        $source = if ($entry) { [string]$entry.source } else { "${letter}:/" }
        # /mnt/host/g is Docker Desktop's internal view. Saving it as an
        # external volume goes stale ("no such device") after a USB replug.
        # Compose launched from Windows reads the letter directly.
        $source = Convert-DaemonHostPathToWindowsBind -Letter $letter -Source $source
        $mode = if ($entry -and $entry.mode) { [string]$entry.mode } else { 'docker-direct' }
        $daemonPath = $source.StartsWith('/')
    }
    $target = if ($entry -and $entry.mount_target) { [string]$entry.mount_target } else { "/host/$lower" }
    $driveMounts[$letter] = @{
        source = $source
        mode = $mode
        target = $target
        source_scope = $(if ($entry -and $entry.source_scope) { [string]$entry.source_scope } else { 'drive' })
        daemon_path = $daemonPath
        volume_name = $(if ($daemonPath) { Get-DaemonVolumeName -Letter $letter -Source $source } else { "" })
    }
}

function New-DriveComposeText {
    param([string[]]$TargetServices)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Auto-generated dynamic Windows drive mounts. Do not edit by hand.') | Out-Null
    $lines.Add('# Regenerate: powershell -File scripts/generate-drive-mounts.ps1') | Out-Null
    $lines.Add($(if ($ExecutionMode -eq 'Wsl') { '# WSL execution mode: Linux-visible paths are mounted directly by Docker Desktop WSL Integration.' } else { '# Direct Windows paths use bind mounts. Verified daemon paths use pre-created external volumes.' })) | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('services:') | Out-Null

    foreach ($service in $TargetServices) {
        $lines.Add("  ${service}:") | Out-Null
        $lines.Add('    volumes:') | Out-Null
        foreach ($letter in $letters) {
            $lower = $letter.ToLower()
            $m = $driveMounts[$letter]
            if ($m.daemon_path) {
                $lines.Add('      - type: volume') | Out-Null
                $lines.Add(("        source: {0}" -f $m.volume_name)) | Out-Null
                $lines.Add(('        target: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.target)))) | Out-Null
                $lines.Add('        read_only: true') | Out-Null
                $lines.Add('        volume:') | Out-Null
                $lines.Add('          nocopy: true') | Out-Null
            }
            else {
                $lines.Add('      - type: bind') | Out-Null
                $lines.Add(('        source: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.source)))) | Out-Null
                $lines.Add(('        target: {0}' -f (Convert-ToYamlSingleQuoted ([string]$m.target)))) | Out-Null
                $lines.Add('        read_only: true') | Out-Null
                $lines.Add('        bind:') | Out-Null
                $lines.Add('          create_host_path: false') | Out-Null
            }
        }
    }

    $daemonLetters = @($letters | Where-Object { $driveMounts[$_].daemon_path })
    if ($daemonLetters.Count) {
        $lines.Add('') | Out-Null
        $lines.Add('volumes:') | Out-Null
        foreach ($letter in $daemonLetters) {
            $m = $driveMounts[$letter]
            $lines.Add(("  {0}:" -f $m.volume_name)) | Out-Null
            $lines.Add('    external: true') | Out-Null
            $lines.Add(("    name: {0}" -f $m.volume_name)) | Out-Null
        }
    }

    return (($lines -join "`n") + "`n")
}

function Write-VerifiedDriveOverride {
    param([string]$Path, [string[]]$Services)
    $content = New-DriveComposeText -TargetServices $Services
    # Always write to a sibling temp file first. The live override is never a
    # half-written YAML document, even if the process is interrupted mid-write.
    $tempPath = "${Path}.${PID}.tmp"
    try {
        [System.IO.File]::WriteAllText($tempPath, $content, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
    Write-ScanNote ("Updated {0}: {1}" -f ([System.IO.Path]::GetFileName($Path)), ($letters -join ', '))
}

# All product overlays must be derived from the SAME verified drive
# inventory. The former launcher refreshed only the unused generic override;
# stale G:/ binds remained in docker-compose.drives.forensic.yml forever.
Write-VerifiedDriveOverride -Path $out -Services $serviceNames
if ($WriteStartupStackOverrides) {
    $startupOverrides = @(
        @{ File = 'docker-compose.drives.forensic.yml'; Services = @('api', 'worker-disk', 'worker-parse', 'worker-report', 'worker-agent') },
        @{ File = 'docker-compose.drives.mobile-android.yml'; Services = @('api', 'worker-build', 'worker-parse') },
        @{ File = 'docker-compose.drives.mobile-ios.yml'; Services = @('api', 'worker-build', 'worker-parse') },
        # Malware Detection reads evidence (read-only, like every overlay here) when a job has no
        # MinIO copy and its bytes must come from the original disk image.
        @{ File = 'docker-compose.drives.mobile-malware.yml'; Services = @('api', 'worker-scan', 'worker-static', 'worker-ml-gpu') }
    )
    foreach ($row in $startupOverrides) {
        Write-VerifiedDriveOverride -Path (Join-Path $root $row.File) -Services $row.Services
    }
}

# Release probe runspaces without waiting for one that is stuck in a driver call.
if ($script:ProbePool) { try { [void]$script:ProbePool.BeginClose($null, $null) } catch { } }
# IMPORTANT: Invoke-DriveGenerator captures the success/output stream. Write-Host
# uses the host/information stream in Windows PowerShell 5.1, so the refresh job
# would otherwise see an empty result and incorrectly report "no drive letters".
Write-Output "Letters: $($letters -join ', ')"
