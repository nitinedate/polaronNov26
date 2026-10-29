# Aetheris / Polaron Windows Docker launcher.
# Windows PowerShell 5.1 compatible.
# Public profiles validate certificates and start the HTTPS edge before product stacks.

[CmdletBinding()]
param(
    [ValidateSet('local', 'nitin', 'prod')]
    [string]$Profile = 'local',
    [string]$PublicIP = '',
    [string]$Domain = '',
    [string]$AcmeEmail = '',
    [switch]$PrepareOnly,
    [switch]$ValidateOnly,
    [switch]$RefreshDependencies,
    [switch]$AutoRecoverEngine,
    [switch]$NoCache
)

$ErrorActionPreference = 'Stop'
# PowerShell 7 otherwise turns a missing Docker network (exit 1) into a terminating
# error before the launcher can create aetheris-common.
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$libPath = Join-Path $scriptDir 'start_docker.lib.ps1'

if (-not (Test-Path -LiteralPath $libPath -PathType Leaf)) {
    Write-Host "ERROR: Missing startup library: $libPath" -ForegroundColor Red
    Write-Host 'Extract the complete project ZIP and retry.' -ForegroundColor Yellow
    exit 2
}

. $libPath

function Write-Ok([string]$Message) { Write-Host "    $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "    $Message" -ForegroundColor Yellow }

function Get-RunningContainerIds {
    $ids = @(& docker ps -q 2>$null)
    return @($ids | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
}

function Stop-PolaronStacks {
    # Stop only owned project containers; never run global docker stop/prune.
    # V1.10.8.1: all Polaron containers are stopped in ONE parallel docker stop
    # (each still gets 45 s to shut down cleanly), with progress every 10 s.
    # Before, the six projects were stopped one after another and the console
    # showed nothing while e.g. the 11 vulnerability containers shut down.
    Write-Step 'Stop existing Polaron project containers (preserve volumes/evidence)'
    Stop-PodmanAetherisContainers
    $names = @('aetheris-gateway','aetheris-vuln','aetheris-mobile-malware','aetheris-mobile-ios','aetheris-mobile-android','aetheris-forensic','aetheris-common')
    $all = New-Object System.Collections.ArrayList
    foreach ($name in $names) {
        $ids = @(& docker ps -q --filter "label=com.docker.compose.project=$name")
        if ($LASTEXITCODE -ne 0) { throw "Cannot query owned containers for $name" }
        $ids = @($ids | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
        if ($ids.Count -gt 0) {
            Write-Host "    $name : $($ids.Count) running container(s)"
            foreach ($id in $ids) { [void]$all.Add($id) }
        }
    }
    if ($all.Count -eq 0) {
        Write-Ok 'No Polaron containers are running.'
        return
    }
    Write-Host ("    Stopping {0} containers together (each gets up to 45 s to shut down cleanly)..." -f $all.Count)
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = Start-Process -FilePath 'docker' -ArgumentList (@('stop', '--time', '45') + @($all)) -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $null = $proc.Handle  # keeps ExitCode readable after exit (Windows PowerShell 5.1)
        $hardLimitSec = 150
        if ("$env:AETHERIS_STOP_HARD_LIMIT_SEC" -match '^[0-9]+$' -and [int]$env:AETHERIS_STOP_HARD_LIMIT_SEC -gt 0) {
            $hardLimitSec = [int]$env:AETHERIS_STOP_HARD_LIMIT_SEC
        }
        while (-not $proc.WaitForExit(10000)) {
            $running = @(Get-RunningContainerIds)
            $left = @($all | Where-Object { $running -contains $_ })
            Write-Host ("    ... {0:n0} s, {1} of {2} still shutting down" -f $sw.Elapsed.TotalSeconds, $left.Count, $all.Count)
            if ($sw.Elapsed.TotalSeconds -ge $hardLimitSec) {
                Write-Warn ("docker stop did not return after {0} s; forcing the remaining {1} container(s) to stop." -f $hardLimitSec, $left.Count)
                try { $proc.Kill() } catch { }
                if ($left.Count) { & docker kill @left *> $null }
                break
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
    $running = @(Get-RunningContainerIds)
    $left = @($all | Where-Object { $running -contains $_ })
    if ($left.Count) {
        throw ("Cannot stop {0} Polaron container(s) ({1}); refusing to start competing containers. Restart Docker Desktop and retry." -f $left.Count, ($left -join ', '))
    }
    Write-Ok ("Stopped {0} containers in {1:n0} s." -f $all.Count, $sw.Elapsed.TotalSeconds)
}

function Assert-StartupAssets {
    # Validate the exact gateway files used by the configured profile.
    param([bool]$Public)
    $files = if ($Public) {
        @('deployment/windows-ip-https/docker-compose.gateway-public-https.yml',
          'deployment/windows-ip-https/nginx.gateway.https.conf')
    } else {
        @('deployment/windows-ip-https/docker-compose.gateway-local.yml')
    }
    foreach ($file in $files) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $file) -PathType Leaf)) {
            throw "Required gateway asset missing: $file. Restore the complete deployment directory before restarting containers."
        }
    }
}

function Assert-RuntimeHealth {
    Write-Step 'Verify gateway, API health, and evidence drive mounts'
    $required = @(
        @{ Project='aetheris-common'; Service='redis' },
        @{ Project='aetheris-forensic'; Service='api' },
        @{ Project='aetheris-mobile-android'; Service='api' },
        @{ Project='aetheris-mobile-ios'; Service='api' },
        @{ Project='aetheris-mobile-malware'; Service='api' }
    )
    foreach ($row in $required) {
        if (-not (Wait-ComposeServiceReady -ProjectName $row.Project -Service $row.Service -TimeoutSeconds 120)) {
            throw "Service not ready: $($row.Project)/$($row.Service). Check docker logs and proxy upstream."
        }
    }
    $gatewayState = Get-ComposeServiceContainerState -ProjectName 'aetheris-gateway' -Service 'gateway'
    if (-not $gatewayState -or $gatewayState.Status -ne 'running') {
        throw 'Gateway is not running. API polling would return 502.'
    }
    $mountConfig = Join-Path $root 'docker-compose.drives.generated.yml'
    if (Test-Path -LiteralPath $mountConfig) {
        $content = Get-Content -LiteralPath $mountConfig -Raw
        if (-not $content.Trim() -or $content.Trim() -eq 'services:') {
            throw 'Generated drive mount configuration is empty; Windows evidence drives would be inaccessible.'
        }
    } else {
        throw 'Missing generated drive override. Check drive generator and disk availability.'
    }
    # Validate from inside the API rather than trusting frontend's static Online badge.
    $apiId = @(& docker ps -q --filter 'label=com.docker.compose.project=aetheris-mobile-android' --filter 'label=com.docker.compose.service=api')
    if ($apiId.Count -lt 1 -or -not $apiId[0]) { throw 'Android API container not found.' }
    $probe = @(& docker exec $apiId[0] python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=8).read()" 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Android API /health failed: $($probe -join ' ')" }
    Write-Ok 'Gateway, APIs and generated drive mapping validated.'
}

function Invoke-DriveMountRefresh {
    # Refresh ALL split-stack overrides with a single verified Windows/Docker
    # inventory. Generic docker-compose.drives.generated.yml is NOT consumed by
    # Get-StackComposeArgs for forensic or mobile stacks.
    # A timed-out or failed scan MUST NOT reuse yesterday's G:/ mapping.
    param([string]$Generator, [bool]$Public)
    $timeoutSec = 240
    if ("$env:AETHERIS_DRIVE_SCAN_TIMEOUT_SEC" -match '^[0-9]+$' -and [int]$env:AETHERIS_DRIVE_SCAN_TIMEOUT_SEC -gt 0) {
        $timeoutSec = [int]$env:AETHERIS_DRIVE_SCAN_TIMEOUT_SEC
    }
    $required = @(
        'docker-compose.drives.generated.yml',
        'docker-compose.drives.forensic.yml',
        'docker-compose.drives.mobile-android.yml',
        'docker-compose.drives.mobile-ios.yml',
        'docker-compose.drives.mobile-malware.yml'
    )
    $startedUtc = [DateTime]::UtcNow.AddSeconds(-2)
    Write-Host ("    Scanning drives for ALL product stacks (time limit {0}s)..." -f $timeoutSec)
    $proc = Start-Process -FilePath 'powershell.exe' -NoNewWindow -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $Generator),
        '-WriteStartupStackOverrides')
    $null = $proc.Handle  # keeps ExitCode readable after exit in PowerShell 5.1
    if (-not $proc.WaitForExit($timeoutSec * 1000)) {
        & taskkill.exe /PID $proc.Id /T /F *> $null
        throw ("Drive scan timed out after {0}s. Refusing stale drive mappings (e.g. disconnected G:). Check/remove offline USB/network drives or raise AETHERIS_DRIVE_SCAN_TIMEOUT_SEC, then retry." -f $timeoutSec)
    }
    if ($proc.ExitCode -ne 0) {
        throw ("Drive scan failed (exit {0}). No stale drive override will be reused. Reconnect required evidence disks or inspect the scan output." -f $proc.ExitCode)
    }
    foreach ($file in $required) {
        $path = Join-Path $root $file
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Drive scan did not produce required product override: $file"
        }
        $item = Get-Item -LiteralPath $path
        $content = Get-Content -LiteralPath $path -Raw
        if ($item.LastWriteTimeUtc -lt $startedUtc -or
            -not $content -or $content -notmatch '(?m)^services:\s*$' -or
            $content -notmatch '(?m)^\s+target:') {
            throw "Drive override is stale or empty: $file. Refusing the previous G: bind configuration."
        }
    }
    $forensicFile = Join-Path $root 'docker-compose.drives.forensic.yml'
    $forensicText = Get-Content -LiteralPath $forensicFile -Raw
    $mapped = @([regex]::Matches($forensicText, "/host/([a-z])'") |
        ForEach-Object { $_.Groups[1].Value.ToUpper() } | Sort-Object -Unique)
    Write-Ok ("Current forensic drive mounts: {0}" -f $(if ($mapped.Count) { $mapped -join ', ' } else { 'none' }))
    Write-Ok 'Generic, forensic, Android, iOS and Malware Detection drive overlays refreshed from one verified scan.'
}

function Show-NewLogLines {
    # Print the complete lines a running process has added to its log since the last call; returns the new count.
    # -Final also prints a last line that has no newline yet.
    param([string]$Path, [int]$Shown, [switch]$Final)
    if (-not (Test-Path -LiteralPath $Path)) { return $Shown }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { $text = (New-Object System.IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
    } catch { return $Shown }
    if (-not $text) { return $Shown }
    $lines = @($text -split "`r?`n")
    if ($text.EndsWith("`n") -or -not $Final) { $lines = @($lines | Select-Object -First ([Math]::Max(0, $lines.Count - 1))) }
    for ($i = $Shown; $i -lt $lines.Count; $i++) {
        if ([string]$lines[$i]) { Write-Host ('    ' + $lines[$i]) }
    }
    return [Math]::Max($Shown, $lines.Count)
}

function Ensure-WorkstationHelper {
    # Connected phones (detection, Device -> Image, and Malware Detection's "Scan a connected phone") need the
    # Polaron host helper and the examiner kit (tools\host-python with pymobiledevice3, tools\platform-tools\adb)
    # on this workstation. ensure-host-drive-helper.ps1 installs the kit when missing and restarts a helper that
    # is older than this release, so a deployment never leaves phones on yesterday's helper. Never fatal.
    Write-Step 'Ensure the workstation helper for connected phones (detection and direct malware scans)'
    $ensure = Join-Path $root 'scripts/ensure-host-drive-helper.ps1'
    if (-not (Test-Path -LiteralPath $ensure -PathType Leaf)) {
        Write-Warn "Missing $ensure; connected phones cannot be detected or scanned directly."
        return
    }
    # Wait for the setup script to EXIT, never for its output to END: the helper it starts keeps running in the
    # background and inherits the script's output handles, so piping that output (| ForEach-Object) waits forever.
    # The output goes to a log file instead, shown line by line while the script runs.
    $log = Join-Path ([System.IO.Path]::GetTempPath()) ('aetheris-helper-setup-' + [guid]::NewGuid().ToString('N') + '.log')
    $errLog = $log + '.err'
    $code = $null
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError $errLog `
            -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $ensure))
        $null = $proc.Handle  # keeps ExitCode readable after exit in Windows PowerShell 5.1
        $deadline = (Get-Date).AddMinutes(15)  # first run may download the examiner kit
        $shown = 0
        while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
            $shown = Show-NewLogLines -Path $log -Shown $shown
            Start-Sleep -Milliseconds 500
        }
        $shown = Show-NewLogLines -Path $log -Shown $shown -Final
        $null = Show-NewLogLines -Path $errLog -Shown 0 -Final
        if ($proc.HasExited) { $code = $proc.ExitCode } else { Write-Warn "Helper setup is still running after 15 minutes; continuing. Its log: $log" }
    } catch {
        Write-Warn "Could not run the helper setup: $($_.Exception.Message)"
    }
    $port = 9876
    if ("$env:HOST_DRIVE_HELPER_PORT" -match '^[0-9]+$') { $port = [int]$env:HOST_DRIVE_HELPER_PORT }
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 10
        $running = [string]$health.helper_version
        $onDisk = $null
        $helperFile = Join-Path $root 'scripts/host-drive-helper.ps1'
        if (Test-Path -LiteralPath $helperFile) {
            $m = Select-String -LiteralPath $helperFile -Pattern '\$script:HelperVersion\s*=\s*"([0-9.]+)"' | Select-Object -First 1
            if ($m) { $onDisk = $m.Matches[0].Groups[1].Value }
        }
        if ($health.malware_triage) {
            Write-Ok "Workstation helper v$running is running: phones are detected and can be scanned directly."
        } elseif ($onDisk -and $running -and $onDisk -ne $running) {
            # The helper is running an old version even though a newer script is on disk here: the setup could not
            # replace the running one (another Polaron folder, or it is launched from elsewhere).
            Write-Warn "Workstation helper is still v$running but this folder has v$onDisk. The old helper did not get replaced."
            Write-Warn "Run scripts\ensure-host-drive-helper.ps1 -ForceRestart on the workstation. If it stays old, another"
            Write-Warn "Polaron folder is running the helper - close it (or restart the workstation) and run from this folder."
        } elseif ($onDisk -and $onDisk -ne '5.55' -and -not $health.malware_triage) {
            Write-Warn "This Polaron folder's helper is v$onDisk, older than this release. Overlay the latest patch onto THIS folder, then run start_docker again."
        } else {
            Write-Warn "Workstation helper v$running cannot read phones for Malware Detection yet. Run scripts\ensure-host-drive-helper.ps1 -ForceRestart."
        }
    } catch {
        Write-Warn "Workstation helper is not answering (setup exit $code). Phone detection and Scan a connected phone need it: run scripts\ensure-host-drive-helper.ps1."
    }
}

function Assert-DockerReady {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        throw 'Docker CLI was not found. Install/start Docker Desktop in Linux container mode.'
    }
    . (Join-Path $root 'scripts/docker-engine-recovery.ps1')
    . (Join-Path $root 'scripts/assert-docker-ready.ps1')
    Assert-PolaronDockerReady -Docker $docker.Source -AutoRecoverEngine:$AutoRecoverEngine
    Write-Ok 'Docker Desktop Linux engine and Compose are ready.'
}

function Get-ComposeConfig {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    $raw = & docker @ComposeArgs config --format json
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose validation failed: docker $($ComposeArgs -join ' ') config" }
    try { return (($raw -join "`n") | ConvertFrom-Json) }
    catch { throw "Docker Compose returned invalid JSON while validating: docker $($ComposeArgs -join ' ') config" }
}

function Get-AllStackDefinitions {
    $rows = @()
    foreach ($name in @('common', 'forensic', 'mobile-android', 'mobile-ios', 'mobile-malware', 'vuln')) {
        $rows += [pscustomobject]@{ Name = $name; Args = @(Get-StackComposeArgs -Root $root -Name $name) }
    }
    $gateway = @('compose', '--project-directory', $root, '--project-name', 'aetheris-gateway',
        '-f', 'services/gateway/docker-compose.yml',
        '-f', 'deployment/windows-ip-https/docker-compose.gateway-local.yml')
    $rows += [pscustomobject]@{ Name = 'gateway'; Args = $gateway }
    return @($rows)
}

function Assert-AllComposeFiles {
    param([switch]$CreateRuntimeDirectories)
    Write-Step 'Validate product Compose files and bind mounts'
    foreach ($stack in @(Get-AllStackDefinitions)) {
        $cfg = Get-ComposeConfig -ComposeArgs $stack.Args
        Assert-DeploymentComposePaths -Root $root -Config $cfg -ValidateOnly:(-not $CreateRuntimeDirectories)
        Write-Ok "$($stack.Name) Compose configuration is valid."
    }

    # Public gateway is a separate validation path because it references the generated
    # certificate-backed nginx config. Assert-DeploymentComposePaths explicitly permits it.
    foreach ($publicProfile in @('nitin', 'prod')) {
        $args = @('compose', '--project-directory', $root, '--project-name', 'aetheris-gateway',
            '-f', 'services/gateway/docker-compose.yml',
            '-f', 'deployment/windows-ip-https/docker-compose.gateway-public-https.yml')
        $cfg = Get-ComposeConfig -ComposeArgs $args
        Assert-DeploymentComposePaths -Root $root -Config $cfg -ValidateOnly:(-not $CreateRuntimeDirectories)
    }
}

function Invoke-StackBuild {
    param([string]$Name, [string[]]$ComposeArgs, [string]$BuildId)
    $args = @($ComposeArgs) + @(Get-AppBuildArgs -BuildId $BuildId -RefreshDependencies:($RefreshDependencies -or $NoCache))
    Invoke-Docker -Title "Build/compile $Name" -DockerArgs $args
}

function Remove-ForeignComposeContainerNames {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs
    )
    # A container created outside this Compose project can keep the canonical
    # service name. Compose then fails with "name already in use" and the
    # whole product stack stops. Remove only a name holder that is not this
    # project and service. Volumes and evidence stay in place.
    $project = "aetheris-$Name"
    $cfg = Get-ComposeConfig -ComposeArgs $ComposeArgs
    if (-not $cfg.services) { return }
    foreach ($property in @($cfg.services.PSObject.Properties)) {
        $service = [string]$property.Name
        $spec = $property.Value
        $expected = @()
        if ($spec.container_name) {
            $expected += [string]$spec.container_name
        } else {
            $replicas = 1
            if ($spec.deploy -and $spec.deploy.replicas) { $replicas = [int]$spec.deploy.replicas }
            if ($replicas -lt 1) { $replicas = 1 }
            for ($index = 1; $index -le $replicas; $index++) {
                $expected += "$project-$service-$index"
            }
        }
        foreach ($containerName in $expected) {
            $ids = @(& docker ps -aq --filter "name=$containerName")
            if ($LASTEXITCODE -ne 0) { throw "Cannot query containers named $containerName" }
            foreach ($id in $ids) {
                $cid = ([string]$id).Trim()
                if (-not $cid) { continue }
                $raw = & docker inspect $cid
                if ($LASTEXITCODE -ne 0) { continue }
                $item = @((($raw -join "`n") | ConvertFrom-Json))[0]
                if ([string]$item.Name -ne "/$containerName") { continue }
                $labels = $item.Config.Labels
                $ownedProject = ''
                $ownedService = ''
                if ($labels) {
                    $ownedProject = [string]$labels.'com.docker.compose.project'
                    $ownedService = [string]$labels.'com.docker.compose.service'
                }
                if ($ownedProject -eq $project -and $ownedService -eq $service) { continue }
                $owner = if ($ownedProject -or $ownedService) { "$ownedProject/$ownedService" } else { 'no Compose project' }
                Write-Warn "Removing $containerName ($cid). It is owned by $owner, so $project/$service cannot take its name."
                $code = Invoke-DockerNativeSafe -DockerArgs @('rm', '-f', $cid) -Quiet
                if ($code -ne 0) { throw "Could not remove $containerName, which blocks $project/$service." }
            }
        }
    }
}

function Clear-StackPublishedPorts {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs,
        [string[]]$Services
    )
    # Another Docker project, or a stopped container that still reserves the
    # host port, makes `compose up` fail with "ports are not available".
    # Remove that container. The engine and WSL relay stay running.
    if (-not (Get-Command Clear-OccupiedHostPorts -ErrorAction SilentlyContinue)) {
        $script = Join-Path $root 'scripts\free-published-ports.ps1'
        if (-not (Test-Path -LiteralPath $script)) { return }
        . $script
    }
    if (-not $Services -or @($Services).Count -eq 0) {
        $cfg = Get-ComposeConfig -ComposeArgs $ComposeArgs
        if (-not $cfg -or -not $cfg.services) { return }
        $Services = @($cfg.services.PSObject.Properties.Name)
    }
    Clear-OccupiedHostPorts -Docker 'docker' -ComposeArgs $ComposeArgs -Services @($Services)
}

function Invoke-StackUp {
    param([string]$Name, [string[]]$ComposeArgs)
    Remove-ForeignComposeContainerNames -Name $Name -ComposeArgs $ComposeArgs
    Clear-StackPublishedPorts -ComposeArgs $ComposeArgs
    Ensure-ComposeExternalVolumes -ComposeArgs $ComposeArgs
    Ensure-ComposeImagesPresent -ComposeArgs $ComposeArgs
    $upArgs = @($ComposeArgs) + @('up', '-d', '--no-build', '--pull', 'missing')
    $code = Invoke-Docker -Title "Start $Name" -DockerArgs $upArgs -PassThru
    if ($code -eq 0) { return }
    if (Test-DockerRegistryDnsFailure $script:AetherisLastDockerText) {
        throw "Docker action 'Start $Name' failed (exit $code)."
    }
    $firstCode = $code
    # Replacing the API sends SIGTERM, which is exit 143. Compose then reports
    # "dependency api failed to start" and leaves workers Created, even when the
    # replacement API is coming up. Wait until it is healthy and start them.
    $project = "aetheris-$Name"
    $ready = Wait-ComposeServiceReady -ProjectName $project -Service 'api' -TimeoutSeconds 240
    if (-not $ready) {
        throw "Docker action 'Start $Name' failed (exit $firstCode)."
    }
    Write-Host "    $Name API is healthy after the recreate. Starting services left created."
    & docker @upArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker action 'Start $Name' failed (exit $LASTEXITCODE)."
    }
}

function Ensure-MobileCoreWorkersStarted {
    param([string]$Name, [string[]]$ComposeArgs)
    if ($Name -notin @('mobile-android', 'mobile-ios')) { return }

    $projectName = "aetheris-$Name"
    # The build/parse pools depend on both API health and CUDA health. Docker Compose
    # may leave them in `created` for a short period after detached startup. Wait for
    # both dependencies, then explicitly reconcile only the core pools that are still
    # created. This avoids false startup failures and guarantees the workers actually
    # start before the global readiness gate completes.
    $apiReady = Wait-ComposeServiceReady -ProjectName $projectName -Service 'api' -TimeoutSeconds 240
    $cudaReady = Wait-ComposeServiceReady -ProjectName $projectName -Service 'nvidia-cuda' -TimeoutSeconds 120
    if (-not $apiReady -or -not $cudaReady) {
        Write-Warn "$Name dependencies are still warming (apiReady=$apiReady cudaReady=$cudaReady); global readiness will continue to monitor them."
        return
    }

    foreach ($service in @('worker-build','worker-parse')) {
        $state = Get-ComposeServiceContainerState -ProjectName $projectName -Service $service
        if ($state -and $state.Status -eq 'created') {
            Write-Host "    Starting deferred $Name/$service after API + CUDA became healthy..." -ForegroundColor DarkCyan
            $code = Invoke-DockerNativeSafe -DockerArgs ($ComposeArgs + @('up','-d','--no-build','--pull','missing',$service))
            if ($code -ne 0) {
                Write-Warn "Deferred worker start returned exit code $code for $Name/$service; readiness loop will retry/diagnose."
            }
        }
    }
}

function Get-ComposeServiceContainerState {
    param([string]$ProjectName, [string]$Service)
    $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$ProjectName" --filter "label=com.docker.compose.service=$Service")
    if ($LASTEXITCODE -ne 0 -or -not $ids.Count) { return $null }
    $raw = & docker inspect ([string]$ids[0])
    if ($LASTEXITCODE -ne 0) { return $null }
    $item = (($raw -join "`n") | ConvertFrom-Json)[0]
    return [pscustomobject]@{
        Id = [string]$item.Id
        Status = [string]$item.State.Status
        Health = if ($item.State.Health) { [string]$item.State.Health.Status } else { 'none' }
        ExitCode = [int]$item.State.ExitCode
    }
}

function Wait-ComposeServiceReady {
    param(
        [string]$ProjectName,
        [string]$Service,
        [int]$TimeoutSeconds = 180,
        [switch]$AllowStartingHealth
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = Get-ComposeServiceContainerState -ProjectName $ProjectName -Service $Service
        if ($state) {
            if ($state.Status -eq 'running' -and $state.Health -in @('none','healthy')) { return $true }
            if ($AllowStartingHealth -and $state.Status -eq 'running' -and $state.Health -eq 'starting') { return $true }
            if ($state.Status -eq 'exited' -or $state.Status -eq 'dead') { return $false }
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-DockerNativeSafe {
    param(
        [Parameter(Mandatory = $true)][string[]]$DockerArgs,
        [switch]$Quiet
    )
    # Docker/Compose writes normal progress (Creating/Stopping/Removed) to stderr.
    # Windows PowerShell 5.1 can convert native stderr into ErrorRecord objects; with
    # $ErrorActionPreference='Stop' that normal progress can abort the whole launcher.
    # Temporarily use Continue, merge stderr into stdout, and trust the native exit code.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($Quiet) {
            & docker @DockerArgs 2>&1 | Out-Null
        } else {
            & docker @DockerArgs 2>&1 | ForEach-Object { Write-Host ([string]$_) }
        }
        return [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
}

function Remove-ComposeOneShotContainer {
    param([string]$ProjectName, [string]$Service, [int]$TimeoutSeconds = 30)
    $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$ProjectName" --filter "label=com.docker.compose.service=$Service")
    if ($LASTEXITCODE -ne 0 -or -not $ids.Count) { return $true }
    foreach ($id in $ids) {
        $cid = ([string]$id).Trim()
        if (-not $cid) { continue }
        [void](Invoke-DockerNativeSafe -DockerArgs @('update','--restart=no',$cid) -Quiet)
        [void](Invoke-DockerNativeSafe -DockerArgs @('rm','-f',$cid) -Quiet)
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $left = @(& docker ps -aq --filter "label=com.docker.compose.project=$ProjectName" --filter "label=com.docker.compose.service=$Service")
        if ($LASTEXITCODE -eq 0 -and -not $left.Count) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-VulnOneShot {
    param([string[]]$ComposeArgs, [string]$Service, [int]$Attempts = 2)
    $projectName = 'aetheris-vuln'
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        Write-Host "    Greenbone feed/init: $Service (attempt $attempt/$Attempts)" -ForegroundColor DarkCyan

        # A previous interrupted launch can leave the canonical service container in
        # created/restarting/stopping state. Remove only that disposable container; the
        # named Greenbone feed volumes are preserved. Do not use `compose rm` here because
        # its progress stream can be promoted to a terminating PowerShell error.
        if (-not (Remove-ComposeOneShotContainer -ProjectName $projectName -Service $Service -TimeoutSeconds 30)) {
            Write-Warn "Could not fully remove stale initializer container for $Service; retrying after Docker settles."
            Start-Sleep -Seconds 3
        }

        $runArgs = @($ComposeArgs) + @('--profile','gvm','run','--rm','--no-deps','--pull','missing',$Service)
        $exitCode = Invoke-DockerNativeSafe -DockerArgs $runArgs
        if ($exitCode -eq 0) {
            Write-Ok "Greenbone initializer '$Service' completed."
            return $true
        }

        Write-Warn "Greenbone initializer '$Service' returned exit code $exitCode."
        if ($attempt -lt $Attempts) {
            Write-Warn "$Service did not finish cleanly. Waiting for Docker memory to settle before retry."
            Start-Sleep -Seconds 12
        }
    }
    return $false
}

function Start-VulnerabilityStackPhased {
    param([string[]]$ComposeArgs)
    Remove-ForeignComposeContainerNames -Name 'vuln' -ComposeArgs $ComposeArgs
    Clear-StackPublishedPorts -ComposeArgs $ComposeArgs -Services @('api')
    Write-Step 'Start vulnerability control plane (lightweight)'
    Invoke-Docker -Title 'Start vulnerability API' -DockerArgs ($ComposeArgs + @('up','-d','--no-build','--pull','missing','--no-deps','api'))

    # Greenbone data images are volume loaders. Running all of them with KEEP_ALIVE caused
    # large concurrent memory spikes in Docker Desktop and exit 137. Run each loader once,
    # sequentially, then release its RAM before moving to the next feed.
    Write-Step 'Initialize Greenbone feeds sequentially'
    $oneShots = @(
        'gpg-data',
        'vulnerability-tests',
        'notus-data',
        'scap-data',
        'cert-bund-data',
        'dfn-cert-data',
        'data-objects',
        'report-formats',
        'pg-gvm-migrator',
        'configure-openvas'
    )
    foreach ($service in $oneShots) {
        if (-not (Invoke-VulnOneShot -ComposeArgs $ComposeArgs -Service $service -Attempts 2)) {
            Write-Warn "Greenbone initializer '$service' did not finish successfully. The platform will continue; vulnerability scanning will report feed warming/unavailable until repaired."
            break
        }
    }

    Write-Step 'Start Greenbone runtime in dependency order'
    $gvmArgs = @($ComposeArgs) + @('--profile','gvm')
    foreach ($service in @('redis-gvm','pg-gvm')) {
        & docker @($gvmArgs + @('up','-d','--no-build','--pull','missing','--no-deps',$service))
        if ($LASTEXITCODE -ne 0) { Write-Warn "Could not start $service; scanner engine will remain degraded."; continue }
        if (-not (Wait-ComposeServiceReady -ProjectName 'aetheris-vuln' -Service $service -TimeoutSeconds 180 -AllowStartingHealth)) {
            Write-Warn "$service is not ready yet; scanner engine will continue warming in the background."
        }
    }
    foreach ($service in @('openvas','openvasd','ospd-openvas','gvmd','gvm-tools')) {
        & docker @($gvmArgs + @('up','-d','--no-build','--pull','missing','--no-deps',$service))
        if ($LASTEXITCODE -ne 0) { Write-Warn "Could not start $service; scanner engine will remain degraded."; continue }
        if (-not (Wait-ComposeServiceReady -ProjectName 'aetheris-vuln' -Service $service -TimeoutSeconds 90 -AllowStartingHealth)) {
            Write-Warn "$service is not ready yet; scanner engine will continue warming in the background."
        }
    }

    # Start the application worker only after the scanner sockets have been given a chance to
    # appear. It can still run while Greenbone finishes feed import and will expose readiness.
    & docker @($ComposeArgs + @('up','-d','--no-build','--pull','missing','--no-deps','worker-nessus'))
    if ($LASTEXITCODE -ne 0) { throw 'Vulnerability worker could not be started.' }

    Write-Step 'Start optional vulnerability sidecars'
    $sidecarArgs = @($ComposeArgs) + @('--profile','vuln-scanners')
    foreach ($service in @('trivy','zap')) {
        & docker @($sidecarArgs + @('up','-d','--no-build','--pull','missing','--no-deps',$service))
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "$service did not start. Core IP/OpenVAS scanning remains available; this sidecar can be restarted later."
        }
    }
}


function Get-CommonRedisState {
    $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=aetheris-common" --filter "label=com.docker.compose.service=redis")
    if ($LASTEXITCODE -ne 0 -or -not $ids.Count) { return $null }
    $id = [string]$ids[0]
    $raw = & docker inspect $id
    if ($LASTEXITCODE -ne 0) { return $null }
    $item = (($raw -join "`n") | ConvertFrom-Json)[0]
    $health = if ($item.State.Health) { [string]$item.State.Health.Status } else { 'none' }
    $volume = @($item.Mounts | Where-Object { $_.Destination -eq '/data' -and $_.Type -eq 'volume' } | Select-Object -First 1)
    return [pscustomobject]@{
        Id = $id
        Name = [string]$item.Name
        Status = [string]$item.State.Status
        Health = $health
        ExitCode = [int]$item.State.ExitCode
        Volume = if ($volume) { [string]$volume.Name } else { '' }
    }
}

function Wait-CommonRedisHealthy {
    param([int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = Get-CommonRedisState
        if ($state -and $state.Status -eq 'running' -and $state.Health -in @('healthy','none')) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Backup-RedisVolume {
    param([Parameter(Mandatory = $true)][string]$VolumeName)
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $backupVolume = "${VolumeName}_backup_${stamp}"
    Write-Warn "Backing up Redis volume '$VolumeName' to '$backupVolume' before repair."
    & docker volume create $backupVolume 1>$null
    if ($LASTEXITCODE -ne 0) { throw "Could not create Redis backup volume $backupVolume." }
    & docker run --rm -v "${VolumeName}:/from:ro" -v "${backupVolume}:/to" alpine:3 sh -c 'cp -a /from/. /to/'
    if ($LASTEXITCODE -ne 0) { throw "Could not back up Redis volume $VolumeName." }
    return $backupVolume
}

function Remove-CommonRedisContainerForRepair {
    param([string]$ContainerId = '')
    if (-not $ContainerId) {
        $state = Get-CommonRedisState
        if (-not $state) { return }
        $ContainerId = [string]$state.Id
    }

    Write-Warn 'Detaching crash-looping Redis container before persistence repair.'
    $oldEap = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can surface native stderr as an ErrorRecord while
        # ErrorActionPreference=Stop.  Crash-loop cleanup is intentionally best-effort;
        # verify removal explicitly below instead of aborting on Docker's progress text.
        $ErrorActionPreference = 'Continue'
        & docker update --restart=no $ContainerId 1>$null 2>$null
        & docker rm -f $ContainerId 1>$null 2>$null
    } finally {
        $ErrorActionPreference = $oldEap
    }

    $removeDeadline = (Get-Date).AddSeconds(20)
    do {
        $stillThere = @(& docker ps -aq --filter "id=$ContainerId" 2>$null)
        if (-not $stillThere.Count) { return }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $removeDeadline)
    throw "Redis container could not be removed from Docker's stopping state. Run: docker rm -f $ContainerId"
}

function Repair-CommonRedis {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    $state = Get-CommonRedisState
    if (-not $state) { throw 'Shared Redis container was not created.' }

    Write-Warn "Redis is not healthy: status=$($state.Status) health=$($state.Health) exit=$($state.ExitCode)."
    Write-Host '---- Redis logs (last 120 lines) ----' -ForegroundColor DarkYellow
    & docker logs --tail 120 $state.Id 2>&1 | ForEach-Object { Write-Host $_ }
    Write-Host '------------------------------------' -ForegroundColor DarkYellow

    if (-not $state.Volume) {
        throw 'Redis /data is not backed by a Docker volume, so automatic safe repair is disabled.'
    }

    $backupVolume = Backup-RedisVolume -VolumeName $state.Volume
    Write-Warn "Redis recovery backup retained as Docker volume: $backupVolume"

    # A Redis container in a restart loop can remain in Docker's "Stopping" state.
    # Force-remove only the container; the named /data volume is retained.
    Remove-CommonRedisContainerForRepair -ContainerId $state.Id

    # First pass: normalize ownership and repair Redis 7 multi-part or legacy AOF data.
    $repairScript = @'
set -eu
chown -R redis:redis /data || true
if [ -f /data/appendonlydir/appendonly.aof.manifest ]; then
  echo "Repairing Redis multi-part AOF manifest..."
  yes y | redis-check-aof --fix /data/appendonlydir/appendonly.aof.manifest || true
elif [ -f /data/appendonly.aof ]; then
  echo "Repairing legacy Redis AOF..."
  yes y | redis-check-aof --fix /data/appendonly.aof || true
fi
chown -R redis:redis /data || true
'@
    & docker run --rm --user root -v "$($state.Volume):/data" redis:7 sh -c $repairScript
    if ($LASTEXITCODE -ne 0) { Write-Warn 'Redis persistence repair command returned a warning; attempting restart before fallback reset.' }

    $redisUpArgs = @($ComposeArgs) + @('up', '-d', '--no-build', '--pull', 'missing', '--force-recreate', 'redis')
    & docker @redisUpArgs
    if ($LASTEXITCODE -eq 0 -and (Wait-CommonRedisHealthy -TimeoutSeconds 35)) {
        Write-Ok 'Shared Redis recovered successfully without clearing persistence.'
        return
    }

    # Last resort: Redis is queue/cache infrastructure, not the forensic evidence store.
    # The first restart may itself be crash-looping on persistence. Remove that container
    # before moving files in the named volume so Redis cannot write concurrently.
    $failedRestart = Get-CommonRedisState
    if ($failedRestart) { Remove-CommonRedisContainerForRepair -ContainerId $failedRestart.Id }

    # Preserve the complete failed volume above, then quarantine persistence files so the
    # service can start cleanly. The backup can be examined/restored later if required.
    Write-Warn 'Redis still cannot start. Quarantining its persistence files and starting a clean transient data set.'
    $quarantineScript = @'
set -eu
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "/data/recovery-$stamp"
if [ -d /data/appendonlydir ]; then mv /data/appendonlydir "/data/recovery-$stamp/appendonlydir"; fi
if [ -f /data/appendonly.aof ]; then mv /data/appendonly.aof "/data/recovery-$stamp/appendonly.aof"; fi
if [ -f /data/dump.rdb ]; then mv /data/dump.rdb "/data/recovery-$stamp/dump.rdb"; fi
chown -R redis:redis /data || true
'@
    & docker run --rm --user root -v "$($state.Volume):/data" redis:7 sh -c $quarantineScript
    if ($LASTEXITCODE -ne 0) { throw 'Redis persistence quarantine failed; see the Redis logs above.' }

    $redisUpArgs = @($ComposeArgs) + @('up', '-d', '--no-build', '--pull', 'missing', '--force-recreate', 'redis')
    & docker @redisUpArgs
    if ($LASTEXITCODE -ne 0 -or -not (Wait-CommonRedisHealthy -TimeoutSeconds 35)) {
        $final = Get-CommonRedisState
        if ($final) { & docker logs --tail 120 $final.Id 2>&1 | ForEach-Object { Write-Host $_ } }
        throw "Shared Redis could not be recovered automatically. Backup volume retained: $backupVolume"
    }
    Write-Ok "Shared Redis started with clean persistence. Previous Redis data is preserved in $backupVolume."
}

function Ensure-CommonRedisHealthy {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    if (Wait-CommonRedisHealthy -TimeoutSeconds 25) {
        Write-Ok 'Shared Redis is healthy.'
        return
    }
    Repair-CommonRedis -ComposeArgs $ComposeArgs
}

function Get-PublicGatewayArgs {
    return @('compose', '--project-directory', $root, '--project-name', 'aetheris-gateway',
        '-f', 'services/gateway/docker-compose.yml',
        '-f', 'deployment/windows-ip-https/docker-compose.gateway-public-https.yml')
}

function Get-LocalGatewayArgs {
    return @('compose', '--project-directory', $root, '--project-name', 'aetheris-gateway',
        '-f', 'services/gateway/docker-compose.yml',
        '-f', 'deployment/windows-ip-https/docker-compose.gateway-local.yml')
}

function Start-AcmeBootstrap {
    param([string[]]$ComposeArgs)
    Invoke-Docker -Title 'Start temporary HTTP-01 certificate bootstrap on TCP 80' -DockerArgs (
        $ComposeArgs + @('--profile', 'acme-bootstrap', 'up', '-d', '--no-build', '--pull', 'missing', 'acme-bootstrap'))
}

function Wait-AcmeChallengeRoute {
    param([string[]]$ComposeArgs)
    # Confirm this host answers the challenge before Certbot contacts Let's Encrypt.
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $token = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    try {
        Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @('challenge', '--token', $token) | Out-Null
        foreach ($attempt in 1..15) {
            if (Test-AcmeRoute -Token $token) { return }
            Start-Sleep -Seconds 1
        }
        throw "HTTP-01 challenge file was not served on http://127.0.0.1/.well-known/acme-challenge/. TCP 80 must answer on this host, and the router must forward public TCP 80, before Let's Encrypt can renew the certificate."
    } finally {
        try { Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @('challenge', '--token', $token, '--remove') | Out-Null } catch { }
    }
}

function Stop-AcmeBootstrap {
    param([string[]]$ComposeArgs)
    try {
        Invoke-Docker -Title 'Remove temporary HTTP-01 certificate bootstrap' -DockerArgs (
            $ComposeArgs + @('--profile', 'acme-bootstrap', 'rm', '-sf', 'acme-bootstrap'))
    } catch { Write-Warn $_.Exception.Message }
}

function Ensure-PublicHttpsEdge {
    param([string]$IP, [string]$DNS, [string]$Email)

    $composeArgs = @(Get-PublicGatewayArgs)
    Assert-PublicPortOwners
    Enable-PublicFirewall

    # Stop-PolaronStacks has already stopped the HTTPS gateway. A short-lived IP
    # certificate that is due for renewal still needs something answering TCP 80;
    # otherwise Certbot reports "Some challenges have failed" and startup aborts.
    $ipName = "aetheris-ip-$IP"
    $domainName = if ($DNS) { "aetheris-domain-$DNS" } else { '' }

    try { Invoke-Docker -Title 'Pause owned HTTPS gateway so the certificate challenge can bind TCP 80' -DockerArgs ($composeArgs + @('rm', '-sf', 'gateway', 'certbot-renewer')) } catch { }
    Start-AcmeBootstrap -ComposeArgs $composeArgs
    $storedCertificateOnly = $false
    try {
        Wait-AcmeChallengeRoute -ComposeArgs $composeArgs
        Ensure-PublicCertificate -ComposeArgs $composeArgs -Identity $IP -CertName $ipName -Email $Email -IsIP
        if ($DNS) {
            Ensure-PublicCertificate -ComposeArgs $composeArgs -Identity $DNS -CertName $domainName -Email $Email
        }
    } catch {
        # Let's Encrypt often cannot fetch the HTTP-01 file on this link (no public
        # route to TCP 80). Aborting here prevents every product stack from starting.
        $storedCertificateOnly = $true
        Write-Warn $_.Exception.Message
    } finally {
        Stop-AcmeBootstrap -ComposeArgs $composeArgs
    }

    if ($storedCertificateOnly) {
        $ipCheck = Invoke-CertificateTool -ComposeArgs $composeArgs -ToolArgs @('inspect', '--name', $ipName, '--identity', $IP)
        if (-not $ipCheck.managed) {
            throw "Certificate renewal for $IP failed and no certificate is stored. Public TCP 80 must reach this host before the first certificate can be issued."
        }
        Write-Warn "Let's Encrypt could not reach ${IP}:80 from the internet. Startup will continue with the stored certificate (expires $($ipCheck.expires_utc)). Forward public TCP 80 and 443 to this PC, then start again to renew it."
    }

    $nginxPath = Join-Path $root 'deployment/windows-ip-https/nginx.gateway.https.conf'
    $nginxText = Get-PublicNginxConfig -PublicIP $IP -Domain $DNS
    [System.IO.File]::WriteAllText($nginxPath, $nginxText, [System.Text.UTF8Encoding]::new($false))

    Start-PublicHttpsGateway -ComposeArgs $composeArgs -PublicIP $IP -Domain $DNS -AllowStoredCertificate:$storedCertificateOnly
    return $composeArgs
}

if ($env:AETHERIS_START_DOCKER_FUNCTIONS_ONLY -eq '1') { return }

$exitCode = 0
$isPublic = ($Profile -ne 'local')
$publicGatewayStarted = $false

Push-Location $root
try {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host " Aetheris / Polaron startup - profile: $Profile" -ForegroundColor Cyan
    Write-Host " Root: $root"
    Write-Host '============================================================' -ForegroundColor DarkCyan

    Write-Step 'Initialize first-launch configuration'
    Initialize-DeploymentFiles -Root $root -Profile $Profile
    Write-Ok '.env and host settings are present; existing values were preserved.'

    if ($PrepareOnly) {
        Write-Ok 'PrepareOnly completed. No Docker operation was performed.'
        exit 0
    }

    Assert-DockerReady
    Assert-StartupAssets -Public $isPublic

    # Refresh BEFORE Compose preflight; a stale removable G:/ bind from the last
    # deployment must never fail validation or reach the Docker daemon.
    $driveGenerator = Join-Path $root 'scripts/generate-drive-mounts.ps1'
    if (Test-Path -LiteralPath $driveGenerator -PathType Leaf) {
        Write-Step 'Refresh Windows drive/evidence mount configuration'
        Invoke-DriveMountRefresh -Generator $driveGenerator -Public $isPublic
    } else {
        throw "Missing drive generator: $driveGenerator"
    }
    Assert-AllComposeFiles -CreateRuntimeDirectories:(-not $ValidateOnly)

    if ($ValidateOnly) {
        Write-Ok 'ValidateOnly completed. Compose files and deployment paths are valid; no containers were started.'
        exit 0
    }

    $settings = Get-DeploymentSettings -Root $root -Profile $Profile -PublicIP $PublicIP -Domain $Domain -AcmeEmail $AcmeEmail
    if ($isPublic -and -not $settings.AcmeEmail) {
        if (-not [Environment]::UserInteractive) {
            throw 'Set acmeEmail in script_docker/start_docker.settings.json or CERTBOT_EMAIL before public startup.'
        }
        $settings.AcmeEmail = Read-Host 'Let''s Encrypt email address'
        if (-not $settings.AcmeEmail) { throw 'An email address is required for trusted public HTTPS.' }
    }
    if ($isPublic) { Save-DeploymentSettings -Settings $settings -Profile $Profile }

    # Stop existing containers only after preflight and drive generation succeed.
    # No docker down -v, prune or global stop: preserve evidence and unrelated projects.
    Stop-PolaronStacks

    $buildId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
    Write-Step 'Build/compile application images (Docker dependency cache retained)'
    $stacks = @(Get-AllStackDefinitions)
    foreach ($stack in $stacks) {
        Invoke-StackBuild -Name $stack.Name -ComposeArgs $stack.Args -BuildId $buildId
    }

    # V55: the HTTPS gateway routes to product APIs directly over the shared Docker network.
    # Create that external network before starting the gateway, including on a first launch.
    Ensure-SharedDockerNetwork

    # Public edge intentionally comes before database/application products. This makes the
    # TLS endpoint deterministic and keeps certificate validation independent of product startup.
    if ($isPublic) {
        Write-Step 'Validate trusted public certificates and start HTTPS gateway first'
        $null = Ensure-PublicHttpsEdge -IP $settings.PublicIP -DNS $settings.Domain -Email $settings.AcmeEmail
        $publicGatewayStarted = $true
    }

    Write-Step "Start shared infrastructure and verify Redis before product stacks"
    $commonArgs = @(Get-StackComposeArgs -Root $root -Name 'common')
    Invoke-StackUp -Name 'common' -ComposeArgs $commonArgs
    Ensure-CommonRedisHealthy -ComposeArgs $commonArgs

    Write-Step "Start product stacks"
    # mobile-malware reads finished Android/iOS jobs read-only, so it starts after them.
    foreach ($name in @('forensic', 'mobile-android', 'mobile-ios', 'mobile-malware')) {
        $args = @(Get-StackComposeArgs -Root $root -Name $name)
        Invoke-StackUp -Name $name -ComposeArgs $args
        Ensure-MobileCoreWorkersStarted -Name $name -ComposeArgs $args
    }
    $vulnArgs = @(Get-StackComposeArgs -Root $root -Name 'vuln')
    Start-VulnerabilityStackPhased -ComposeArgs $vulnArgs

    if (-not $isPublic) {
        Write-Step 'Start local loopback gateway'
        $localGateway = @(Get-LocalGatewayArgs)
        Invoke-StackUp -Name 'gateway' -ComposeArgs $localGateway
    }

    Write-Step 'Check container readiness'
    $deadline = (Get-Date).AddMinutes(8)
    do {
        $report = Get-StackContainerReport
        if ($report.Failed.Count -gt 0) {
            throw "One or more containers failed: $($report.Failed -join '; ')"
        }
        if ($report.Missing.Count -eq 0 -and $report.Pending -eq 0) { break }
        Write-Host "    running=$($report.Running) pending=$($report.Pending) missing=$($report.Missing -join ',')"
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    $report = Get-StackContainerReport
    if ($report.Failed.Count -gt 0 -or $report.Missing.Count -gt 0 -or $report.Pending -gt 0) {
        throw "Startup readiness timeout. failed=$($report.Failed -join '; ') missing=$($report.Missing -join ',') pending=$($report.Pending)"
    }
    if ($report.OptionalFailed.Count -gt 0) {
        Write-Warn "Optional vulnerability engines are still warming/degraded: $($report.OptionalFailed -join '; ')"
    }

    Assert-RuntimeHealth
    Ensure-WorkstationHelper

    Write-Host ''
    if ($isPublic) {
        Write-Host "READY (frontend HTTP): http://localhost:3001/" -ForegroundColor Green
        Write-Host "READY (frontend HTTP on LAN): http://<WINDOWS_LAN_IP>:3001/ (requires LAN firewall access)" -ForegroundColor Yellow
        Write-Host "READY: https://$($settings.PublicIP)/" -ForegroundColor Green
        if ($settings.Domain) { Write-Host "READY: https://$($settings.Domain)/" -ForegroundColor Green }
    } else {
        # V1.10.8: local uses the same stacks and gateway as prod, without HTTPS.
        Write-Host "READY (frontend HTTP): http://localhost:3001/" -ForegroundColor Green
        Write-Host "READY (frontend HTTP on LAN): http://<WINDOWS_LAN_IP>:3001/ (requires LAN firewall access)" -ForegroundColor Yellow
    }
    Write-Host "Malware Detection: sidebar > Malware Detection (API on http://localhost:8085)" -ForegroundColor Green
    Write-Host "Application build ID: $buildId" -ForegroundColor DarkGray
}
catch {
    $exitCode = 1
    Write-Host ''
    Write-Host "STARTUP ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if ("$($_.Exception.Message)" -match 'malware') {
        Write-Host 'Malware Detection diagnosis (containers, API log, gateway route): .\scripts\check-malware-stack.ps1' -ForegroundColor Yellow
    }
    if ($isPublic -and $publicGatewayStarted) {
        Write-Host 'HTTPS gateway and certificate renewal remain running; product startup did not fully complete.' -ForegroundColor Yellow
    }
    if ($isPublic) {
        Write-Host 'If the error above is HTTPS-related, check router TCP 80/443 forwarding, Windows Firewall, DNS, and ISP inbound TCP 80.' -ForegroundColor Yellow
        Write-Host 'If the error names Redis/Postgres/MinIO or another container, use that container error/log instead; HTTPS may already be healthy.' -ForegroundColor Yellow
    }
}
finally {
    Pop-Location
}

exit $exitCode
