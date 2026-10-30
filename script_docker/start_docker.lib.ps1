# Windows PowerShell 5.1-compatible helpers. Dot-sourceable for offline checks.

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Test-DockerRegistryDnsFailure {
    param([string]$Text)
    if (-not $Text) { return $false }
    # Compose cancels the other pulls after the first registry failure and then
    # reports "No such image". Match the transport failure itself, including
    # Docker Hub token requests that never mention registry-1.docker.io.
    $mentionsRegistry = $Text -match 'registry-1\.docker\.io|auth\.docker\.io|docker\.io/docker/dockerfile|docker\.io/library/|failed to resolve source metadata|failed to resolve reference'
    $lookupFailed = $Text -match 'no such host|Temporary failure in name resolution|i/o timeout|dial tcp: lookup|HTTP response to HTTPS client|TLS handshake timeout|connection reset by peer|unexpected EOF|proxyconnect|502 Bad Gateway|503 Service Unavailable|tls: protocol version not supported|failed to fetch oauth token|remote error: tls:'
    return [bool]($mentionsRegistry -and $lookupFailed)
}

function Get-DockerHubBypassHosts {
    # BuildKit must dial these directly. Docker Desktop's internal proxy is an
    # HTTP listener named http.docker.internal, and sending registry TLS through
    # it returns "HTTP response to HTTPS client". That name also does not
    # resolve from the Windows client, so it must not be copied into HTTP_PROXY.
    return @(
        'localhost', '127.0.0.1', '::1',
        'registry-1.docker.io', 'auth.docker.io', 'docker.io', 'index.docker.io',
        'production.cloudflare.docker.com', 'hubproxy.docker.internal'
    )
}

function Enable-DockerDesktopProxyScheme {
    param([string]$Docker = 'docker')
    if ($script:AetherisProxySchemeReady) { return }
    $script:AetherisProxySchemeReady = $true
    foreach ($name in @('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy')) {
        $cur = [string][Environment]::GetEnvironmentVariable($name, 'Process')
        if ($cur -match '^(?i)https?://http\.docker\.internal(?::\d+)?/?$') {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    }
    $hosts = @(Get-DockerHubBypassHosts)
    foreach ($name in @('NO_PROXY', 'no_proxy')) {
        $current = [string][Environment]::GetEnvironmentVariable($name, 'Process')
        $items = @()
        if ($current) {
            $items = @($current -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        foreach ($hostName in $hosts) {
            if ($items -notcontains $hostName) { $items += $hostName }
        }
        [Environment]::SetEnvironmentVariable($name, ($items -join ','), 'Process')
    }
    Write-Host '    Docker Hub registry requests bypass the HTTP proxy.'
}

function Merge-DockerDaemonDns {
    param([string]$JsonText, [string[]]$Servers = @('8.8.8.8', '1.1.1.1'))
    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        $obj = New-Object psobject
    } else {
        $obj = $JsonText | ConvertFrom-Json
    }
    $existing = @()
    if ($obj.PSObject.Properties.Name -contains 'dns' -and $null -ne $obj.dns) {
        $existing = @($obj.dns)
    }
    $merged = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($existing + $Servers)) {
        $name = [string]$item
        if ($name -and -not $merged.Contains($name)) { [void]$merged.Add($name) }
    }
    $dns = $merged.ToArray()
    if ($obj.PSObject.Properties.Name -contains 'dns') {
        $obj.dns = $dns
    } else {
        $obj | Add-Member -NotePropertyName dns -NotePropertyValue $dns
    }
    return ($obj | ConvertTo-Json -Depth 8)
}

function Invoke-Docker {
    param(
        [string]$Title,
        [Parameter(Mandatory = $true)][string[]]$DockerArgs,
        [string]$Exe = 'docker',
        [switch]$PassThru
    )
    Enable-DockerDesktopProxyScheme -Docker $Exe
    $max = 3
    for ($attempt = 1; $attempt -le $max; $attempt++) {
        if ($Title) {
            if ($attempt -eq 1) { Write-Host $Title }
            else { Write-Host "$Title (retry $attempt of $max after Docker Hub did not answer)" }
        }
        $log = Join-Path ([System.IO.Path]::GetTempPath()) ("aetheris-docker-" + [guid]::NewGuid().ToString('N') + '.log')
        $writer = New-Object System.IO.StreamWriter($log, $false, (New-Object System.Text.UTF8Encoding $false))
        $saved = $ErrorActionPreference
        $code = 0
        try {
            $ErrorActionPreference = 'Continue'
            & $Exe @DockerArgs 2>&1 | ForEach-Object {
                $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
                Write-Host $line
                $writer.WriteLine($line)
            }
            $code = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
            $writer.Dispose()
        }
        if ($null -eq $code) { $code = 0 }
        $text = ''
        if (Test-Path -LiteralPath $log) {
            $text = [System.IO.File]::ReadAllText($log)
            Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
        }
        $script:AetherisLastDockerText = $text
        if ([int]$code -eq 0) {
            if ($PassThru) { return 0 }
            return
        }
        $retry = (Test-DockerRegistryDnsFailure $text) -and ($attempt -lt $max)
        if (-not $retry) {
            if ($PassThru) { return [int]$code }
            throw "Docker action '$Title' failed (exit $code)."
        }
        Write-Host "    Docker Hub did not answer the registry request. Retrying in $($attempt * 5) seconds." -ForegroundColor Yellow
        if ($attempt -ge 2 -and (Get-Command Ensure-DockerRegistryDns -ErrorAction SilentlyContinue)) {
            Ensure-DockerRegistryDns -Docker $Exe
        }
        Start-Sleep -Seconds ($attempt * 5)
    }
}

function Get-RemoteComposeImages {
    param($Config)
    # Built services already have a local image tag. Pulling that tag asks
    # Docker Hub for an image that only exists after the project build.
    $images = New-Object System.Collections.Generic.List[string]
    if (-not $Config -or -not $Config.services) { return @() }
    foreach ($property in @($Config.services.PSObject.Properties)) {
        $spec = $property.Value
        if (-not $spec) { continue }
        $image = ''
        if ($spec.PSObject.Properties.Name -contains 'image' -and $spec.image) {
            $image = [string]$spec.image
        }
        if (-not $image) { continue }
        $builtHere = $spec.PSObject.Properties.Name -contains 'build' -and $null -ne $spec.build
        if ($builtHere) { continue }
        if (-not $images.Contains($image)) { [void]$images.Add($image) }
    }
    return @($images)
}

function Get-ExternalComposeVolumeNames {
    param($Config)
    $names = New-Object System.Collections.Generic.List[string]
    if (-not $Config -or -not $Config.volumes) { return @() }
    foreach ($property in @($Config.volumes.PSObject.Properties)) {
        $spec = $property.Value
        if (-not $spec) { continue }
        $isExternal = $spec.PSObject.Properties.Name -contains 'external' -and $spec.external
        if (-not $isExternal) { continue }
        $name = [string]$property.Name
        if ($spec.PSObject.Properties.Name -contains 'name' -and $spec.name) { $name = [string]$spec.name }
        if ($spec.external -is [pscustomobject] -and $spec.external.PSObject.Properties.Name -contains 'name' -and $spec.external.name) {
            $name = [string]$spec.external.name
        }
        if ($name -and -not $names.Contains($name)) { [void]$names.Add($name) }
    }
    return @($names)
}

function Ensure-ComposeExternalVolumes {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs,
        [string]$Exe = 'docker'
    )
    # Common Postgres and pgAdmin volumes are external so a later product
    # compose down cannot delete the database. Create them on first launch.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = @(& $Exe @ComposeArgs config --format json 2>&1)
        if ($LASTEXITCODE -ne 0) { return }
        $text = ($raw | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
        }) -join "`n"
        $cfg = $text | ConvertFrom-Json
        foreach ($name in @(Get-ExternalComposeVolumeNames -Config $cfg)) {
            & $Exe volume inspect $name 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { continue }
            Write-Host "    Create Docker volume $name"
            & $Exe volume create $name 2>&1 | ForEach-Object { Write-Host ([string]$_) }
            if ($LASTEXITCODE -ne 0) { throw "Could not create Docker volume $name." }
        }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function Ensure-ComposeImagesPresent {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs,
        [string]$Exe = 'docker'
    )
    # `compose up` pulls every missing image at once. Docker Desktop's engine
    # proxy then answers registry TLS with plain HTTP, and Compose aborts the
    # whole stack. Pull one image at a time so a failed token request can be
    # retried without discarding the images that already downloaded.
    Enable-DockerDesktopProxyScheme -Docker $Exe
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = @(& $Exe @ComposeArgs config --format json 2>&1)
        if ($LASTEXITCODE -ne 0) { return }
        $text = ($raw | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
        }) -join "`n"
        $cfg = $text | ConvertFrom-Json
        foreach ($image in @(Get-RemoteComposeImages -Config $cfg)) {
            & $Exe image inspect $image --format '{{.Id}}' 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { continue }
            $ErrorActionPreference = $saved
            Invoke-Docker -Title "Pull $image" -DockerArgs @('pull', $image) -Exe $Exe
            $ErrorActionPreference = 'Continue'
        }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function Stop-PodmanAetherisContainers {
    # The same host ports are published by a rootful Podman machine. `podman ps`
    # without -u root looks at an empty rootless store and misses them, and
    # Windows only shows wslrelay, which must stay running. Stop the containers.
    # Do not remove them or their volumes.
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) { return }
    $distro = 'podman-machine-default'
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = @(& wsl.exe -d $distro -u root -- podman ps -q --filter name=aetheris- 2>&1)
        if ($LASTEXITCODE -ne 0) { return }
        $ids = @($raw | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
        } | Where-Object { $_ -match '^[0-9a-f]{12,64}$' })
        if (-not $ids.Count) { return }
        Write-Host "    Stopping $($ids.Count) Podman Aetheris containers so Docker can bind 6380, 5434, 9004, and the product ports. Podman volumes stay in place."
        # Stop reports IPAM errors when the Podman network record is already gone.
        # The port is free once no Aetheris container is still running.
        & wsl.exe -d $distro -u root -- podman stop -t 45 @ids 2>&1 | ForEach-Object { Write-Host "    $([string]$_)" }
        $left = @(& wsl.exe -d $distro -u root -- podman ps -q --filter name=aetheris- 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
        } | Where-Object { $_ -match '^[0-9a-f]{12,64}$' })
        if ($left.Count) {
            & wsl.exe -d $distro -u root -- podman kill @left 2>&1 | ForEach-Object { Write-Host "    $([string]$_)" }
            $left = @(& wsl.exe -d $distro -u root -- podman ps -q --filter name=aetheris- 2>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { [string]$_.Exception.Message } else { [string]$_ }
            } | Where-Object { $_ -match '^[0-9a-f]{12,64}$' })
        }
        if ($left.Count) {
            throw "Could not stop the Podman Aetheris containers that are holding the Docker host ports."
        }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function Ensure-SharedDockerNetwork {
    param([string]$Name = 'aetheris-common')
    # A missing network is the normal first-launch case. PowerShell treats
    # docker's stderr as a terminating error when ErrorAction is Stop, which
    # aborted startup with "network aetheris-common not found" before create.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & docker network inspect $Name 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { return }
        Write-Step "Create shared Docker network $Name"
        $created = @(& docker network create $Name 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $detail = ($created | ForEach-Object { [string]$_ }) -join ' '
            if ($detail -match 'already exists') { return }
            throw "Could not create external Docker network ${Name}. $detail"
        }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function Get-DockerJson {
    param([string[]]$DockerArgs)
    $raw = & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect the Docker configuration." }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-StackComposeArgs {
    param([string]$Root, [string]$Name)
    $composeArgs = @("compose", "--project-directory", $Root, "--project-name", "aetheris-$Name",
        "-f", "services/$Name/docker-compose.yml")
    $drives = switch ($Name) {
        'forensic' { 'docker-compose.drives.forensic.yml' }
        'mobile-android' { 'docker-compose.drives.mobile-android.yml' }
        'mobile-ios' { 'docker-compose.drives.mobile-ios.yml' }
        'mobile-malware' { 'docker-compose.drives.mobile-malware.yml' }
        default { '' }
    }
    if ($drives -and (Test-Path -LiteralPath (Join-Path $Root $drives))) {
        $composeArgs += @('-f', $drives)
    }
    # The GPU sequence-model worker is opt-in (Compose profile 'gpu').
    if ($Name -eq 'mobile-malware' -and "$env:MALWARE_GPU_MODEL_ENABLED" -eq 'true') {
        $composeArgs += @('--profile', 'gpu')
    }
    return $composeArgs
}

function Write-NewDeploymentFile {
    param([string]$Path, [string]$Text)
    # Exclusive creation preserves a configuration written by another launch.
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
        throw
    }
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}

function New-DeploymentSecret {
    $bytes = New-Object byte[] 32
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

function Initialize-DeploymentFiles {
    param([string]$Root, [ValidateSet('local', 'nitin', 'prod')][string]$Profile)
    $manifestPath = Join-Path $Root 'script_docker/start_docker.required-files.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Missing $manifestPath. Extract the complete startup update into the project root."
    }
    $required = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $files = @($required.common)
    if ($Profile -ne 'local') { $files += @($required.public) }
    $missing = @($files | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf)
    })
    if ($missing.Count) {
        throw "Required deployment files are missing: $($missing -join ', '). Restore them from the complete project or startup update."
    }
    $envPath = Join-Path $Root '.env'
    if (-not (Test-Path -LiteralPath $envPath)) {
        $text = [System.IO.File]::ReadAllText((Join-Path $Root '.env.example'))
        $text = [regex]::Replace($text, '(?m)^JWT_SECRET=[^\r\n]*', ('JWT_SECRET=' + (New-DeploymentSecret)))
        $text = [regex]::Replace($text, '(?m)^CLIENT_TOKEN_SECRET=[^\r\n]*', ('CLIENT_TOKEN_SECRET=' + (New-DeploymentSecret)))
        Write-NewDeploymentFile -Path $envPath -Text $text
        Write-Host 'Created root .env from .env.example with fresh signing secrets.' -ForegroundColor Green
    }
    if (-not (Test-Path -LiteralPath $envPath -PathType Leaf) -or
        -not [System.IO.File]::ReadAllText($envPath).Trim()) {
        throw "The existing $envPath is empty or is not a file. Restore your configuration or copy .env.example; existing files are never overwritten."
    }
    $settingsPath = Join-Path $Root 'script_docker/start_docker.settings.json'
    if (-not (Test-Path -LiteralPath $settingsPath)) {
        $settingsText = [System.IO.File]::ReadAllText((Join-Path $Root 'script_docker/start_docker.settings.example.json'))
        Write-NewDeploymentFile -Path $settingsPath -Text $settingsText
        Write-Host 'Created script_docker/start_docker.settings.json from the supplied profile template.' -ForegroundColor Green
    }
    # Validate JSON here even for prepare-only, before any Docker operation.
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    foreach ($name in @('local', 'nitin', 'prod')) {
        if (-not $settings.$name) { throw "Deployment settings are missing the '$name' profile in $settingsPath." }
    }
}

function Get-WindowsPathDrive {
    # Drive letter of an absolute Windows path (F:/x, F:\x, F:), else $null.
    param([string]$Path)
    if ("$Path" -match '^\s*([A-Za-z]):([\\/]|$)') { return $Matches[1].ToUpperInvariant() }
    return $null
}

function Test-WindowsDrivePresent {
    # Never throws, unlike Get-Item/New-Item on a missing drive ("Cannot find drive").
    param([string]$Letter)
    if (-not $Letter) { return $true }
    return [System.IO.Directory]::Exists("$($Letter):\")
}

function Find-EnvSettingForPath {
    # The .env line that puts a bind source on its drive (e.g. MINIO_DATA_DIR=D:/aetheris/minio), else $null.
    param([string]$Root, [string]$Path)
    $envPath = Join-Path $Root '.env'
    if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) { return $null }
    $norm = { param($p) ("$p".Trim().Trim('"').Trim("'") -replace '\\', '/').TrimEnd('/').ToLowerInvariant() }
    $target = & $norm $Path
    $best = $null
    foreach ($line in [System.IO.File]::ReadAllLines($envPath)) {
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$') { continue }
        $key = $Matches[1]
        $value = $Matches[2]
        if (-not (Get-WindowsPathDrive -Path $value.Trim('"').Trim("'"))) { continue }
        $v = & $norm $value
        if ($target -eq $v -or $target.StartsWith("$v/")) {
            if (-not $best -or $v.Length -gt $best.Length) { $best = [pscustomobject]@{ Key = $key; Value = $value.Trim('"').Trim("'"); Length = $v.Length } }
        }
    }
    return $best
}

function Assert-DeploymentComposePaths {
    param([string]$Root, $Config, [switch]$ValidateOnly)
    $runtimeTargets = @('/app/data', '/app/data/uploads', '/scratch', '/data',
        '/root/.ollama', '/root/.cache/huggingface', '/evidence')
    $generatedNginx = [System.IO.Path]::GetFullPath((Join-Path $Root 'deployment/windows-ip-https/nginx.gateway.https.conf'))
    foreach ($row in @($Config.services.PSObject.Properties)) {
        $service = $row.Value
        if ($service.build) {
            $context = [string]$service.build.context
            if (-not (Test-Path -LiteralPath $context -PathType Container)) { throw "Missing build context for $($row.Name): $context" }
            $dockerfile = if ($service.build.dockerfile) { [string]$service.build.dockerfile } else { 'Dockerfile' }
            if (-not (Test-Path -LiteralPath (Join-Path $context $dockerfile) -PathType Leaf)) {
                throw "Missing Dockerfile for $($row.Name): $context/$dockerfile"
            }
        }
        foreach ($mount in @($service.volumes)) {
            if ($mount.type -ne 'bind') { continue }
            $source = [string]$mount.source
            $drive = Get-WindowsPathDrive -Path $source
            if ($drive -and -not (Test-WindowsDrivePresent -Letter $drive)) {
                if ([string]$mount.target -match '^/host/[a-z]$') {
                    # Evidence drives are detected dynamically just before this check; one vanished in between.
                    throw ("Drive ${drive}: was connected during the drive scan but is gone now ($($row.Name) evidence mount " +
                        "$($mount.target)). Reconnect it, or start again: the scan only mounts drives that are connected.")
                }
                $setting = Find-EnvSettingForPath -Root $Root -Path $source
                $origin = if ($setting) { ", set by $($setting.Key)=$($setting.Value) in .env" } else { '' }
                $change = if ($setting) { "change $($setting.Key) in .env" } else { 'change that path' }
                throw ("Drive ${drive}: is not connected, but service '$($row.Name)' keeps its data there: $source " +
                    "(container path $($mount.target))$origin. Startup stops so the service never starts on an empty " +
                    "folder and hides the existing data. Connect drive ${drive}: and start again, or, if the data has " +
                    "moved to another drive, $change to the new location.")
            }
            if (Test-Path -LiteralPath $source) {
                if ($runtimeTargets -contains [string]$mount.target -and
                    -not (Test-Path -LiteralPath $source -PathType Container)) {
                    throw "Expected a runtime directory for $($row.Name), but found a file: $source"
                }
                if ([System.IO.Path]::GetFullPath($source) -eq $generatedNginx -and
                    -not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "The generated HTTPS configuration path is a directory, not a file: $source"
                }
                continue
            }
            # HTTPS configuration is generated after the matching certificates exist.
            if ([System.IO.Path]::GetFullPath($source) -eq $generatedNginx) { continue }
            if ($runtimeTargets -contains [string]$mount.target) {
                if (-not $ValidateOnly) {
                    New-Item -ItemType Directory -Path $source -Force | Out-Null
                }
            } else {
                throw "Missing bind-mounted deployment file/directory for $($row.Name): $source (container path $($mount.target)). Restore the complete project."
            }
        }
    }
}

function Get-DeploymentSettings {
    param([string]$Root, [string]$Profile, [string]$PublicIP, [string]$Domain, [string]$AcmeEmail)
    $path = Join-Path $Root "script_docker\start_docker.settings.json"
    $source = if (Test-Path -LiteralPath $path) { $path } else {
        Join-Path $Root "script_docker\start_docker.settings.example.json"
    }
    $all = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json
    $selected = $all.$Profile
    if (-not $selected) { throw "Deployment settings are missing the '$Profile' profile." }
    $ip = if ($PublicIP) { $PublicIP } else { [string]$selected.publicIp }
    $dns = if ($Domain) { $Domain } else { [string]$selected.domain }
    $email = if ($AcmeEmail) { $AcmeEmail } elseif ($env:CERTBOT_EMAIL) {
        $env:CERTBOT_EMAIL
    } else { [string]$selected.acmeEmail }
    if ($Profile -eq "prod") {
        if ($Domain) { throw "The prod launcher uses only an IP address. Use nitin for domain HTTPS." }
        $dns = ""
    }
    if ($Profile -ne "local") {
        # HTTP-01 needs a public IPv4 address, not a LAN/loopback address.
        $parsed = $null
        if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or
            -not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
            throw "Set a valid static public IPv4 address in $path or pass -PublicIP."
        }
        $octets = $parsed.GetAddressBytes()
        if ($octets[0] -eq 0 -or $octets[0] -eq 10 -or $octets[0] -eq 127 -or
            $octets[0] -ge 224 -or ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
            ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
            ($octets[0] -eq 192 -and $octets[1] -eq 168) -or
            ($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127)) {
            throw "HTTPS IP issuance needs your static public IPv4 address, not $ip."
        }
        $ip = $parsed.ToString()
        if ($Profile -eq "nitin") {
            $dns = $dns.Trim().ToLowerInvariant()
            if ($dns.Length -gt 253 -or $dns -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') {
                throw "Set a valid DNS hostname for the nitin profile."
            }
        }
    }
    return [pscustomobject]@{ PublicIP = $ip; Domain = $dns; AcmeEmail = $email;
        Path = $path; All = $all }
}

function Save-DeploymentSettings {
    param($Settings, [string]$Profile)
    $row = $Settings.All.$Profile
    $row.publicIp = $Settings.PublicIP
    $row.domain = $Settings.Domain
    $row.acmeEmail = $Settings.AcmeEmail
    $text = $Settings.All | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($Settings.Path, $text, [System.Text.UTF8Encoding]::new($false))
}

function Get-ComposePullFlag {
    # Production sets this to "never" after the one library pull, so later
    # compose up/run commands do not ask the registry for the same images again.
    if ($script:AetherisImagePullPolicy) { return [string]$script:AetherisImagePullPolicy }
    return "missing"
}

function Get-AppBuildArgs {
    param([string]$BuildId, [switch]$RefreshDependencies)
    if (-not $BuildId) { throw "Application build ID is required." }
    $buildOptions = @("build", "--build-arg", "AETHERIS_APP_BUILD_ID=$BuildId")
    if ($RefreshDependencies) { $buildOptions += @("--pull", "--no-cache") }
    return $buildOptions
}

function Get-StableAppBuildId {
    param([string]$Root)
    # The id changes only when application source or a dependency manifest changes.
    # An unchanged id leaves every Docker layer cached, so libraries are not fetched again.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $files = New-Object System.Collections.Generic.List[string]
        $named = @(
            'backend\requirements.txt',
            'backend\requirements-malware.txt',
            'backend\Dockerfile',
            'backend\Dockerfile.malware',
            'frontend\package.json',
            'frontend\package-lock.json',
            'frontend\Dockerfile'
        )
        foreach ($rel in $named) {
            $path = Join-Path $Root $rel
            if (Test-Path -LiteralPath $path -PathType Leaf) { $files.Add($path) }
        }
        foreach ($rel in @('backend\app', 'frontend\src')) {
            $dir = Join-Path $Root $rel
            if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
            Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.FullName -match '\\__pycache__\\' -or $_.Extension -eq '.pyc') { return }
                $files.Add($_.FullName)
            }
        }
        foreach ($file in ($files | Sort-Object -Unique)) {
            $info = Get-Item -LiteralPath $file
            $rel = $file.Substring($Root.Length).Replace('\', '/').TrimStart('/')
            $line = [Text.Encoding]::UTF8.GetBytes("$rel|$($info.Length)|$($info.LastWriteTimeUtc.Ticks)`n")
            $sha.TransformBlock($line, 0, $line.Length, $null, 0) | Out-Null
        }
        $sha.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
        return ([BitConverter]::ToString($sha.Hash)).Replace('-', '').Substring(0, 16).ToLower()
    } finally {
        $sha.Dispose()
    }
}

function Get-PublicNginxConfig {
    param([string]$PublicIP, [string]$Domain)
    $ipCert = "aetheris-ip-$PublicIP"
    $blocks = @()
    $identities = @([pscustomobject]@{ Identity = "$PublicIP _"; Cert = $ipCert; Default = $true })
    if ($Domain) {
        $identities += [pscustomobject]@{ Identity = $Domain; Cert = "aetheris-domain-$Domain"; Default = $false }
    }
    foreach ($row in $identities) {
        $listen = if ($row.Default) { "listen 443 ssl default_server;" } else { "listen 443 ssl;" }
        $listen6 = if ($row.Default) { "listen [::]:443 ssl default_server;" } else { "listen [::]:443 ssl;" }
        $blocks += @"
server {
    $listen
    $listen6
    server_name $($row.Identity);
    ssl_certificate /etc/letsencrypt/live/$($row.Cert)/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$($row.Cert)/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    root /usr/share/nginx/html;
    index index.html;
    server_tokens off;
    client_max_body_size 0;
    include /etc/nginx/conf.d/gateway-https-locations.inc;
}
"@
    }
    $canonical = if ($Domain) { $Domain } else { $PublicIP }
    return @"
# Generated by script_docker/start_docker.ps1. Certificate renewal reloads nginx.
resolver 127.0.0.11 valid=10s ipv6=off;
map `$http_x_aetheris_service `$hdr_upstream {
    default http://forensic-api:8080;
    forensic http://forensic-api:8080;
    mobile-android http://android-api:8080;
    android http://android-api:8080;
    mobile-ios http://ios-api:8080;
    ios http://ios-api:8080;
    mobile-extract http://android-api:8080;
    mobile http://android-api:8080;
    vuln http://vuln-api:8080;
    mobile-malware http://malware-api:8080;
    malware http://malware-api:8080;
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $PublicIP $Domain _;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type text/plain;
        try_files `$uri =404;
    }
    location = /gateway-health { return 200 "ok\n"; }
    location / { return 308 https://$canonical`$request_uri; }
}
$($blocks -join "`n")
"@
}

function Assert-PublicPortOwners {
    param([int[]]$Ports = @(80, 443))
    # Never stop IIS/Caddy/another Compose project to take its ports.
    $ids = @(& docker ps -q)
    if ($LASTEXITCODE -ne 0) { throw "Could not inspect Docker port owners." }
    if ($ids.Count -gt 0) {
        foreach ($id in $ids) {
            $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
            $item = $items[0]
            $project = [string]$item.Config.Labels.'com.docker.compose.project'
            $service = [string]$item.Config.Labels.'com.docker.compose.service'
            foreach ($prop in @($item.HostConfig.PortBindings.PSObject.Properties)) {
                foreach ($bind in @($prop.Value)) {
                    if ($Ports -contains [int]$bind.HostPort -and
                        ($project -ne "aetheris-gateway" -or $service -notin @("gateway", "acme-bootstrap"))) {
                        throw "TCP $($bind.HostPort) is reserved by $($item.Name). Stop or reconfigure that owner first."
                    }
                }
            }
        }
    }
    foreach ($port in $Ports) {
        foreach ($listener in @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -notmatch '^(docker|dockerd|vpnkit|wsl|wslservice|wslrelay|com\.docker)') {
                throw "TCP $port is held by $($proc.ProcessName) (PID $($proc.Id)). Stop or reconfigure it first."
            }
        }
    }
}

function Enable-PublicFirewall {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Run as Administrator to create inbound TCP 80/443 rules, or create those rules before starting." -ForegroundColor Yellow
        return
    }
    foreach ($port in @(80, 443)) {
        $name = "Aetheris HTTPS TCP $port"
        $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
        if ($existing) { $existing | Remove-NetFirewallRule | Out-Null }
        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any | Out-Null
    }
}

function Invoke-CertificateTool {
    param([string[]]$ComposeArgs, [string[]]$ToolArgs)
    $pull = Get-ComposePullFlag
    $raw = & docker @ComposeArgs run --rm --no-deps --pull $pull --entrypoint python certbot /tools/public_https.py @ToolArgs
    if ($LASTEXITCODE -ne 0) { throw "Certificate identity/trust check failed." }
    return (($raw -join "`n") | ConvertFrom-Json)
}

function Get-CertbotIssueArgs {
    param([string]$Identity, [string]$CertName, [string]$Email, [switch]$IsIP)
    $issueOptions = @("certonly", "--non-interactive", "--agree-tos", "--email", $Email,
        "--server", "https://acme-v02.api.letsencrypt.org/directory",
        "--webroot", "--webroot-path", "/var/www/certbot", "--preferred-challenges", "http",
        "--cert-name", $CertName, "--keep-until-expiring")
    if ($IsIP) { $issueOptions += @("--required-profile", "shortlived", "--ip-address", $Identity) }
    else { $issueOptions += @("-d", $Identity) }
    return $issueOptions
}

function Ensure-PublicCertificate {
    param([string[]]$ComposeArgs, [string]$Identity, [string]$CertName, [string]$Email, [switch]$IsIP)
    $check = Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("inspect", "--name", $CertName, "--identity", $Identity)
    if ($check.managed) {
        # Certbot decides whether renewal is due (including ACME Renewal Information).
        Invoke-Docker -Title "Check renewal for $Identity" -DockerArgs ($ComposeArgs + @(
            "run", "--rm", "--no-deps", "--pull", (Get-ComposePullFlag), "certbot", "renew",
            "--cert-name", $CertName, "--non-interactive", "--no-random-sleep-on-renew"))
    } else {
        $issue = Get-CertbotIssueArgs -Identity $Identity -CertName $CertName -Email $Email -IsIP:$IsIP
        Invoke-Docker -Title "Issue trusted HTTPS certificate for $Identity" -DockerArgs (
            $ComposeArgs + @("run", "--rm", "--no-deps", "--pull", (Get-ComposePullFlag), "certbot") + $issue)
    }
    $check = Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("inspect", "--name", $CertName, "--identity", $Identity)
    if (-not $check.valid) { throw "Certificate for $Identity is invalid: $($check.reason)." }
    Write-Host "Certificate ready for $Identity (expires $($check.expires_utc))."
}

function Test-AcmeRoute {
    param([string]$Token)
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1/.well-known/acme-challenge/$Token" -TimeoutSec 10
        return ($response.StatusCode -eq 200 -and $response.Content.Trim() -eq $Token)
    } catch { return $false }
}

function Get-StackContainerReport {
    $failed = @()
    $pending = 0
    $running = 0
    $missing = @()
    $oneShots = @("ollama-init", "configure-openvas", "pg-gvm-migrator", "gpg-data", "postgres-ensure", "certbot", "acme-bootstrap", "vulnerability-tests", "notus-data", "scap-data", "cert-bund-data", "dfn-cert-data", "data-objects", "report-formats")
    $optionalServices = @("zap", "trivy", "gvmd", "openvas", "openvasd", "ospd-openvas", "redis-gvm", "pg-gvm", "gvm-tools", "vulnerability-tests", "notus-data", "scap-data", "cert-bund-data", "dfn-cert-data", "data-objects", "report-formats", "gpg-data", "configure-openvas", "pg-gvm-migrator")
    $warmupServices = @("gvmd", "openvasd", "ospd-openvas", "pg-gvm")
    $optionalFailed = @()
    foreach ($project in @("aetheris-common", "aetheris-forensic", "aetheris-mobile-android", "aetheris-mobile-ios", "aetheris-mobile-malware", "aetheris-vuln", "aetheris-gateway")) {
        $ids = @(& docker ps -aq --filter "label=com.docker.compose.project=$project")
        if ($LASTEXITCODE -ne 0) { throw "Could not inspect containers for $project." }
        if (-not $ids.Count) { $missing += $project; continue }
        foreach ($id in $ids) {
            $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
            $item = $items[0]
            $status = [string]$item.State.Status
            $health = if ($item.State.Health) { [string]$item.State.Health.Status } else { "none" }
            $service = [string]$item.Config.Labels.'com.docker.compose.service'
            if ($status -eq "running" -and $health -in @("none", "healthy")) { $running++; continue }
            if ($status -eq "running" -and $health -eq "starting" -and $service -in $warmupServices) { $running++; continue }
            if ($status -eq "running" -and $health -eq "starting") { $pending++; continue }
            # V64: Compose can return from `up -d` while a dependent worker is still
            # in the created/restarting transition. Treat these as pending, not failed.
            # The readiness deadline below still turns a genuinely stuck container into
            # a timeout with diagnostics instead of failing immediately at exit=0.
            if ($status -in @("created", "restarting", "removing")) { $pending++; continue }
            if ($service -in $oneShots -and $status -eq "exited" -and $item.State.ExitCode -eq 0) { continue }
            if ($service -in $optionalServices) {
                $optionalFailed += "$($item.Name) status=$status health=$health exit=$($item.State.ExitCode)"
                continue
            }
            $failed += "$($item.Name) status=$status health=$health exit=$($item.State.ExitCode)"
        }
    }
    return [pscustomobject]@{ Running = $running; Pending = $pending; Failed = @($failed); OptionalFailed = @($optionalFailed); Missing = @($missing) }
}


function Assert-PublicGatewayBindings {
    param([string[]]$ComposeArgs)
    $gateway = Get-DockerJson -DockerArgs ($ComposeArgs + @("ps", "--format", "json", "gateway"))
    $id = [string]$gateway.ID
    if (-not $id) { throw "HTTPS gateway is not running; TCP 443 is not ready." }
    $items = @(Get-DockerJson -DockerArgs @("inspect", $id))
    $container = $items[0]
    if (-not $container.State.Running) { throw "HTTPS gateway container is stopped." }
    foreach ($port in @(80, 443)) {
        $bindings = @($container.NetworkSettings.Ports."$port/tcp")
        $public = @($bindings | Where-Object {
            [string]$_.HostPort -eq [string]$port -and [string]$_.HostIp -in @("0.0.0.0", "::")
        })
        if (-not $public.Count) { throw "Gateway TCP $port is not published on a public host interface. Check the public HTTPS Compose override." }
    }
}

function Start-PublicHttpsGateway {
    param([string[]]$ComposeArgs, [string]$PublicIP, [string]$Domain, [switch]$AllowStoredCertificate)
    # This also removes an owned bootstrap left by an earlier interrupted launch.
    # Compose scopes the removal to aetheris-gateway; other projects are untouched.
    Invoke-Docker -Title "Release owned HTTP certificate bootstrap" -DockerArgs (
        $ComposeArgs + @("--profile", "acme-bootstrap", "rm", "-sf", "acme-bootstrap"))
    Invoke-Docker -Title "Start HTTPS gateway on TCP 80/443 and automatic renewal" -DockerArgs (
        $ComposeArgs + @("up", "-d", "--no-build", "--pull", (Get-ComposePullFlag), "--force-recreate", "--wait", "--wait-timeout", "180", "gateway", "certbot-renewer"))
    Assert-PublicGatewayBindings -ComposeArgs $ComposeArgs
    Invoke-Docker -Title "Verify running HTTPS nginx" -DockerArgs ($ComposeArgs + @("exec", "-T", "gateway", "nginx", "-t"))
    $trusted = $true
    try {
        Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("probe", "--identity", $PublicIP) | Out-Null
        if ($Domain) { Invoke-CertificateTool -ComposeArgs $ComposeArgs -ToolArgs @("probe", "--identity", $Domain) | Out-Null }
    } catch {
        if (-not $AllowStoredCertificate) { throw }
        $trusted = $false
        Write-Host "HTTPS gateway is listening on TCP 443 with the stored certificate. Renewal did not succeed, so browsers may warn until public TCP 80 to $PublicIP reaches this host." -ForegroundColor Yellow
    }
    if ($trusted) {
        Write-Host "HTTPS edge is listening with verified certificates on TCP 443. Product API readiness is checked next." -ForegroundColor Green
    }
}
