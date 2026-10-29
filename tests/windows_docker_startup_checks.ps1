param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
. (Join-Path $ProjectRoot 'script_docker/start_docker.lib.ps1')
$script:checks = 0
function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
function Assert-Throws([scriptblock]$Body, [string]$Message) {
    $threw = $false
    try { & $Body | Out-Null } catch { $threw = $true }
    Assert-True $threw $Message
}
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('aetheris-start-check-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory (Join-Path $tempRoot 'script_docker') -Force | Out-Null
Copy-Item (Join-Path $ProjectRoot 'script_docker/start_docker.settings.example.json') (Join-Path $tempRoot 'script_docker/start_docker.settings.example.json')
try {
    $prod = Get-DeploymentSettings -Root $tempRoot -Profile prod -AcmeEmail admin@example.com
    Assert-True ($prod.Domain -eq '') 'Production has no DNS dependency'
    Assert-True ($prod.PublicIP -eq '122.179.141.248') 'Production defaults stay configurable'
    $prod.PublicIP = '8.8.4.4'
    Save-DeploymentSettings -Settings $prod -Profile prod
    $persisted = Get-DeploymentSettings -Root $tempRoot -Profile prod
    Assert-True ($persisted.PublicIP -eq '8.8.4.4' -and $persisted.AcmeEmail -eq 'admin@example.com') 'User settings persist across launches'
    $nitin = Get-DeploymentSettings -Root $tempRoot -Profile nitin
    Assert-True ($nitin.Domain -eq 'future-softtech.co.in') 'Nitin domain defaults retained'
    $custom = Get-DeploymentSettings -Root $tempRoot -Profile nitin -PublicIP 8.8.8.8 -Domain example.org
    Assert-True ($custom.Domain -eq 'example.org' -and $custom.PublicIP -eq '8.8.8.8') 'CLI host overrides work'
    foreach ($badIP in @('192.168.1.10','10.0.0.1','172.16.0.1','127.0.0.1','169.254.1.1','100.64.0.1','224.1.1.1','999.1.1.1','1.2.3.4;id')) {
        Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile prod -PublicIP $badIP } "Reject private or malformed IP: $badIP"
    }
    Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile prod -Domain example.org } 'Production rejects domain overrides'
    Assert-Throws { Get-DeploymentSettings -Root $tempRoot -Profile nitin -Domain 'a;return 200;' } 'Reject nginx domain injection'
    $normal = @(Get-AppBuildArgs -BuildId first)
    $next = @(Get-AppBuildArgs -BuildId second)
    Assert-True ($normal -notcontains '--no-cache' -and $normal -notcontains '--pull') 'Normal application builds retain dependencies'
    Assert-True ($normal[-1] -ne $next[-1]) 'Every launch can invalidate application compilation'
    $refresh = @(Get-AppBuildArgs -BuildId first -RefreshDependencies)
    Assert-True ($refresh -contains '--no-cache' -and $refresh -contains '--pull') 'Dependency refresh is explicit'
    Assert-Throws { Get-AppBuildArgs -BuildId '' } 'Empty application build ID is rejected'
    $nginxProd = Get-PublicNginxConfig -PublicIP 8.8.8.8
    Assert-True ($nginxProd -match 'aetheris-ip-8.8.8.8/fullchain.pem' -and $nginxProd -notmatch 'aetheris-domain') 'IP configuration has no domain certificate'
    Assert-True ($nginxProd -match 'return 308 https://8.8.8.8\$request_uri') 'Production HTTP redirects to configured IP'
    Assert-True ($nginxProd -match 'location \^~ /\.well-known/acme-challenge/' -and $nginxProd -match 'listen 80 default_server' -and $nginxProd -match 'listen 443 ssl default_server') 'HTTP-01 remains available on public ports'
    $nginxNitin = Get-PublicNginxConfig -PublicIP 8.8.8.8 -Domain example.org
    Assert-True ($nginxNitin -match 'aetheris-domain-example.org' -and $nginxNitin -match 'aetheris-ip-8.8.8.8') 'Domain and IP get separate TLS certificates'
    $ipIssue = @(Get-CertbotIssueArgs -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP)
    Assert-True ($ipIssue -contains '--ip-address' -and $ipIssue -contains 'shortlived' -and $ipIssue -notcontains '-d' -and $ipIssue -notcontains '--staging') 'IP issuance uses production shortlived ACME profile'
    $domainIssue = @(Get-CertbotIssueArgs -Identity example.org -CertName aetheris-domain-example.org -Email admin@example.com)
    Assert-True ($domainIssue -contains '-d' -and $domainIssue -notcontains '--ip-address') 'Domain issuance uses DNS identifier'

    $script:dockerCalls = New-Object System.Collections.Generic.List[object]
    function Invoke-Docker {
        param([string]$Title, [string[]]$DockerArgs)
        $script:dockerCalls.Add(@($DockerArgs))
    }
    $script:managed = $true
    function Invoke-CertificateTool {
        param([string[]]$ComposeArgs, [string[]]$ToolArgs)
        return [pscustomobject]@{ managed = $script:managed; valid = $true; expires_utc = 'test' }
    }
    Ensure-PublicCertificate -ComposeArgs @('compose') -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP
    Assert-True ($script:dockerCalls[0] -contains 'renew' -and $script:dockerCalls[0] -notcontains 'certonly') 'Existing certificates are renewed only when due'
    $script:managed = $false
    Ensure-PublicCertificate -ComposeArgs @('compose') -Identity 8.8.8.8 -CertName aetheris-ip-8.8.8.8 -Email admin@example.com -IsIP
    Assert-True ($script:dockerCalls[1] -contains 'certonly') 'Missing certificate lineage is acquired'
    function Get-NetTCPConnection { param($LocalPort,$State,$ErrorAction); return @() }
    function docker { $global:LASTEXITCODE = 0; return @('fake-container') }
    $script:owner = 'another-project'
    function Get-DockerJson {
        param([string[]]$DockerArgs)
        return [pscustomobject]@{ Name = '/test'; Config = [pscustomobject]@{ Labels = [pscustomobject]@{
            'com.docker.compose.project' = $script:owner; 'com.docker.compose.service' = 'gateway'
        }}; HostConfig = [pscustomobject]@{PortBindings = [pscustomobject]@{'80/tcp' = @([pscustomobject]@{HostPort = '80'})}} }
    }
    Assert-Throws { Assert-PublicPortOwners } 'Another Docker project owning TCP 80 blocks deployment'
    $script:owner = 'aetheris-gateway'
    Assert-PublicPortOwners
    Assert-True $true 'Own gateway can be upgraded without removing another project'
    function Get-NetTCPConnection { param($LocalPort,$State,$ErrorAction); return @([pscustomobject]@{OwningProcess=4242}) }
    function Get-Process { param($Id,$ErrorAction); return [pscustomobject]@{ProcessName='caddy';Id=4242} }
    Assert-Throws { Assert-PublicPortOwners } 'Caddy/IIS port conflicts are reported without termination'

    $registryError = @'
failed to resolve source metadata for docker.io/docker/dockerfile:1: failed to do request: Head "https://registry-1.docker.io/v2/docker/dockerfile/manifests/1": dial tcp: lookup registry-1.docker.io: no such host
'@
    Assert-True (Test-DockerRegistryDnsFailure $registryError) 'Docker Hub DNS failure is retried'
    Assert-True (Test-DockerRegistryDnsFailure 'lookup registry-1.docker.io: no such host') 'Plain registry lookup failure is retried'
    $proxyError = 'Head "https://registry-1.docker.io/v2/library/node/manifests/20-alpine": http: server gave HTTP response to HTTPS client'
    Assert-True (Test-DockerRegistryDnsFailure $proxyError) 'Docker Hub HTTP-on-HTTPS response is retried'
    Assert-True (-not (Test-DockerRegistryDnsFailure 'Failed to fetch http://archive.ubuntu.com/ubuntu 400 Bad Request')) 'Ubuntu archive 400 is not a registry DNS failure'
    Assert-True (-not (Test-DockerRegistryDnsFailure 'docker compose failed for gateway')) 'Ordinary compose failures are not retried as DNS'
    $tokenError = 'failed to resolve reference "docker.io/dpage/pgadmin4:8": failed to authorize: failed to fetch oauth token: Post "https://auth.docker.io/token": remote error: tls: protocol version not supported'
    Assert-True (Test-DockerRegistryDnsFailure $tokenError) 'Docker Hub token TLS failures are retried'
    $commonProxyError = 'failed to resolve reference "docker.io/dpage/pgadmin4:8": Head "https://registry-1.docker.io/v2/dpage/pgadmin4/manifests/8": http: server gave HTTP response to HTTPS client'
    Assert-True (Test-DockerRegistryDnsFailure $commonProxyError) 'Shared image manifest failures are retried'
    $remoteImages = @(Get-RemoteComposeImages -Config ([pscustomobject]@{
        services = [pscustomobject]@{
            postgres = [pscustomobject]@{ image = 'pgvector/pgvector:pg16' }
            api = [pscustomobject]@{ image = 'aetheris-forensic-api'; build = [pscustomobject]@{ context = '.' } }
            pgadmin = [pscustomobject]@{ image = 'dpage/pgadmin4:8' }
            again = [pscustomobject]@{ image = 'pgvector/pgvector:pg16' }
        }
    }))
    Assert-True ($remoteImages.Count -eq 2 -and $remoteImages -contains 'dpage/pgadmin4:8' -and $remoteImages -notcontains 'aetheris-forensic-api') 'Only published images are pulled before compose up'
    $volumeNames = @(Get-ExternalComposeVolumeNames -Config ([pscustomobject]@{
        volumes = [pscustomobject]@{
            pgdata = [pscustomobject]@{ external = $true; name = 'aetheris-forensic_pgdata' }
            redis_data = [pscustomobject]@{}
        }
    }))
    Assert-True ($volumeNames.Count -eq 1 -and $volumeNames -contains 'aetheris-forensic_pgdata') 'External database volumes are created before compose up'
    $bypass = @(Get-DockerHubBypassHosts)
    Assert-True ($bypass -contains 'registry-1.docker.io' -and $bypass -contains 'auth.docker.io') 'Docker Hub hosts bypass the HTTP proxy'
    $merged = Merge-DockerDaemonDns -JsonText '{"builder":{"gc":{"defaultKeepStorage":"20GB","enabled":true}},"experimental":false,"dns":["8.8.8.8"]}'
    $mergedObj = $merged | ConvertFrom-Json
    Assert-True ($mergedObj.builder.gc.defaultKeepStorage -eq '20GB' -and $mergedObj.experimental -eq $false) 'DNS repair keeps existing daemon settings'
    Assert-True (@($mergedObj.dns) -contains '8.8.8.8' -and @($mergedObj.dns) -contains '1.1.1.1') 'DNS repair adds public resolvers once'
    Assert-True (@($mergedObj.dns | Where-Object { $_ -eq '8.8.8.8' }).Count -eq 1) 'Existing public resolver is not duplicated'
    foreach ($scenario in @('local', 'nitin', 'prod')) {
        $cmd = [IO.File]::ReadAllText((Join-Path $ProjectRoot "script_docker/start_docker_$scenario.cmd"))
        Assert-True ($cmd -match 'start_docker\.ps1' -and $cmd -match "-Profile $scenario") "$scenario launcher uses the shared startup preflight"
    }
    $assertReady = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'scripts/assert-docker-ready.ps1'))
    Assert-True ($assertReady -match 'Ensure-DockerRegistryDns') 'Every Docker-ready check resolves registry-1.docker.io'
    $launcher = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'script_docker/start_docker.lib.ps1'))
    Assert-True ($launcher -match 'Test-DockerRegistryDnsFailure' -and $launcher -match 'retry \$attempt of \$max after Docker Hub did not answer') 'Shared build action retries registry connection failures'
    Assert-True ($assertReady -match 'Enable-DockerDesktopProxyScheme') 'Startup bypasses the HTTP proxy for Docker Hub before builds'
    Assert-True ($launcher -notmatch 'http://http\.docker\.internal') 'Startup does not send the client through the VM-only proxy name'
    $starter = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'script_docker/start_docker.ps1'))
    Assert-True ($starter -match 'Ensure-SharedDockerNetwork' -and $starter -notmatch 'network inspect aetheris-common \*>') 'A missing shared network is created instead of aborting startup'
    Assert-True ($starter -match 'PSNativeCommandUseErrorActionPreference = \$false') 'Native Docker failures stay non-terminating in the launcher'
    Assert-True ($launcher -match 'function Ensure-SharedDockerNetwork') 'Shared network creation lives in the startup library'
    $stack = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'scripts/start-stack.ps1'))
    Assert-True ($launcher -match 'function Ensure-ComposeImagesPresent' -and $starter -match 'Ensure-ComposeImagesPresent') 'Startup pulls missing images one at a time before compose up'
    Assert-True ($launcher -match 'function Ensure-ComposeExternalVolumes' -and $starter -match 'Ensure-ComposeExternalVolumes') 'Startup creates external volumes before compose up'
    Assert-True ($launcher -match 'function Stop-PodmanAetherisContainers' -and $launcher -match '-u root -- podman stop' -and $launcher -notmatch 'podman rm') 'Startup stops rootful Podman containers that hold the published ports'
    Assert-True ($starter -match 'Stop-PodmanAetherisContainers') 'The Docker launcher stops conflicting Podman containers before compose up'
    Assert-True ($starter -match 'function Clear-StackPublishedPorts' -and $starter -match 'Clear-StackPublishedPorts -ComposeArgs \$ComposeArgs -Services @\(''api''\)') 'Vulnerability API startup frees host port 8082 before compose up'
    Assert-True ($stack -match 'Clear-OccupiedHostPorts -Docker \$docker -ComposeArgs \$commonArgs') 'start-stack frees shared host ports before compose up'
    $commonCompose = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'services/common/docker-compose.yml'))
    Assert-True ($commonCompose -match '(?s)networks:\s+default:\s+name:\s+aetheris-common\s+external:\s+true') 'The shared network is external so a pre-created bridge is accepted'
    Assert-True ($stack -match 'Ensure-ComposeImagesPresent') 'start-stack pulls shared images before compose up'
    Assert-True ($stack -match 'Invoke-Docker -Exe \$Docker' -and $stack -match 'Build/start gateway') 'start-stack builds retry registry DNS failures'
    foreach ($dockerfile in @('frontend/Dockerfile', 'backend/Dockerfile', 'backend/Dockerfile.malware', 'backend/Dockerfile.scanner')) {
        $text = [IO.File]::ReadAllText((Join-Path $ProjectRoot $dockerfile))
        Assert-True ($text -notmatch '(?m)^#\s*syntax=docker/dockerfile') "$dockerfile does not pull the Docker Hub frontend image"
    }
    Write-Host "PASS: $script:checks Windows startup behavior checks (offline Docker mocks)."
} finally { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
