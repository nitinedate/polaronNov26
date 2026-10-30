# Install Aetheris host drive helper to start automatically at Windows logon.
# Run once on the examiner workstation (admin not required):
#   powershell -ExecutionPolicy Bypass -File scripts\install-host-drive-helper-task.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
$taskName = "AetherisHostDriveHelper"

function Install-StartupFolderFallback {
    $startup = [Environment]::GetFolderPath("Startup")
    $launcher = Join-Path $startup "AetherisHostDriveHelper.cmd"
    $content = @"
@echo off
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$ensure"
"@
    Set-Content -Path $launcher -Value $content -Encoding ASCII
    Write-Host "Registered Startup folder launcher: $launcher"
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ensure`"" `
    -WorkingDirectory $root

# Logon covers the first moment the examiner can plug in a phone. The repeat covers a
# helper that later exits (reboot of Docker, a closed window, a killed powershell): the
# ensure script returns immediately when port 9876 is already healthy.
$logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$watch = $null
foreach ($days in @(9999, 365, 31)) {
    try {
        $watch = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
            -RepetitionInterval (New-TimeSpan -Minutes 5) `
            -RepetitionDuration (New-TimeSpan -Days $days)
        break
    } catch {
        $watch = $null
    }
}
if (-not $watch) {
    $watch = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration (New-TimeSpan -Hours 23)
}
$triggers = @($logon, $watch)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

$taskRegistered = $false
try {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $triggers `
        -Settings $settings `
        -Description "Keeps the Polaron host helper (port 9876) running so connected phones and USB drives stay visible. Starts at logon and every 5 minutes if it has stopped." `
        -Force | Out-Null
    $taskRegistered = $true
    Write-Host "Registered scheduled task: $taskName (at logon for $env:USERNAME, and every 5 minutes if it has stopped)"
} catch {
    Write-Warning "Could not register scheduled task ($($_.Exception.Message)). Using Startup folder fallback."
    Install-StartupFolderFallback
}

Write-Host "Starting helper now..."
& $ensure
if ($LASTEXITCODE -eq 0) {
    Write-Host "Host drive helper is online."
} else {
    Write-Host "Helper did not respond yet - run ensure-host-drive-helper.ps1 manually or log off/on after install."
}

if ($taskRegistered) {
    exit 0
}
exit $LASTEXITCODE
