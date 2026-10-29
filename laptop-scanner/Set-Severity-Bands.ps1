# Updates only vulnerability severity thresholds in the existing .env.
# No containers, volumes, credentials or evidence are modified.
param([string]$ProjectRoot = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$envPath = Join-Path $ProjectRoot '.env'
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Cannot find existing .env at $envPath. Preserve your production .env and rerun from its folder."
}
$backupPath = "$envPath.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item -LiteralPath $envPath -Destination $backupPath -ErrorAction Stop
$text = [System.IO.File]::ReadAllText($envPath)
$settings = [ordered]@{
    VULN_SEVERITY_CRITICAL_MIN = '8.0'
    VULN_SEVERITY_HIGH_MIN = '6.0'
    VULN_SEVERITY_MEDIUM_MIN = '4.0'
    VULN_SEVERITY_LOW_MIN = '0.1'
}
$lineEnding = if ($text.Contains("`r`n")) { "`r`n" } else { "`n" }
foreach ($entry in $settings.GetEnumerator()) {
    $regex = '(?m)^' + [regex]::Escape($entry.Key) + '=.*$'
    $replacement = $entry.Key + '=' + $entry.Value
    if ([regex]::IsMatch($text, $regex)) {
        $text = [regex]::Replace($text, $regex, $replacement)
    } else {
        if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $text += $lineEnding }
        $text += $replacement + $lineEnding
    }
}
[System.IO.File]::WriteAllText($envPath, $text, [System.Text.UTF8Encoding]::new($false))
Write-Host "Updated severity thresholds in $envPath"
Write-Host "Backup saved to $backupPath"
Write-Host 'Recreate affected containers to load the new environment. Do not delete volumes.'
