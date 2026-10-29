@echo off
rem Polaron Client Evidence Agent - one-time installer.
rem Keep this file next to polaron-client-evidence-agent.ps1 and double-click it.
rem Optional: Install-PolaronClientEvidenceAgent.cmd -ConsoleOrigin https://polaron.lab -AllowedServer 10.20.30.5
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%~dp0polaron-client-evidence-agent.ps1" (
  echo polaron-client-evidence-agent.ps1 was not found next to this file.
  echo Download both files from Polaron into the same folder and run this again.
  pause
  exit /b 1
)
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0polaron-client-evidence-agent.ps1" -Install %*
echo.
pause
