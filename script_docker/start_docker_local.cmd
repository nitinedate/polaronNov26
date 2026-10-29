@echo off
setlocal
title Aetheris - start_docker_local
cd /d "%~dp0.."
echo.
echo  Local HTTP only (no HTTPS / certificates). Same stacks and gateway as prod.
echo  Stops only Polaron stacks, then rebuilds and starts all application stacks.
echo  Existing Docker volumes, evidence, and unrelated projects are preserved.
echo  Frontend HTTP: http://localhost:3001/ (also available via host LAN IP:3001).
echo  Drive scan is time-limited (AETHERIS_DRIVE_SCAN_TIMEOUT_SEC, default 240 s).
echo  Application compiles every launch. Dependencies use Docker cache.
echo  First launch creates missing .env and host settings automatically.
echo  Host settings: script_docker\start_docker.settings.json
echo  Optional checks: -PrepareOnly or -ValidateOnly
echo  Optional maintenance: -RefreshDependencies
echo.
if not exist "%~dp0start_docker.ps1" (
  echo.
  echo  ERROR: Missing %~dp0start_docker.ps1
  echo  Extract the complete Polaron project ZIP and retry.
  echo.
  if not "%AETHERIS_NO_PAUSE%"=="1" pause
  exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile local %*
set "ERR=%ERRORLEVEL%"
echo.
if %ERR% neq 0 (
  echo  Startup failed with exit code %ERR%.
) else (
  echo  Startup finished. Open http://localhost:3001/
)
if not "%AETHERIS_NO_PAUSE%"=="1" pause
exit /b %ERR%
