@echo off
setlocal
title Aetheris - start_docker_prod
cd /d "%~dp0.."
echo.
echo  Trusted HTTPS for the configured static public IP on ports 80/443. No domain required.
echo  HTTPS gateway starts after certificate validation, before product stacks.
echo  Public TCP 80 and 443 must be forwarded to this Windows host.
echo  Stops only Polaron stacks, then rebuilds and starts all application stacks.
echo  Existing Docker volumes, evidence, and unrelated projects are preserved.
echo  Frontend HTTP: http://localhost:3001/ (also available via host LAN IP:3001).
echo  Production HTTPS: https://122.179.141.248/ (public TCP 80/443).
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_docker.ps1" -Profile prod %*
set "ERR=%ERRORLEVEL%"
echo.
if %ERR% neq 0 (
  echo  Startup failed with exit code %ERR%.
) else (
  echo  Startup finished.
)
if not "%AETHERIS_NO_PAUSE%"=="1" pause
exit /b %ERR%
