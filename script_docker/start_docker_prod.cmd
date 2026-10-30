@echo off
setlocal
title Aetheris - start_docker_prod
cd /d "%~dp0.."
echo.
echo  Production HTTPS: https://122.179.141.248/ (public TCP 80 and 443). No domain required.
echo  Order: down Polaron containers, pull each library image once, build each
echo  application once, start every stack, then verify containers and HTTPS.
echo  NVIDIA CUDA, PyTorch, Python, npm, databases, scanners, and Certbot are
echo  pulled once. Forensic, Android, iOS, and the vulnerability API share that
echo  backend image instead of downloading it again per service.
echo  An image already stored by Docker is not downloaded again.
echo  Let's Encrypt certificate for 122.179.141.248 is issued or renewed.
echo  certbot-renewer checks every 6 hours and reloads nginx after a renew.
echo  Public TCP 80 and 443 must be forwarded to this Windows host.
echo  Volumes, evidence, and unrelated projects are preserved (no down -v).
echo  Frontend HTTP: http://localhost:3001/ (also available via host LAN IP:3001).
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
  echo  Startup finished. Open https://122.179.141.248/
)
if not "%AETHERIS_NO_PAUSE%"=="1" pause
exit /b %ERR%
