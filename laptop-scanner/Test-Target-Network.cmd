@echo off
setlocal EnableExtensions
if "%~1"=="" (
  echo Usage: Test-Target-Network.cmd TARGET_IP
  echo Example: Test-Target-Network.cmd 192.168.0.164
  exit /b 2
)
rem Run only the explicitly named local diagnostic; no persistent policy change.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Target-Network.ps1" -TargetIP "%~1"
exit /b %ERRORLEVEL%
