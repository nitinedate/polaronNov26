@echo off
setlocal
cd /d "%~dp0"
rem Applies V1.9.7 on an installed laptop: .env clean-up, configure-openvas,
rem scanner-agent recreate, checks. Extra arguments are passed on (-Force, -SkipEnv).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Apply-Scanner-v1.9.7.ps1" %*
if errorlevel 1 pause
endlocal
