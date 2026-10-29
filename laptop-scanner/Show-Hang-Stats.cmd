@echo off
setlocal EnableExtensions
rem Shows which Greenbone checks (NVTs) keep timing out and which fast mode caps.
rem Usage: Show-Hang-Stats.cmd            (table)
rem        Show-Hang-Stats.cmd --reset OID (forget one NVT)
cd /d "%~dp0"
docker compose exec -T scanner-agent python -m agent.nvt_hang_stats %*
exit /b %ERRORLEVEL%
