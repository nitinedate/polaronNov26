@echo off
setlocal EnableExtensions
if "%~1"=="" (
  echo Usage: Diagnose-Report.cmd REPORT_ID [TARGET_IP]
  echo Example: Diagnose-Report.cmd 034bf5f5-ff36-4f9f-ac7f-3935036b3b99 192.168.0.163
  echo Prints every result, timed-out checks, open ports and the V1.6.5 verdict.
  exit /b 2
)
rem Read-only: never creates, stops or uploads anything.
cd /d "%~dp0"
if "%~2"=="" (
  docker compose exec -T scanner-agent python -m agent.report_diagnose "%~1"
) else (
  docker compose exec -T scanner-agent python -m agent.report_diagnose "%~1" --host "%~2"
)
exit /b %ERRORLEVEL%
