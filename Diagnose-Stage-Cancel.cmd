@echo off
rem V1.10.3: why did a forensic stage stop?  Usage: Diagnose-Stage-Cancel.cmd [JOB_ID]
setlocal
cd /d "%~dp0"
echo ===== Parse worker container: start time, restarts, OOM kill =====
for /f %%c in ('docker compose ps -a -q worker-parse') do docker inspect --format "{{.Name}} started={{.State.StartedAt}} restarts={{.RestartCount}} oom_killed={{.State.OOMKilled}} exit={{.State.ExitCode}}" %%c
echo.
echo ===== Parse worker shutdown / signal / memory lines, last 48 h =====
docker compose logs --no-color --since 48h worker-parse 2>&1 | findstr /i /c:"shutdown" /c:"SIGTERM" /c:"SIGQUIT" /c:"Killed" /c:"MemoryError" /c:"stopped by its owner" /c:"from outside its owner" /c:"cancelled"
echo.
echo ===== Docker events for the parse worker, last 48 h =====
docker events --since 48h --until 0s --filter "label=com.docker.compose.service=worker-parse" --filter "type=container" --format "{{.Time}} {{.Action}}" 2>nul
echo.
echo ===== Pipeline timeline from the database =====
docker compose exec -T api python scripts/diagnose_stage_cancel.py %1
endlocal
