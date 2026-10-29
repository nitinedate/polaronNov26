@echo off
rem Point MinIO's data folder (MINIO_DATA_DIR in .env) to a new location. Default: D:/aetheris/minio
rem   Set-MinioDataDir.cmd
rem   Set-MinioDataDir.cmd -Path E:/storage/minio -CopyFrom F:/aetheris/minio
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Set-MinioDataDir.ps1" %*
set ERR=%ERRORLEVEL%
echo.
pause
exit /b %ERR%
