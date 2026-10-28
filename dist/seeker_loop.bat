@echo off
REM seeker_loop.bat - ProxMiner GPU seeker, restarted if it stops (started by start_mine.bat)
setlocal EnableExtensions
title ProxMiner - GPU seeker
cd /d "%~dp0"
:again
set "GPUS="
if exist gpus.txt set /p GPUS=<gpus.txt
proxminer.exe --key-file wallet\proxima.key --args-file seeker.txt %GPUS% --log seeker.log
if exist mine.stop goto end
echo [%date% %time%] seeker stopped (exit %errorlevel%), restart in 10 s
timeout /t 10 /nobreak >nul
if exist mine.stop goto end
goto again
:end
