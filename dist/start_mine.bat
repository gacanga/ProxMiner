@echo off
REM ===========================================================================
REM start_mine.bat - proxi node mine (wallet\, serves jobs to the seeker, places the rewards)
REM   + the ProxMiner GPU seeker in its own window (seeker_loop.bat).  Both restart if they stop.
REM   GPUs and other seeker options: gpus.txt (e.g. --gpus 0,1,2), default all GPUs.
REM   Extra mining streams: stream.txt (one line, comma separated node API URLs).
REM   Stop: stop_mine.bat.  Logs: mine.log, seeker.log
REM ===========================================================================
setlocal EnableExtensions
title ProxMiner - proxi node mine
cd /d "%~dp0"
if not exist seeker.txt (
    echo seeker.txt missing: run setup.bat first.
    pause
    exit /b 1
)
if exist mine.stop del /q mine.stop
set "STREAM=http://65.21.170.230:8001,http://79.137.70.25:8001,http://51.254.47.76:8001"
if exist stream.txt set /p STREAM=<stream.txt
start "ProxMiner - GPU seeker" cmd /c seeker_loop.bat
:again
echo [%date% %time%] proxi node mine --workers 0 --stream %STREAM%
pushd wallet
..\proxi.exe node mine --workers 0 --stream %STREAM%
popd
if exist mine.stop goto end
echo [%date% %time%] proxi node mine stopped, restart in 10 s
timeout /t 10 /nobreak >nul
if exist mine.stop goto end
goto again
:end
echo stopped.
