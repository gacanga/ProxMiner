@echo off
REM start_node.bat - Proxima access node (proxima.exe, working folder node\), restarted if it stops.
REM   First start: it downloads a recent snapshot from the public nodes (may be refused for a few
REM   minutes while their latest snapshot is too young: it just retries).  Log: node\proxima.log
setlocal EnableExtensions
title ProxMiner - Proxima node
cd /d "%~dp0"
if not exist node\proxima.yaml (
    echo node\proxima.yaml missing: run setup.bat first.
    pause
    exit /b 1
)
:again
echo [%date% %time%] node start
pushd node
..\proxima.exe
popd
echo [%date% %time%] node stopped, restart in 10 s (close this window to stop it)
timeout /t 10 /nobreak >nul
goto again
