@echo off
REM stop_mine.bat - stops proxi node mine and the ProxMiner seeker (the node keeps running)
cd /d "%~dp0"
echo stop> mine.stop
taskkill /im proxminer.exe >nul 2>&1
taskkill /im proxi.exe >nul 2>&1
timeout /t 3 /nobreak >nul
taskkill /f /im proxminer.exe >nul 2>&1
taskkill /f /im proxi.exe >nul 2>&1
echo stopped.
pause
