@echo off
REM bench.bat - 30 s benchmark of every GPU on a synthetic job (no network, no key needed)
cd /d "%~dp0"
proxminer.exe --bench 30 %*
pause
