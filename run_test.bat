@echo off
REM run_test.bat - dev\proxminer.exe --test (GPU against the CPU reference) -> logs\test.log
REM   options (e.g. --gpus 4) in run\test_args.txt
setlocal EnableExtensions
cd /d "%~dp0"
set "ARGS="
if exist run\test_args.txt set /p ARGS=<run\test_args.txt
echo [%date% %time%] test %ARGS% > logs\test.log
dev\proxminer.exe --test %ARGS% >> logs\test.log 2>&1
echo [exit %errorlevel%] >> logs\test.log
exit /b 0
