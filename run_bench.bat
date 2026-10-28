@echo off
REM run_bench.bat - dev\proxminer.exe --bench (options in run\bench_args.txt, e.g. --bench 30 --gpus 4) -> logs\bench.log
setlocal EnableExtensions
cd /d "%~dp0"
set "ARGS=--bench 30"
if exist run\bench_args.txt set /p ARGS=<run\bench_args.txt
echo [%date% %time%] bench %ARGS% > logs\bench.log
dev\proxminer.exe %ARGS% >> logs\bench.log 2>&1
echo [exit %errorlevel%] >> logs\bench.log
type logs\bench.log >> logs\bench_history.log
exit /b 0
