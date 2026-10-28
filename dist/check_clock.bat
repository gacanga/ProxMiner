@echo off
REM check_clock.bat - Proxima needs the clock synced to real time (well under 80 ms).
REM   Shows the Windows Time status and the offset to pool.ntp.org.
REM   If the service is not running or the offset is above ~0.05 s: Settings > Time & language >
REM   Date & time > "Set time automatically" ON, then "Sync now"; or, as administrator:
REM     net start w32time  &  w32tm /resync /force
cd /d "%~dp0"
w32tm /query /status
echo.
w32tm /stripchart /computer:pool.ntp.org /samples:4 /dataonly
echo.
echo The offsets above (+/- seconds) should be close to 0 (under 0.05 s).
pause
