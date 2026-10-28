@echo off
REM test.bat - every GPU against the CPU reference (RFC 9381 vector, 3 x 4096 nonces, candidate filter); must end with TEST ALL OK
cd /d "%~dp0"
proxminer.exe --test %*
pause
