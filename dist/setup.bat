@echo off
REM ===========================================================================
REM setup.bat - first-time setup of ProxMiner, in this folder:
REM   node\proxima.yaml   Proxima access node configuration (proxi config node)
REM   wallet\proxi.yaml   mining wallet profile + wallet\proxima.key (proxi config wallet)
REM   seeker.txt          connection of the GPU seeker to proxi node mine (random token)
REM Existing files are kept.  Run it again at any time.
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"
if not exist node mkdir node
if not exist wallet mkdir wallet

echo.
echo === 1/3 node configuration (node\proxima.yaml)
if exist node\proxima.yaml (
    echo node\proxima.yaml already exists, kept.
) else (
    pushd node
    ..\proxi.exe config node
    popd
)

echo.
echo === 2/3 mining wallet (wallet\proxi.yaml, wallet\proxima.key)
if exist wallet\proxima.key (
    echo wallet\proxima.key already exists, kept.
) else (
    echo Answer N to "Encrypt the key file with a passphrase?": ProxMiner reads the key in clear.
    echo Use a DEDICATED mining wallet that holds nothing else, and back up wallet\proxima.key.
    pushd wallet
    ..\proxi.exe config wallet
    popd
)

echo.
echo === 3/3 seeker connection (mine.seeker in wallet\proxi.yaml, seeker.txt)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_seeker.ps1"

echo.
echo Next: check_clock.bat, then start_node.bat, wait until the node is synced, then start_mine.bat
pause
