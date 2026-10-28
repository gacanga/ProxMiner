#!/usr/bin/env bash
# build_host.sh - builds <dir>/proxminer.exe (MSYS2 MINGW64 g++), linked directly against <dir>/pxgpu.dll.
# Log: logs/build_host.log.  PX_HOST_ARCH overrides -march=native (release: "-march=x86-64 -mtune=generic").
set -u
cd "$(dirname "$0")/.."
OUT="${1:-dev}"
mkdir -p logs
LOG=logs/build_host.log
: > "$LOG"
echo "[$(date '+%F %T')] build_host start" >> "$LOG"
g++ --version | head -1 >> "$LOG"
if [ ! -f "$OUT/pxgpu.dll" ]; then
    echo "ERROR: $OUT/pxgpu.dll missing" | tee -a "$LOG"
    exit 1
fi
ARCH="${PX_HOST_ARCH:--march=native}"
FLAGS="-O2 $ARCH -std=gnu++17 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-unknown-pragmas -Isrc -Igpu"
if g++ $FLAGS -o "$OUT/proxminer.exe" src/main.cpp "$OUT/pxgpu.dll" -static -lws2_32 -pthread >> "$LOG" 2>&1; then
    echo "static link OK" >> "$LOG"
else
    echo "static link failed, trying dynamic link" >> "$LOG"
    if ! g++ $FLAGS -o "$OUT/proxminer.exe" src/main.cpp "$OUT/pxgpu.dll" -lws2_32 -pthread >> "$LOG" 2>&1; then
        echo "[$(date '+%F %T')] HOST BUILD FAILED" | tee -a "$LOG"
        exit 1
    fi
    echo "dynamic link OK (needs C:\\msys64\\mingw64\\bin in PATH)" >> "$LOG"
fi
echo "[$(date '+%F %T')] host OK" | tee -a "$LOG"
exit 0
