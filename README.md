# ProxMiner

No-fee, open-source **NVIDIA GPU nonce seeker for Proxima (PROX)**, with a ready-to-use Windows
package: the Proxima node, the `proxi` wallet / miner and the GPU seeker, wired together.

*Français : [README.fr.md](README.fr.md)*

> **Read this first.** The Proxima network is in its centralized **pre-launch** phase: its founder can
> stop or reset it at any time, and tokens mined on it confer no rights, are not carried over and
> disappear at a reset. PROX has no market. Mine for the exercise, at your own risk.
> ProxMiner is not affiliated with the Proxima project.

## What it is

[Proxima](https://lunfardo314.github.io) distributes 94 % of its supply through a **mine chain**: a
single chained output that moves one *transit* per ~10 s slot; each transit pays its miner. To produce a
transit you need a nonce whose **VRF output** under your own key has at least *K* trailing zero bits:

```
H     = ECVRF_encode_to_curve_TAI(pubkey, alpha_prefix || nonce)
Gamma = x * H                                    (x = your secret scalar)
beta  = SHA-512(0x03 || 0x03 || encode(8 * Gamma) || 0x00)      ECVRF-EDWARDS25519-SHA512-TAI, RFC 9381
```

Each attempt is a SHA-512, a square root and a full variable-base scalar multiplication on Ed25519, under
your private key: the work cannot be pooled, mining is solo.

The official miner `proxi node mine` follows the mine chain, verifies, proves, signs and submits, and puts
every reward into consensus (delegations), which the ledger pays in full. It can hand the nonce search to
external **nonce seekers** over a small HTTP protocol. ProxMiner is such a seeker, for NVIDIA GPUs:

- stage 1, one thread per nonce: SHA-512 of the first hash-to-curve try from a per-job midstate, point
  decoding; nonces whose first try is not a curve point are skipped (their output is never submitted);
- stage 2: Q = 8P, table of odd multiples, wNAF(5) scalar multiplication by k = 8x mod L (the same digit
  schedule for every thread: no divergence), compression, SHA-512, trailing-zero filter;
- every GPU candidate is recomputed on the CPU before it is sent, with its `beta`, so the miner checks it
  again; a GPU self-check runs at start and every 10 minutes (exit code 6 on any difference).

Field arithmetic mod 2^255 - 19 is inline PTX with carry chains (8 x 32-bit limbs, dedicated squaring),
called as real functions on the GPU so that the scalar multiplication fits the instruction cache.

About **1.3 – 1.4 MH/s per NVIDIA P104-100** (Pascal), depending on clocks (0.1.0: 0.8 – 0.9).

## Windows package (release zip)

| File | What |
|---|---|
| `proxminer.exe`, `pxgpu.dll`, `cudart64_12.dll` | the GPU seeker (CUDA 12, sm_61 + PTX) |
| `proxima.exe` | Proxima node, built unmodified from [lunfardo314/proxima](https://github.com/lunfardo314/proxima) v1.3.8p1 (commit `cb30e5a`), MIT licence (`LICENSE-PROXIMA.txt`) |
| `proxi.exe` | Proxima wallet / admin tool / official miner, same source |
| `setup.bat`, `setup_seeker.ps1` | node config, mining wallet, seeker connection |
| `check_clock.bat` | clock check (Proxima needs the clock synced, well under 80 ms) |
| `start_node.bat`, `start_mine.bat`, `seeker_loop.bat`, `stop_mine.bat` | run / stop |
| `test.bat`, `bench.bat` | GPU correctness test, 30 s benchmark |
| VC++ runtime DLLs | needed by `pxgpu.dll` |

Requirements: Windows 10/11 x64, NVIDIA GPU with a driver for CUDA 12 (Pascal or newer), an SSD with a few
GB free, a clock synced by NTP.

### Quick start

1. Unzip to a folder of its own. Run `test.bat`: it must end with `TEST ALL OK`. `bench.bat` shows the speed.
2. Run `check_clock.bat`. The offset must be close to 0 (under 0.05 s). If the Windows Time service is not
   running, turn on *Set time automatically* (Settings > Time & language) and *Sync now*.
3. Run `setup.bat`:
   - it writes `node\proxima.yaml` (the public Proxima nodes as peers and snapshot sources, API on
     127.0.0.1:8000 — if port 8000 is taken on your machine, change `api.port` there and `api.node_url`
     in `wallet\proxi.yaml`);
   - it creates the mining wallet: answer **N** to the encryption question (ProxMiner reads the key in
     clear; or set the environment variable `NONCE_SEEKER_SEED` to the 32-byte seed in hex);
   - it sets `mine.seeker.listen` (127.0.0.1:8100) and a random `mine.seeker.token` in the profile and
     writes `seeker.txt` for the seeker.
4. Run `start_node.bat` and wait until the node is synced: `node\proxima.log` shows
   `latest reliable branch is 1 slots behind`. On the first start the public nodes may refuse a snapshot
   for a few minutes (too young): the node retries by itself.
5. Run `start_mine.bat`. It starts `proxi node mine --workers 0 --stream <public nodes>` and the seeker in
   a second window (all GPUs; put e.g. `--gpus 0,1` in `gpus.txt` to choose). The seeker prints its speed
   every 30 s; `proxi` prints the rounds and the transits it wins.
6. `stop_mine.bat` stops the miner and the seeker (it ends every `proxi.exe` and `proxminer.exe` process).

### Keep in mind

- **The key.** The seeker needs the private key: mine with a dedicated wallet, back up
  `wallet\proxima.key`, keep the folder private.
- **Updates.** The ledger names the miner version it expects. When `proxi` says *update proxi*, take a newer
  `proxi.exe` (and `proxima.exe`) from the Proxima project; ProxMiner keeps working as long as the seeker
  protocol and the work function do not change.
- **Network resets.** After a reset, stop the node, delete `node\proximadb` and `node\proximadb.txstore`,
  and start again (see the Proxima docs).
- The node API has no authentication: keep it on 127.0.0.1.

## Command line

```
proxminer --proxi http://127.0.0.1:8100 --token T --key-file wallet\proxima.key [--gpus 0,1] [--log seeker.log]
proxminer --test [--gpus ...]          GPU against the CPU reference, then exit
proxminer --bench 30 [--gpus ...]      benchmark on a synthetic job, then exit
```

Other options: `--name`, `--batch-ms` (GPU time per batch, default 300), `--tpb1/--tpb2/--blocks2`
(launch geometry), `--selfcheck MIN`, `--args-file F`. Exit codes: 2 options/key, 3 no GPU, 4 CUDA error,
6 self-check failed.

## Building

- GPU engine `pxgpu.dll`: CUDA 12.9 + Visual Studio 2022 (`windows\build_gpu_dll.bat`).
- Host `proxminer.exe`: MSYS2 MINGW64 g++ (`windows/build_host.sh`). `build_all.bat` builds both into
  `dev\` and runs the test.
- Tests without a GPU (Linux or MSYS2):
  - `g++ -O2 -std=gnu++17 -Igpu tests/core_test.cpp -o core_test && ./core_test cases.txt` — RFC 9381
    vectors and the fast path against the generic reference;
  - `python3 tests/ref_vrf.py --check cases.txt` — the same cases recomputed by an independent Python
    implementation;
  - `tests/px_stub.cpp` (CPU stand-in for `pxgpu.dll`) + `tests/fake_proxi.py` (fake job server of
    `proxi node mine`) — end-to-end test of the seeker;
  - `python3 tests/ptx_sim.py gpu/fe_ptx.h` — the PTX field arithmetic run by a small interpreter against
    Python integers. `gpu/fe_ptx.h` is generated by `python3 tools/gen_fe_ptx.py > gpu/fe_ptx.h`.
- Build options: `-DPX_FE_C` (portable C arithmetic on the GPU), `-DPX_FE_INLINE` (inline field
  functions; slower on Pascal).
- `proxima.exe` / `proxi.exe`: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`
  in the Proxima repository (`.` and `./proxi`).

## Licence

ProxMiner: Apache-2.0 (`LICENSE`). No developer fee. Proxima (`proxima.exe`, `proxi.exe`): MIT,
© Evaldas Drasutis (`LICENSE-PROXIMA.txt`).
