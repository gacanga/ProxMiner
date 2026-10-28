# Changelog

## 0.1.0 - 2026-10-28

- First release: CUDA nonce seeker for `proxi node mine` (external nonce seeker protocol), work function
  ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) as the Proxima mine chain requires.
- Two-stage GPU engine (hash + point decoding, then wNAF(5) scalar multiplication), every candidate
  recomputed on the CPU, GPU self-check at start and every 10 minutes.
- Windows package with the Proxima node and wallet (`proxima.exe`, `proxi.exe`, v1.3.8p1, unmodified)
  and setup / start / stop scripts.
- Tests: RFC 9381 vectors, independent Python reference, CPU stand-in + fake job server.
