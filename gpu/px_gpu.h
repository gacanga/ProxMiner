/**
 * ProxMiner - pxgpu.dll API (CUDA engine of the Proxima mine-chain proof of work:
 * ECVRF-EDWARDS25519-SHA512-TAI output, see px_core.h)
 */
#pragma once
#include <stdint.h>
#include "px_core.h"

#if defined(_WIN32)
#  if defined(PXGPU_BUILD)
#    define PX_API extern "C" __declspec(dllexport)
#  else
#    define PX_API extern "C" __declspec(dllimport)
#  endif
#else
#  define PX_API extern "C"
#endif

#define PX_MAX_FOUND 64

/* number of CUDA devices, < 0 on error */
PX_API int px_device_count(void);
/* name and PCI bus of a device into buf */
PX_API int px_device_name(int dev, char *buf, int len);
/*
 * Opens a device.  max_items = largest batch (nonces per px_scan call).
 * tpb1 / tpb2 = threads per block of stage 1 (hash + decode) / stage 2 (scalar multiplication),
 * blocks2 = blocks of stage 2 (grid-stride), 0 = defaults.  NULL + err on error.
 */
PX_API void *px_create(int dev, uint32_t max_items, int tpb1, int tpb2, int blocks2, char *err, int errlen);
PX_API void px_destroy(void *ctx);
/* key (wNAF digits of 8x mod L) and job (midstate, k) */
PX_API int px_set_key(void *ctx, const px_key *key);
PX_API int px_set_job(void *ctx, const px_job *job);
/*
 * Nonce counters [base, base + count) (56 bits, wrapping): stage 1 keeps those whose ctr = 0 hash is
 * a point (*nvalid of them: these are the attempts), stage 2 computes their beta and returns up to
 * max_found counters whose beta has >= job.k trailing zero bits (*nfound may exceed max_found).
 * count must be a multiple of tpb1 and <= max_items.  Blocking.  ms_gpu (optional) = GPU time.
 * Returns 0 or a CUDA error code.
 */
PX_API int px_scan(void *ctx, uint64_t base, uint32_t count, uint64_t *found, int max_found, int *nfound,
		uint32_t *nvalid, float *ms_gpu);
/* test: for counters [base, base + count): valid[i] = 1 if ctr 0 decodes, and then beta (64 bytes) */
PX_API int px_debug(void *ctx, uint64_t base, uint32_t count, uint8_t *valid, uint8_t *betas);
/* last CUDA error text */
PX_API const char *px_error_string(int code);
/* kernel attributes (registers, local memory bytes) of stage 1 and 2, for the logs */
PX_API int px_kernel_info(void *ctx, int *regs1, int *local1, int *regs2, int *local2);
