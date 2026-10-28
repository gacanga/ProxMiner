/**
 * ProxMiner - CUDA engine (pxgpu.dll / linked object), NVIDIA Pascal sm_61 and later.
 *   stage 1 (k_stage1): one thread per nonce counter: SHA-512 of the first hash-to-curve try from the
 *            job midstate, point decoding (one square root); decodable ones are appended to a buffer
 *            (warp-aggregated atomics), the others are skipped.
 *   stage 2 (k_stage2): grid-stride over the buffer: Q = 8P, odd-multiple table, wNAF(5) scalar
 *            multiplication by k = 8x mod L (same digits for every thread: no divergence),
 *            compression (one inversion), SHA-512 -> beta; counters with >= k trailing zero bits
 *            are returned (the host recomputes and checks each one).
 * License: Apache-2.0.
 */
#define PXGPU_BUILD
#include "px_gpu.h"
#include <cuda_runtime.h>
#include <stdio.h>
#include <string.h>

#ifndef PX_TPB1
#define PX_TPB1 256
#endif
#ifndef PX_TPB2
#define PX_TPB2 128
#endif
#ifndef PX_MINB2
#define PX_MINB2 1
#endif

__constant__ px_job c_job;
__constant__ px_key c_key;

struct px_item {
	uint64_t counter;
	fe x, y;
};

struct px_ctx {
	int dev;
	uint32_t max_items;
	int tpb1, tpb2, blocks2;
	px_item *d_items;
	uint32_t *d_count;        /* [0] = items, [1] = found */
	uint64_t *d_found;
	uint8_t *d_valid, *d_betas;
	uint32_t dbg_cap;
	cudaEvent_t e0, e1;
};

#define PX_MASK56 0x00ffffffffffffffULL

__global__ void __launch_bounds__(PX_TPB1) k_stage1(uint64_t base, uint32_t n, px_item *items, uint32_t *count)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint64_t c = (base + idx) & PX_MASK56;
	fe x, y;
	bool ok = false;
	if (idx < n) ok = px_stage1(c_job, c, x, y);
	unsigned mask = __ballot_sync(0xffffffffu, ok);
	if (mask == 0) return;
	int lane = threadIdx.x & 31;
	int leader = __ffs(mask) - 1;
	uint32_t pos = 0;
	if (lane == leader) pos = atomicAdd(&count[0], (uint32_t)__popc(mask));
	pos = __shfl_sync(0xffffffffu, pos, leader);
	if (ok) {
		uint32_t my = pos + (uint32_t)__popc(mask & ((1u << lane) - 1u));
		px_item &it = items[my];
		it.counter = c;
		it.x = x;
		it.y = y;
	}
}

__global__ void __launch_bounds__(PX_TPB2, PX_MINB2) k_stage2(const px_item *items, uint32_t *count, uint64_t *found, int max_found)
{
	uint32_t n = count[0];
	uint32_t k = c_job.k;
	uint64_t kmask = k >= 64 ? ~0ULL : ((1ULL << k) - 1ULL);
	for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x; i < n; i += gridDim.x * blockDim.x) {
		fe x = items[i].x, y = items[i].y;
		uint64_t beta[8];
		px_stage2(c_key, x, y, beta);
		if ((beta[7] & kmask) == 0 && (k <= 64 || (beta[6] & ((1ULL << (k - 64)) - 1ULL)) == 0)) {
			uint32_t s = atomicAdd(&count[1], 1u);
			if ((int)s < max_found) found[s] = items[i].counter;
		}
	}
}

__global__ void k_debug(uint64_t base, uint32_t n, uint8_t *valid, uint8_t *betas)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	if (idx >= n) return;
	uint64_t c = (base + idx) & PX_MASK56;
	fe x, y;
	bool ok = px_stage1(c_job, c, x, y);
	valid[idx] = ok ? 1 : 0;
	uint64_t beta[8];
	if (ok) px_stage2(c_key, x, y, beta);
	else for (int i = 0; i < 8; i++) beta[i] = 0;
	px_beta_bytes(betas + 64ull * idx, beta);
}

/* ------------------------------------------------------------------ API */

PX_API int px_device_count(void)
{
	int n = 0;
	cudaError_t e = cudaGetDeviceCount(&n);
	return e == cudaSuccess ? n : -(int)e;
}

PX_API int px_device_name(int dev, char *buf, int len)
{
	cudaDeviceProp p;
	cudaError_t e = cudaGetDeviceProperties(&p, dev);
	if (e != cudaSuccess) { snprintf(buf, len, "?"); return (int)e; }
	snprintf(buf, len, "%s (bus %02x:%02x, %d SM, cc %d.%d)", p.name, p.pciBusID, p.pciDeviceID, p.multiProcessorCount, p.major, p.minor);
	return 0;
}

PX_API const char *px_error_string(int code) { return cudaGetErrorString((cudaError_t)code); }

PX_API void *px_create(int dev, uint32_t max_items, int tpb1, int tpb2, int blocks2, char *err, int errlen)
{
	cudaError_t e;
	if ((e = cudaSetDevice(dev)) != cudaSuccess) { snprintf(err, errlen, "cudaSetDevice(%d): %s", dev, cudaGetErrorString(e)); return nullptr; }
	cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
	px_ctx *c = new px_ctx;
	memset(c, 0, sizeof(*c));
	c->dev = dev;
	c->max_items = max_items;
	c->tpb1 = tpb1 > 0 ? tpb1 : PX_TPB1;
	c->tpb2 = tpb2 > 0 ? tpb2 : PX_TPB2;
	if (c->tpb1 > PX_TPB1) c->tpb1 = PX_TPB1;
	if (c->tpb2 > PX_TPB2) c->tpb2 = PX_TPB2;
	cudaDeviceProp p;
	cudaGetDeviceProperties(&p, dev);
	if (blocks2 <= 0) {
		int per = 0;
		cudaOccupancyMaxActiveBlocksPerMultiprocessor(&per, k_stage2, c->tpb2, 0);
		if (per < 1) per = 1;
		blocks2 = p.multiProcessorCount * per;
	}
	c->blocks2 = blocks2;
	if ((e = cudaMalloc(&c->d_items, sizeof(px_item) * (size_t)max_items)) != cudaSuccess ||
	    (e = cudaMalloc(&c->d_count, 2 * sizeof(uint32_t))) != cudaSuccess ||
	    (e = cudaMalloc(&c->d_found, PX_MAX_FOUND * sizeof(uint64_t))) != cudaSuccess) {
		snprintf(err, errlen, "cudaMalloc: %s", cudaGetErrorString(e));
		px_destroy(c);
		return nullptr;
	}
	cudaEventCreate(&c->e0);
	cudaEventCreate(&c->e1);
	return c;
}

PX_API void px_destroy(void *ctx)
{
	px_ctx *c = (px_ctx *)ctx;
	if (!c) return;
	cudaSetDevice(c->dev);
	if (c->d_items) cudaFree(c->d_items);
	if (c->d_count) cudaFree(c->d_count);
	if (c->d_found) cudaFree(c->d_found);
	if (c->d_valid) cudaFree(c->d_valid);
	if (c->d_betas) cudaFree(c->d_betas);
	if (c->e0) cudaEventDestroy(c->e0);
	if (c->e1) cudaEventDestroy(c->e1);
	delete c;
}

PX_API int px_set_key(void *ctx, const px_key *key)
{
	px_ctx *c = (px_ctx *)ctx;
	cudaSetDevice(c->dev);
	return (int)cudaMemcpyToSymbol(c_key, key, sizeof(px_key));
}

PX_API int px_set_job(void *ctx, const px_job *job)
{
	px_ctx *c = (px_ctx *)ctx;
	cudaSetDevice(c->dev);
	return (int)cudaMemcpyToSymbol(c_job, job, sizeof(px_job));
}

PX_API int px_scan(void *ctx, uint64_t base, uint32_t count, uint64_t *found, int max_found, int *nfound, uint32_t *nvalid, float *ms_gpu)
{
	px_ctx *c = (px_ctx *)ctx;
	cudaSetDevice(c->dev);
	if (count > c->max_items) count = c->max_items;
	if (max_found > PX_MAX_FOUND) max_found = PX_MAX_FOUND;
	cudaMemsetAsync(c->d_count, 0, 2 * sizeof(uint32_t));
	cudaEventRecord(c->e0);
	uint32_t blocks1 = (count + c->tpb1 - 1) / c->tpb1;
	k_stage1<<<blocks1, c->tpb1>>>(base, count, c->d_items, c->d_count);
	k_stage2<<<c->blocks2, c->tpb2>>>(c->d_items, c->d_count, c->d_found, max_found);
	cudaEventRecord(c->e1);
	uint32_t h[2] = {0, 0};
	cudaError_t e = cudaMemcpy(h, c->d_count, sizeof(h), cudaMemcpyDeviceToHost);
	if (e == cudaSuccess) e = cudaGetLastError();
	if (e != cudaSuccess) return (int)e;
	int nf = (int)h[1];
	int ncopy = nf < max_found ? nf : max_found;
	if (ncopy > 0) {
		e = cudaMemcpy(found, c->d_found, sizeof(uint64_t) * ncopy, cudaMemcpyDeviceToHost);
		if (e != cudaSuccess) return (int)e;
	}
	*nfound = nf;
	*nvalid = h[0];
	if (ms_gpu) { cudaEventSynchronize(c->e1); cudaEventElapsedTime(ms_gpu, c->e0, c->e1); }
	return 0;
}

PX_API int px_debug(void *ctx, uint64_t base, uint32_t count, uint8_t *valid, uint8_t *betas)
{
	px_ctx *c = (px_ctx *)ctx;
	cudaSetDevice(c->dev);
	cudaError_t e;
	if (count > c->dbg_cap) {
		if (c->d_valid) cudaFree(c->d_valid);
		if (c->d_betas) cudaFree(c->d_betas);
		c->d_valid = nullptr; c->d_betas = nullptr; c->dbg_cap = 0;
		if ((e = cudaMalloc(&c->d_valid, count)) != cudaSuccess) return (int)e;
		if ((e = cudaMalloc(&c->d_betas, 64ull * count)) != cudaSuccess) return (int)e;
		c->dbg_cap = count;
	}
	k_debug<<<(count + 127) / 128, 128>>>(base, count, c->d_valid, c->d_betas);
	if ((e = cudaGetLastError()) != cudaSuccess) return (int)e;
	if ((e = cudaMemcpy(valid, c->d_valid, count, cudaMemcpyDeviceToHost)) != cudaSuccess) return (int)e;
	if ((e = cudaMemcpy(betas, c->d_betas, 64ull * count, cudaMemcpyDeviceToHost)) != cudaSuccess) return (int)e;
	return 0;
}

PX_API int px_kernel_info(void *ctx, int *regs1, int *local1, int *regs2, int *local2)
{
	(void)ctx;
	cudaFuncAttributes a;
	if (cudaFuncGetAttributes(&a, k_stage1) == cudaSuccess) { *regs1 = a.numRegs; *local1 = (int)a.localSizeBytes; }
	if (cudaFuncGetAttributes(&a, k_stage2) == cudaSuccess) { *regs2 = a.numRegs; *local2 = (int)a.localSizeBytes; }
	return 0;
}
