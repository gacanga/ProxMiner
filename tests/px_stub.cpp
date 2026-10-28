/**
 * ProxMiner - CPU stand-in for pxgpu.dll (same API, same px_core.h code), to test the host program
 * without a GPU (tests/fake_proxi.py plays the miner's job server).
 */
#include "px_gpu.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

struct stub_ctx { px_key key; px_job job; uint32_t max_items; };

PX_API int px_device_count(void) { return 1; }
PX_API int px_device_name(int dev, char *buf, int len) { snprintf(buf, len, "CPU stub %d", dev); return 0; }
PX_API const char *px_error_string(int) { return "stub error"; }
PX_API void *px_create(int, uint32_t max_items, int, int, int, char *, int) { stub_ctx *c = new stub_ctx; memset(c, 0, sizeof(*c)); c->max_items = max_items; return c; }
PX_API void px_destroy(void *ctx) { delete (stub_ctx *)ctx; }
PX_API int px_set_key(void *ctx, const px_key *key) { ((stub_ctx *)ctx)->key = *key; return 0; }
PX_API int px_set_job(void *ctx, const px_job *job) { ((stub_ctx *)ctx)->job = *job; return 0; }
PX_API int px_scan(void *ctx, uint64_t base, uint32_t count, uint64_t *found, int max_found, int *nfound, uint32_t *nvalid, float *ms_gpu)
{
	stub_ctx *c = (stub_ctx *)ctx;
	auto t0 = std::chrono::steady_clock::now();
	int nf = 0; uint32_t nv = 0;
	for (uint32_t i = 0; i < count; i++) {
		uint64_t ctr = (base + i) & 0x00ffffffffffffffULL;
		fe x, y;
		if (!px_stage1(c->job, ctr, x, y)) continue;
		nv++;
		uint64_t b[8];
		px_stage2(c->key, x, y, b);
		if ((uint32_t)px_trailing_zeros(b) >= c->job.k) { if (nf < max_found) found[nf] = ctr; nf++; }
	}
	*nfound = nf; *nvalid = nv;
	if (ms_gpu) *ms_gpu = (float)std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
	return 0;
}
PX_API int px_debug(void *ctx, uint64_t base, uint32_t count, uint8_t *valid, uint8_t *betas)
{
	stub_ctx *c = (stub_ctx *)ctx;
	for (uint32_t i = 0; i < count; i++) {
		fe x, y; uint64_t b[8] = {0};
		bool ok = px_stage1(c->job, (base + i) & 0x00ffffffffffffffULL, x, y);
		valid[i] = ok;
		if (ok) px_stage2(c->key, x, y, b);
		px_beta_bytes(betas + 64ull * i, b);
	}
	return 0;
}
PX_API int px_kernel_info(void *, int *a, int *b, int *c, int *d) { *a = *b = *c = *d = 0; return 0; }
