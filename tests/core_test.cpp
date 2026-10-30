/**
 * ProxMiner - host test of gpu/px_core.h + gpu/px_host.h (the same code the GPU runs).
 *   1. RFC 9381 B.4 vectors: public key, H and beta.
 *   2. Fast path (midstate + ctr = 0 only) against the generic reference on random jobs:
 *      decode success must match ctr == 0 of the reference, beta must be identical.
 *   3. Writes cases to stdout (or the file in argv[1]) for tests/ref_vrf.py --check.
 * Build: g++ -O2 -std=gnu++17 -Igpu tests/core_test.cpp -o core_test
 */
#include "px_host.h"
#include <cstdio>
#include <cstdlib>
#include <random>

static int fails = 0;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

int main(int argc, char **argv)
{
	struct V { const char *sk, *pk, *alpha, *h, *beta; } vec[3] = {
		{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
		 "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
		 "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"},
		{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
		 "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
		 "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"},
		{"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
		 "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
		 "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"},
	};
	for (auto &v : vec) {
		std::vector<uint8_t> sk, alpha;
		px_unhex(v.sk, sk); px_unhex(v.alpha, alpha);
		px_secret sec; px_secret_from_seed(sec, sk.data());
		CHECK(px_hex(sec.pk, 32) == v.pk, "pk %s", px_hex(sec.pk, 32).c_str());
		uint8_t beta[64], H[32];
		int ctr = px_reference_beta(beta, sec, alpha.data(), alpha.size(), H);
		CHECK(ctr >= 0, "no point");
		CHECK(px_hex(H, 32) == v.h, "H %s", px_hex(H, 32).c_str());
		CHECK(px_hex(beta, 64) == v.beta, "beta %s", px_hex(beta, 64).c_str());
	}
	printf("RFC vectors: %s\n", fails ? "FAILED" : "OK");

	FILE *out = argc > 1 ? fopen(argv[1], "w") : nullptr;
	std::mt19937_64 rng(12345);
	int njobs = 6, per = 64, valid = 0, invalid = 0;
	for (int j = 0; j < njobs; j++) {
		uint8_t seed[32], prefix[37];
		for (auto &b : seed) b = (uint8_t)rng();
		for (auto &b : prefix) b = (uint8_t)rng();
		px_secret sec; px_secret_from_seed(sec, seed);
		uint8_t n0 = (uint8_t)rng();
		px_job job; px_make_job(job, sec.pk, prefix, 37, n0, 0);
		uint64_t base = rng() & 0x00ffffffffffffffULL;
		for (int i = 0; i < per; i++) {
			uint64_t c = (base + (uint64_t)i * 0x1000193ULL) & 0x00ffffffffffffffULL;
			uint8_t alpha[45];
			memcpy(alpha, prefix, 37);
			px_nonce_bytes(alpha + 37, n0, c);
			uint8_t rbeta[64];
			int ctr = px_reference_beta(rbeta, sec, alpha, 45);
			fe x, y;
			bool ok = px_stage1(job, c, x, y);
			CHECK(ok == (ctr == 0), "job %d nonce %d: fast decode %d, reference ctr %d", j, i, (int)ok, ctr);
			if (ok) {
				uint64_t bw[8]; uint8_t fbeta[64];
				px_stage2(sec.key, x, y, bw);
				px_beta_bytes(fbeta, bw);
				CHECK(memcmp(fbeta, rbeta, 64) == 0, "job %d nonce %d: beta differs", j, i);
				CHECK(px_trailing_zeros(bw) >= 0, "tz");
				valid++;
			} else invalid++;
			if (out) fprintf(out, "%s %s %s %d %s\n", px_hex(seed, 32).c_str(), px_hex(alpha, 45).c_str(),
				px_hex(sec.pk, 32).c_str(), ctr, px_hex(rbeta, 64).c_str());
		}
	}
	if (out) fclose(out);
	printf("fast path: %d valid, %d skipped (ctr 0 not a point): %s\n", valid, invalid, fails ? "FAILED" : "OK");

	/* Jacobi symbol against Euler's criterion w^((p-1)/2), and the batched stage 2 */
	{
		std::mt19937_64 r2(777);
		int bad = 0, sq = 0, n = 20000;
		for (int it = 0; it < n; it++) {
			fe w;
			for (int i = 0; i < 8; i++) w.v[i] = (uint32_t)r2();
			if (it == 0) fe_set_small(w, 0);
			if (it == 1) fe_set_small(w, 1);
			if (it == 2) { fe_set_small(w, 0); fe one; fe_set_small(one, 1); fe_sub(w, w, one); }
			fe_canon(w, w);
			/* e = (p-1)/2 = 2^254 - 10 : square-and-multiply over its bits, high to low */
			fe acc; fe_set_small(acc, 1);
			for (int b = 253; b >= 0; b--) {
				fe_sq(acc, acc);
				/* bits of 2^254 - 10 = 0x3fff...fff6 : all ones except bit 0 and bit 3 */
				bool bit = !(b == 0 || b == 3);
				if (bit) fe_mul(acc, acc, w);
			}
			fe_canon(acc, acc);
			int euler;
			fe one; fe_set_small(one, 1);
			uint32_t z = 0, o = 0;
			for (int i = 0; i < 8; i++) { z |= acc.v[i]; o |= acc.v[i] ^ one.v[i]; }
			euler = z == 0 ? 0 : (o == 0 ? 1 : -1);
			int j = fe_jacobi(w);
			if (j != euler) { if (bad < 3) printf("jacobi %d euler %d\n", j, euler); bad++; }
			sq += j == 1;
		}
		CHECK(bad == 0, "jacobi: %d differences", bad);
		printf("jacobi: %d values, %d squares, %d differences\n", n, sq, bad);
		/* batch */
		uint8_t seed[32]; for (auto &b : seed) b = (uint8_t)r2();
		px_secret sec; px_secret_from_seed(sec, seed);
		uint8_t prefix[37]; for (auto &b : prefix) b = (uint8_t)r2();
		px_job job; px_make_job(job, sec.pk, prefix, 37, 7, 0);
		fe xs[PX_BATCH], ys[PX_BATCH];
		int got = 0, bb = 0;
		for (uint64_t c = 1000; got < PX_BATCH; c++) { fe x, y; if (px_stage1(job, c, x, y)) { xs[got] = x; ys[got] = y; got++; } }
		for (int cnt = 1; cnt <= PX_BATCH; cnt++) {
			uint64_t bw[PX_BATCH][8];
			px_stage2_batch(sec.key, xs, ys, cnt, bw);
			for (int i = 0; i < cnt; i++) { uint64_t one[8]; px_stage2(sec.key, xs[i], ys[i], one); bb += memcmp(one, bw[i], sizeof one) != 0; }
		}
		CHECK(bb == 0, "batch: %d differences", bb);
		printf("batch stage 2: cnt 1..%d, %d differences\n", PX_BATCH, bb);
	}
	printf(fails ? "CORE TEST FAILED (%d)\n" : "CORE TEST ALL OK\n", fails);
	return fails ? 1 : 0;
}
