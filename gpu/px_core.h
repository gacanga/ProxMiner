/**
 * ProxMiner - core of the Proxima mining work function, shared by the host (C++) and the GPU (CUDA):
 *   ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) output beta, stopped after Gamma:
 *     H     = encode_to_curve_TAI(pk, alpha)        alpha = alpha_prefix(37) || nonce(8)
 *     beta  = SHA-512(0x03 || 0x03 || encode(8 * x * H) || 0x00)
 *   computed as R = k * Q with Q = 8 * P (P = decoded hash point) and k = 8 * x mod L.
 *
 * Field GF(2^255 - 19): 8 x 32-bit little-endian limbs, values kept below 2^256 (not canonical).
 * Points: twisted Edwards a = -1, ref10 representations (p2, p3, p1p1, cached).
 *
 * The GPU only uses nonces whose first try (ctr = 0) decodes to a point: their beta is exactly the
 * one the miner computes.  Nonces whose ctr = 0 hash is not a point are skipped (never submitted).
 *
 * License: Apache-2.0.  No developer fee.
 */
#pragma once
#include <stdint.h>

#if defined(__CUDACC__)
#  define PXF __host__ __device__ __forceinline__
#  define PXC __host__ __device__
#else
#  define PXF static inline
#  define PXC static inline
#endif

/* fe_mul / fe_sq: inlined by default; -DPX_FE_NOINLINE makes them real calls on the GPU
   (much smaller code: the whole scalar multiplication then fits the instruction cache) */
#if defined(__CUDACC__) && defined(PX_FE_NOINLINE)
#  define PX_FEFN __host__ __device__ __noinline__
#else
#  define PX_FEFN PXF
#endif

/* ===================================================================== field GF(2^255-19) */

typedef struct { uint32_t v[8]; } fe;

PXF void fe_copy(fe &r, const fe &a) { for (int i = 0; i < 8; i++) r.v[i] = a.v[i]; }
PXF void fe_set_small(fe &r, uint32_t x) { r.v[0] = x; for (int i = 1; i < 8; i++) r.v[i] = 0; }

/* r = a + b */
PXF void fe_add(fe &r, const fe &a, const fe &b)
{
	uint64_t c = 0;
	for (int i = 0; i < 8; i++) { c += (uint64_t)a.v[i] + b.v[i]; r.v[i] = (uint32_t)c; c >>= 32; }
	/* 2^256 = 38 (mod p): fold the carry twice (the second fold cannot carry again) */
	uint64_t f = c * 38;
	for (int i = 0; i < 8; i++) { f += r.v[i]; r.v[i] = (uint32_t)f; f >>= 32; }
	r.v[0] += (uint32_t)f * 38;
}

/* r = a - b */
PXF void fe_sub(fe &r, const fe &a, const fe &b)
{
	int64_t t = 0;
	for (int i = 0; i < 8; i++) { t += (int64_t)a.v[i] - b.v[i]; r.v[i] = (uint32_t)t; t >>= 32; }
	/* borrow -> r + 2^256 was stored: subtract 38, twice at most */
	uint32_t bw = (uint32_t)(t & 1);
	t = -(int64_t)(bw * 38);
	for (int i = 0; i < 8; i++) { t += r.v[i]; r.v[i] = (uint32_t)t; t >>= 32; }
	bw = (uint32_t)(t & 1);
	r.v[0] -= bw * 38;
}

/* 512-bit t[16] -> r = t mod p (below 2^256) */
PXF void fe_reduce512(fe &r, const uint32_t t[16])
{
	uint64_t c = 0;
	for (int i = 0; i < 8; i++) { c += (uint64_t)t[8 + i] * 38 + t[i]; r.v[i] = (uint32_t)c; c >>= 32; }
	c = c * 38 + r.v[0]; r.v[0] = (uint32_t)c; c >>= 32;
	for (int i = 1; i < 8; i++) { c += r.v[i]; r.v[i] = (uint32_t)c; c >>= 32; }
	r.v[0] += (uint32_t)c * 38;
}

/* r = a * b */
PX_FEFN void fe_mul(fe &r, const fe &a, const fe &b)
{
	uint32_t t[16];
	{
		uint64_t c = 0;
		for (int j = 0; j < 8; j++) { c += (uint64_t)a.v[0] * b.v[j]; t[j] = (uint32_t)c; c >>= 32; }
		t[8] = (uint32_t)c;
	}
	for (int i = 1; i < 8; i++) {
		uint64_t c = 0;
		for (int j = 0; j < 8; j++) { c += (uint64_t)a.v[i] * b.v[j] + t[i + j]; t[i + j] = (uint32_t)c; c >>= 32; }
		t[i + 8] = (uint32_t)c;
	}
	fe_reduce512(r, t);
}

/* r = a^2 */
PX_FEFN void fe_sq(fe &r, const fe &a)
{
	uint32_t t[16];
	for (int i = 0; i < 16; i++) t[i] = 0;
	/* cross products a[i]*a[j], i < j */
	for (int i = 0; i < 7; i++) {
		uint64_t c = 0;
		for (int j = i + 1; j < 8; j++) { c += (uint64_t)a.v[i] * a.v[j] + t[i + j]; t[i + j] = (uint32_t)c; c >>= 32; }
		t[i + 8] = (uint32_t)c;
	}
	/* double */
	uint32_t top = 0;
	for (int i = 0; i < 16; i++) { uint32_t n = t[i] >> 31; t[i] = (t[i] << 1) | top; top = n; }
	/* add the squares */
	uint64_t c = 0;
	for (int i = 0; i < 8; i++) {
		uint64_t s = (uint64_t)a.v[i] * a.v[i];
		c += (uint64_t)t[2 * i] + (uint32_t)s; t[2 * i] = (uint32_t)c; c >>= 32;
		c += (uint64_t)t[2 * i + 1] + (uint32_t)(s >> 32); t[2 * i + 1] = (uint32_t)c; c >>= 32;
	}
	fe_reduce512(r, t);
}

/* r = a^(2^n) */
PXF void fe_sqn(fe &r, const fe &a, int n)
{
	fe_sq(r, a);
#if defined(__CUDA_ARCH__)
#pragma unroll 1
#endif
	for (int i = 1; i < n; i++) fe_sq(r, r);
}

/* canonical value in [0, p) */
PXF void fe_canon(fe &r, const fe &a)
{
	/* fold bit 255: a = lo255 + 19 * top */
	uint32_t top = a.v[7] >> 31;
	uint64_t c = (uint64_t)top * 19;
	for (int i = 0; i < 8; i++) { c += (i == 7) ? (a.v[7] & 0x7fffffffu) : a.v[i]; r.v[i] = (uint32_t)c; c >>= 32; }
	/* now r < 2^255 + 19; subtract p if r >= p  <=>  r + 19 >= 2^255 */
	fe s; c = 19;
	for (int i = 0; i < 8; i++) { c += r.v[i]; s.v[i] = (uint32_t)c; c >>= 32; }
	uint32_t ge = s.v[7] >> 31;
	s.v[7] &= 0x7fffffffu;
	uint32_t m = 0u - ge;
	for (int i = 0; i < 8; i++) r.v[i] = (s.v[i] & m) | (r.v[i] & ~m);
}

PXF bool fe_equal(const fe &a, const fe &b)
{
	fe x, y; fe_canon(x, a); fe_canon(y, b);
	uint32_t d = 0;
	for (int i = 0; i < 8; i++) d |= x.v[i] ^ y.v[i];
	return d == 0;
}

PXF void fe_neg(fe &r, const fe &a) { fe z; fe_set_small(z, 0); fe_sub(r, z, a); }

/* z^((p-5)/8) = z^(2^252 - 3) (ref10 chain) */
PXF void fe_pow22523(fe &out, const fe &z)
{
	fe t0, t1, t2;
	fe_sq(t0, z);
	fe_sqn(t1, t0, 2);
	fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);
	fe_mul(t0, t1, t0);
	fe_sqn(t1, t0, 5);
	fe_mul(t0, t1, t0);
	fe_sqn(t1, t0, 10);
	fe_mul(t1, t1, t0);
	fe_sqn(t2, t1, 20);
	fe_mul(t1, t2, t1);
	fe_sqn(t1, t1, 10);
	fe_mul(t0, t1, t0);
	fe_sqn(t1, t0, 50);
	fe_mul(t1, t1, t0);
	fe_sqn(t2, t1, 100);
	fe_mul(t1, t2, t1);
	fe_sqn(t1, t1, 50);
	fe_mul(t0, t1, t0);
	fe_sqn(t0, t0, 2);
	fe_mul(out, t0, z);
}

/* z^(p-2) = 1/z (ref10 chain) */
PXF void fe_invert(fe &out, const fe &z)
{
	fe t0, t1, t2, t3;
	fe_sq(t0, z);
	fe_sqn(t1, t0, 2);
	fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t2, t0);
	fe_mul(t1, t1, t2);
	fe_sqn(t2, t1, 5);
	fe_mul(t1, t2, t1);
	fe_sqn(t2, t1, 10);
	fe_mul(t2, t2, t1);
	fe_sqn(t3, t2, 20);
	fe_mul(t2, t3, t2);
	fe_sqn(t2, t2, 10);
	fe_mul(t1, t2, t1);
	fe_sqn(t2, t1, 50);
	fe_mul(t2, t2, t1);
	fe_sqn(t3, t2, 100);
	fe_mul(t2, t3, t2);
	fe_sqn(t2, t2, 50);
	fe_mul(t1, t2, t1);
	fe_sqn(t1, t1, 5);
	fe_mul(out, t1, t0);
}

/* curve constants (little-endian 32-bit limbs) */
#define PX_FE_D      {{0x135978a3u, 0x75eb4dcau, 0x4141d8abu, 0x00700a4du, 0x7779e898u, 0x8cc74079u, 0x2b6ffe73u, 0x52036ceeu}}
#define PX_FE_D2     {{0x26b2f159u, 0xebd69b94u, 0x8283b156u, 0x00e0149au, 0xeef3d130u, 0x198e80f2u, 0x56dffce7u, 0x2406d9dcu}}
#define PX_FE_SQRTM1 {{0x4a0ea0b0u, 0xc4ee1b27u, 0xad2fe478u, 0x2f431806u, 0x3dfbd7a7u, 0x2b4d0099u, 0x4fc1df0bu, 0x2b832480u}}

/* ===================================================================== points */

typedef struct { fe X, Y, Z; } ge_p2;
typedef struct { fe X, Y, Z, T; } ge_p3;
typedef struct { fe X, Y, Z, T; } ge_p1p1;
typedef struct { fe YplusX, YminusX, Z, T2d; } ge_cached;

PXF void ge_p1p1_to_p2(ge_p2 &r, const ge_p1p1 &p)
{
	fe_mul(r.X, p.X, p.T);
	fe_mul(r.Y, p.Y, p.Z);
	fe_mul(r.Z, p.Z, p.T);
}

PXF void ge_p1p1_to_p3(ge_p3 &r, const ge_p1p1 &p)
{
	fe_mul(r.X, p.X, p.T);
	fe_mul(r.Y, p.Y, p.Z);
	fe_mul(r.Z, p.Z, p.T);
	fe_mul(r.T, p.X, p.Y);
}

/* r = 2 * p  (dbl-2008-hwcd, a = -1) */
PXF void ge_p2_dbl(ge_p1p1 &r, const ge_p2 &p)
{
	fe t0;
	fe_sq(r.X, p.X);
	fe_sq(r.Z, p.Y);
	fe_sq(r.T, p.Z);
	fe_add(r.T, r.T, r.T);
	fe_add(r.Y, p.X, p.Y);
	fe_sq(t0, r.Y);
	fe_add(r.Y, r.Z, r.X);
	fe_sub(r.Z, r.Z, r.X);
	fe_sub(r.X, t0, r.Y);
	fe_sub(r.T, r.T, r.Z);
}

PXF void ge_p3_to_cached(ge_cached &r, const ge_p3 &p)
{
	const fe d2 = PX_FE_D2;
	fe_add(r.YplusX, p.Y, p.X);
	fe_sub(r.YminusX, p.Y, p.X);
	fe_copy(r.Z, p.Z);
	fe_mul(r.T2d, p.T, d2);
}

/* r = p + q */
PXF void ge_add(ge_p1p1 &r, const ge_p3 &p, const ge_cached &q)
{
	fe t0;
	fe_add(r.X, p.Y, p.X);
	fe_sub(r.Y, p.Y, p.X);
	fe_mul(r.Z, r.X, q.YplusX);
	fe_mul(r.Y, r.Y, q.YminusX);
	fe_mul(r.T, q.T2d, p.T);
	fe_mul(r.X, p.Z, q.Z);
	fe_add(t0, r.X, r.X);
	fe_sub(r.X, r.Z, r.Y);
	fe_add(r.Y, r.Z, r.Y);
	fe_add(r.Z, t0, r.T);
	fe_sub(r.T, t0, r.T);
}

/* r = p - q */
PXF void ge_sub(ge_p1p1 &r, const ge_p3 &p, const ge_cached &q)
{
	fe t0;
	fe_add(r.X, p.Y, p.X);
	fe_sub(r.Y, p.Y, p.X);
	fe_mul(r.Z, r.X, q.YminusX);
	fe_mul(r.Y, r.Y, q.YplusX);
	fe_mul(r.T, q.T2d, p.T);
	fe_mul(r.X, p.Z, q.Z);
	fe_add(t0, r.X, r.X);
	fe_sub(r.X, r.Z, r.Y);
	fe_add(r.Y, r.Z, r.Y);
	fe_sub(r.Z, t0, r.T);
	fe_add(r.T, t0, r.T);
}

/*
 * Point decoding exactly as filippo.io/edwards25519 Point.SetBytes (used by the miner):
 * y = 255 low bits (a non-canonical y >= p is accepted and reduced), x = sqrt(u / v) with
 * u = y^2 - 1, v = d y^2 + 1; the root with the parity given by bit 255.  Returns false when
 * u / v is not a square.  y in: the 255 low bits as limbs; sign: bit 255.
 */
PXF bool ge_decode_xy(fe &x, const fe &y, uint32_t sign)
{
	const fe d = PX_FE_D;
	const fe sqrtm1 = PX_FE_SQRTM1;
	fe one, u, v, v3, v7, r, chk, t;
	fe_set_small(one, 1);
	fe_sq(u, y);
	fe_mul(v, u, d);
	fe_sub(u, u, one);
	fe_add(v, v, one);
	fe_sq(v3, v); fe_mul(v3, v3, v);            /* v^3 */
	fe_sq(v7, v3); fe_mul(v7, v7, v);           /* v^7 */
	fe_mul(t, u, v7);
	fe_pow22523(t, t);                           /* (u v^7)^((p-5)/8) */
	fe_mul(r, u, v3);
	fe_mul(r, r, t);                             /* r = u v^3 (u v^7)^((p-5)/8) */
	fe_sq(chk, r);
	fe_mul(chk, chk, v);                         /* v r^2 */
	fe cu, cn, cc, un;
	fe_canon(cu, u);
	fe_neg(un, u); fe_canon(cn, un);
	fe_canon(cc, chk);
	uint32_t e1 = 0, e2 = 0;
	for (int i = 0; i < 8; i++) { e1 |= cc.v[i] ^ cu.v[i]; e2 |= cc.v[i] ^ cn.v[i]; }
	bool correct = e1 == 0, flipped = e2 == 0;
	if (!correct && !flipped) return false;
	if (!correct) fe_mul(r, r, sqrtm1);
	fe_canon(r, r);
	if ((r.v[0] & 1u) != sign) { fe_neg(r, r); fe_canon(r, r); }
	fe_copy(x, r);
	return true;
}

/* 32-byte encoding of p (y little-endian, bit 255 = parity of x) as 8 little-endian limbs */
PXF void ge_encode_p2(uint32_t out[8], const ge_p2 &p)
{
	fe zi, x, y;
	fe_invert(zi, p.Z);
	fe_mul(x, p.X, zi);
	fe_mul(y, p.Y, zi);
	fe_canon(x, x);
	fe_canon(y, y);
	for (int i = 0; i < 8; i++) out[i] = y.v[i];
	out[7] |= (x.v[0] & 1u) << 31;
}

/* ===================================================================== SHA-512 */

#define PX_ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#if defined(__CUDACC__)
__host__ __device__
#endif
static inline uint64_t px_sha512_k(int i)
{
	/* switch so that it is usable from host and device without a table in constant memory */
	switch (i) {
	case 0: return 0x428a2f98d728ae22ULL; case 1: return 0x7137449123ef65cdULL; case 2: return 0xb5c0fbcfec4d3b2fULL; case 3: return 0xe9b5dba58189dbbcULL;
	case 4: return 0x3956c25bf348b538ULL; case 5: return 0x59f111f1b605d019ULL; case 6: return 0x923f82a4af194f9bULL; case 7: return 0xab1c5ed5da6d8118ULL;
	case 8: return 0xd807aa98a3030242ULL; case 9: return 0x12835b0145706fbeULL; case 10: return 0x243185be4ee4b28cULL; case 11: return 0x550c7dc3d5ffb4e2ULL;
	case 12: return 0x72be5d74f27b896fULL; case 13: return 0x80deb1fe3b1696b1ULL; case 14: return 0x9bdc06a725c71235ULL; case 15: return 0xc19bf174cf692694ULL;
	case 16: return 0xe49b69c19ef14ad2ULL; case 17: return 0xefbe4786384f25e3ULL; case 18: return 0x0fc19dc68b8cd5b5ULL; case 19: return 0x240ca1cc77ac9c65ULL;
	case 20: return 0x2de92c6f592b0275ULL; case 21: return 0x4a7484aa6ea6e483ULL; case 22: return 0x5cb0a9dcbd41fbd4ULL; case 23: return 0x76f988da831153b5ULL;
	case 24: return 0x983e5152ee66dfabULL; case 25: return 0xa831c66d2db43210ULL; case 26: return 0xb00327c898fb213fULL; case 27: return 0xbf597fc7beef0ee4ULL;
	case 28: return 0xc6e00bf33da88fc2ULL; case 29: return 0xd5a79147930aa725ULL; case 30: return 0x06ca6351e003826fULL; case 31: return 0x142929670a0e6e70ULL;
	case 32: return 0x27b70a8546d22ffcULL; case 33: return 0x2e1b21385c26c926ULL; case 34: return 0x4d2c6dfc5ac42aedULL; case 35: return 0x53380d139d95b3dfULL;
	case 36: return 0x650a73548baf63deULL; case 37: return 0x766a0abb3c77b2a8ULL; case 38: return 0x81c2c92e47edaee6ULL; case 39: return 0x92722c851482353bULL;
	case 40: return 0xa2bfe8a14cf10364ULL; case 41: return 0xa81a664bbc423001ULL; case 42: return 0xc24b8b70d0f89791ULL; case 43: return 0xc76c51a30654be30ULL;
	case 44: return 0xd192e819d6ef5218ULL; case 45: return 0xd69906245565a910ULL; case 46: return 0xf40e35855771202aULL; case 47: return 0x106aa07032bbd1b8ULL;
	case 48: return 0x19a4c116b8d2d0c8ULL; case 49: return 0x1e376c085141ab53ULL; case 50: return 0x2748774cdf8eeb99ULL; case 51: return 0x34b0bcb5e19b48a8ULL;
	case 52: return 0x391c0cb3c5c95a63ULL; case 53: return 0x4ed8aa4ae3418acbULL; case 54: return 0x5b9cca4f7763e373ULL; case 55: return 0x682e6ff3d6b2b8a3ULL;
	case 56: return 0x748f82ee5defb2fcULL; case 57: return 0x78a5636f43172f60ULL; case 58: return 0x84c87814a1f0ab72ULL; case 59: return 0x8cc702081a6439ecULL;
	case 60: return 0x90befffa23631e28ULL; case 61: return 0xa4506cebde82bde9ULL; case 62: return 0xbef9a3f7b2c67915ULL; case 63: return 0xc67178f2e372532bULL;
	case 64: return 0xca273eceea26619cULL; case 65: return 0xd186b8c721c0c207ULL; case 66: return 0xeada7dd6cde0eb1eULL; case 67: return 0xf57d4f7fee6ed178ULL;
	case 68: return 0x06f067aa72176fbaULL; case 69: return 0x0a637dc5a2c898a6ULL; case 70: return 0x113f9804bef90daeULL; case 71: return 0x1b710b35131c471bULL;
	case 72: return 0x28db77f523047d84ULL; case 73: return 0x32caab7b40c72493ULL; case 74: return 0x3c9ebe0a15c9bebcULL; case 75: return 0x431d67c49c100d4cULL;
	case 76: return 0x4cc5d4becb3e42b6ULL; case 77: return 0x597f299cfc657e2aULL; case 78: return 0x5fcb6fab3ad6faecULL; default: return 0x6c44198c4a475817ULL;
	}
}

#define PX_SHA512_IV0 0x6a09e667f3bcc908ULL
#define PX_SHA512_IV1 0xbb67ae8584caa73bULL
#define PX_SHA512_IV2 0x3c6ef372fe94f82bULL
#define PX_SHA512_IV3 0xa54ff53a5f1d36f1ULL
#define PX_SHA512_IV4 0x510e527fade682d1ULL
#define PX_SHA512_IV5 0x9b05688c2b3e6c1fULL
#define PX_SHA512_IV6 0x1f83d9abfb41bd6bULL
#define PX_SHA512_IV7 0x5be0cd19137e2179ULL

/*
 * SHA-512 compression rounds [from, 80) on the working state s[8] (a..h after `from` rounds),
 * message words w[16] (the 16 words of the block, as given; rounds >= 16 expand them in place).
 * The caller adds the chaining value afterwards.
 */
PXF void px_sha512_rounds(uint64_t s[8], uint64_t w[16], int from)
{
	uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
#if defined(__CUDA_ARCH__)
#pragma unroll
#endif
	for (int t = 0; t < 80; t++) {
		if (t < from) continue;
		uint64_t wt;
		if (t < 16) wt = w[t];
		else {
			uint64_t w2 = w[(t - 2) & 15], w15 = w[(t - 15) & 15];
			uint64_t s0 = PX_ROTR64(w15, 1) ^ PX_ROTR64(w15, 8) ^ (w15 >> 7);
			uint64_t s1 = PX_ROTR64(w2, 19) ^ PX_ROTR64(w2, 61) ^ (w2 >> 6);
			wt = w[t & 15] + s0 + w[(t - 7) & 15] + s1;
			w[t & 15] = wt;
		}
		uint64_t S1 = PX_ROTR64(e, 14) ^ PX_ROTR64(e, 18) ^ PX_ROTR64(e, 41);
		uint64_t ch = (e & f) ^ (~e & g);
		uint64_t t1 = h + S1 + ch + px_sha512_k(t) + wt;
		uint64_t S0 = PX_ROTR64(a, 28) ^ PX_ROTR64(a, 34) ^ PX_ROTR64(a, 39);
		uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
		uint64_t t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = f; s[6] = g; s[7] = h;
}

PXF void px_sha512_iv(uint64_t s[8])
{
	s[0] = PX_SHA512_IV0; s[1] = PX_SHA512_IV1; s[2] = PX_SHA512_IV2; s[3] = PX_SHA512_IV3;
	s[4] = PX_SHA512_IV4; s[5] = PX_SHA512_IV5; s[6] = PX_SHA512_IV6; s[7] = PX_SHA512_IV7;
}

PXF uint32_t px_bswap32(uint32_t x)
{
	return (x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) | (x << 24);
}

/* ===================================================================== the mining job */

/*
 * Message of the first hash-to-curve try (ctr = 0), 81 bytes, one SHA-512 block:
 *   0:03 1:01 2..33:pk 34..70:alpha_prefix 71:n0 72..78:nonce counter (56 bits, big-endian) 79:ctr=0 80:00
 * Words 0..8 do not depend on the counter: the host runs rounds 0..8 once per job (midstate).
 * Word 9 = counter << 8 (ctr = 0).  Words 10..15 are constant.
 * The nonce sent to the miner is n0 || counter (8 bytes, counter big-endian).
 */
#define PX_MID_ROUNDS 9

typedef struct {
	uint64_t mid[8];          /* working state a..h after rounds 0..8 */
	uint64_t w[16];           /* message words (w[9] is replaced by counter << 8) */
	uint32_t k;               /* required trailing zero bits */
	uint32_t pad;
} px_job;

typedef struct {
	int8_t digits[256];       /* wNAF(5) digits of 8x mod L, least significant first */
	int32_t ndigits;
} px_key;

#define PX_WNAF_W   5
#define PX_TABLE_N  8         /* odd multiples 1, 3, ..., 15 */

/* stage 1: nonce counter -> decoded point (x, y) of the ctr = 0 hash, or false */
PXF bool px_stage1(const px_job &job, uint64_t counter, fe &x, fe &y)
{
	uint64_t s[8], w[16];
	for (int i = 0; i < 8; i++) s[i] = job.mid[i];
	for (int i = 0; i < 16; i++) w[i] = job.w[i];
	w[9] = counter << 8;
	px_sha512_rounds(s, w, PX_MID_ROUNDS);
	uint64_t h0 = s[0] + PX_SHA512_IV0, h1 = s[1] + PX_SHA512_IV1, h2 = s[2] + PX_SHA512_IV2, h3 = s[3] + PX_SHA512_IV3;
	y.v[0] = px_bswap32((uint32_t)(h0 >> 32)); y.v[1] = px_bswap32((uint32_t)h0);
	y.v[2] = px_bswap32((uint32_t)(h1 >> 32)); y.v[3] = px_bswap32((uint32_t)h1);
	y.v[4] = px_bswap32((uint32_t)(h2 >> 32)); y.v[5] = px_bswap32((uint32_t)h2);
	y.v[6] = px_bswap32((uint32_t)(h3 >> 32)); y.v[7] = px_bswap32((uint32_t)h3);
	uint32_t sign = y.v[7] >> 31;
	y.v[7] &= 0x7fffffffu;
	return ge_decode_xy(x, y, sign);
}

/* 32-byte point encoding (limbs) -> SHA-512(03 03 enc 00): the 8 words of beta (big-endian words) */
PXF void px_beta_words(uint64_t out[8], const uint32_t enc[8])
{
	/* byte i of enc = (enc[i/4] >> 8*(i%4)) & 0xff */
	uint8_t m[40];
	m[0] = 3; m[1] = 3;
	for (int i = 0; i < 32; i++) m[2 + i] = (uint8_t)(enc[i >> 2] >> (8 * (i & 3)));
	m[34] = 0; m[35] = 0x80; m[36] = m[37] = m[38] = m[39] = 0;
	uint64_t w[16];
	for (int i = 0; i < 5; i++) {
		uint64_t x = 0;
		for (int j = 0; j < 8; j++) x = (x << 8) | m[8 * i + j];
		w[i] = x;
	}
	for (int i = 5; i < 15; i++) w[i] = 0;
	w[15] = 35 * 8;
	uint64_t s[8];
	px_sha512_iv(s);
	px_sha512_rounds(s, w, 0);
	out[0] = s[0] + PX_SHA512_IV0; out[1] = s[1] + PX_SHA512_IV1; out[2] = s[2] + PX_SHA512_IV2; out[3] = s[3] + PX_SHA512_IV3;
	out[4] = s[4] + PX_SHA512_IV4; out[5] = s[5] + PX_SHA512_IV5; out[6] = s[6] + PX_SHA512_IV6; out[7] = s[7] + PX_SHA512_IV7;
}

/* table of odd multiples of Q (cached form): tab[i] = (2i + 1) Q */
PXF void px_table(ge_cached tab[PX_TABLE_N], const ge_p3 &Q)
{
	ge_p1p1 t; ge_p2 q2; ge_p3 q3, cur; ge_cached c2;
	ge_p3_to_cached(tab[0], Q);
	q2.X = Q.X; q2.Y = Q.Y; q2.Z = Q.Z;
	ge_p2_dbl(t, q2);
	ge_p1p1_to_p3(q3, t);
	ge_p3_to_cached(c2, q3);
	cur = Q;
	for (int i = 1; i < PX_TABLE_N; i++) {
		ge_add(t, cur, c2);
		ge_p1p1_to_p3(cur, t);
		ge_p3_to_cached(tab[i], cur);
	}
}

/* stage 2: decoded point (x, y) -> R = k * 8 * P (projective) -> beta words */
PXF void px_stage2(const px_key &key, const fe &x, const fe &y, uint64_t beta[8])
{
	ge_p2 p2; ge_p1p1 t; ge_p3 Q;
	/* Q = 8 P */
	p2.X = x; p2.Y = y; fe_set_small(p2.Z, 1);
	ge_p2_dbl(t, p2); ge_p1p1_to_p2(p2, t);
	ge_p2_dbl(t, p2); ge_p1p1_to_p2(p2, t);
	ge_p2_dbl(t, p2); ge_p1p1_to_p3(Q, t);

	ge_cached tab[PX_TABLE_N];
	px_table(tab, Q);

	/* R = sum digits * 2^i * Q, most significant digit first (the top digit is always positive) */
	ge_p3 r3;
	int top = key.ndigits - 1;
	fe_set_small(r3.X, 0); fe_set_small(r3.Y, 1); fe_set_small(r3.Z, 1); fe_set_small(r3.T, 0);
	ge_add(t, r3, tab[(key.digits[top] - 1) >> 1]);
	for (int i = top - 1; i >= 0; i--) {
		ge_p1p1_to_p2(p2, t);
		ge_p2_dbl(t, p2);
		int dg = key.digits[i];
		if (dg > 0) { ge_p1p1_to_p3(r3, t); ge_add(t, r3, tab[(dg - 1) >> 1]); }
		else if (dg < 0) { ge_p1p1_to_p3(r3, t); ge_sub(t, r3, tab[(-dg - 1) >> 1]); }
	}
	ge_p1p1_to_p2(p2, t);
	uint32_t enc[8];
	ge_encode_p2(enc, p2);
	px_beta_words(beta, enc);
}

/* trailing zero bits of beta, counted from the least significant bit of beta[63] (= low byte of word 7) */
PXF int px_trailing_zeros(const uint64_t beta[8])
{
	int n = 0;
	for (int i = 7; i >= 0; i--) {
		uint64_t w = beta[i];
		if (w == 0) { n += 64; continue; }
		while (!(w & 1)) { w >>= 1; n++; }
		break;
	}
	return n;
}

/* beta words -> 64 bytes */
PXF void px_beta_bytes(uint8_t out[64], const uint64_t beta[8])
{
	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(beta[i] >> (56 - 8 * j));
}
