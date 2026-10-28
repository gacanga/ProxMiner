/**
 * ProxMiner - host-side helpers around px_core.h:
 *   generic SHA-512, the key (secret scalar x, k = 8x mod L, its wNAF digits, public key),
 *   the job constants (midstate of the first hash), and a full reference VRF output for any alpha
 *   (all hash-to-curve counters) used to verify every candidate and in the tests.
 * License: Apache-2.0.
 */
#pragma once
#include "px_core.h"
#include <string.h>
#include <vector>
#include <string>

/* ------------------------------------------------------------------ generic SHA-512 */

static inline void px_sha512(uint8_t out[64], const uint8_t *msg, size_t len)
{
	uint64_t s[8], h[8];
	px_sha512_iv(h);
	std::vector<uint8_t> m(msg, msg + len);
	m.push_back(0x80);
	while (m.size() % 128 != 112) m.push_back(0);
	for (int i = 0; i < 8; i++) m.push_back(0);                 /* high 64 bits of the length */
	uint64_t bits = (uint64_t)len * 8;
	for (int i = 7; i >= 0; i--) m.push_back((uint8_t)(bits >> (8 * i)));
	for (size_t off = 0; off < m.size(); off += 128) {
		uint64_t w[16];
		for (int i = 0; i < 16; i++) {
			uint64_t x = 0;
			for (int j = 0; j < 8; j++) x = (x << 8) | m[off + 8 * i + j];
			w[i] = x;
		}
		for (int i = 0; i < 8; i++) s[i] = h[i];
		px_sha512_rounds(s, w, 0);
		for (int i = 0; i < 8; i++) h[i] += s[i];
	}
	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(h[i] >> (56 - 8 * j));
}

/* ------------------------------------------------------------------ scalars mod L */

/* 256-bit little-endian, 4 x 64 */
struct px_u256 { uint64_t w[4]; };

static const px_u256 PX_L = {{0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL, 0ULL, 0x1000000000000000ULL}};

static inline int px_u256_cmp(const px_u256 &a, const px_u256 &b)
{
	for (int i = 3; i >= 0; i--) { if (a.w[i] < b.w[i]) return -1; if (a.w[i] > b.w[i]) return 1; }
	return 0;
}
static inline void px_u256_sub(px_u256 &a, const px_u256 &b)
{
	unsigned __int128 br = 0;
	for (int i = 0; i < 4; i++) {
		unsigned __int128 t = (unsigned __int128)a.w[i] - b.w[i] - (uint64_t)br;
		a.w[i] = (uint64_t)t;
		br = (t >> 64) ? 1 : 0;
	}
}
/* a mod L for a < 2^259 */
static inline void px_u256_modL(px_u256 &a, uint64_t top /* bits 256.. */)
{
	/* subtract L * 2^s while needed (a < 2^259 = at most 2^7 L) */
	for (int s = 7; s >= 0; s--) {
		/* Ls = L << s, compared as 260-bit with top */
		px_u256 Ls; uint64_t Lt;
		Ls.w[0] = PX_L.w[0] << s;
		Ls.w[1] = (PX_L.w[1] << s) | (s ? PX_L.w[0] >> (64 - s) : 0);
		Ls.w[2] = (PX_L.w[2] << s) | (s ? PX_L.w[1] >> (64 - s) : 0);
		Ls.w[3] = (PX_L.w[3] << s) | (s ? PX_L.w[2] >> (64 - s) : 0);
		Lt = s ? PX_L.w[3] >> (64 - s) : 0;
		bool ge = top > Lt || (top == Lt && px_u256_cmp(a, Ls) >= 0);
		if (ge) {
			bool borrow = px_u256_cmp(a, Ls) < 0;
			px_u256_sub(a, Ls);
			top -= Lt + (borrow ? 1 : 0);
		}
	}
}

struct px_secret {
	uint8_t seed[32];
	uint8_t pk[32];
	px_u256 x;         /* clamped secret scalar mod L */
	px_u256 k;         /* 8 x mod L */
	px_key key;        /* wNAF digits of k */
};

static inline void px_wnaf(px_key &key, const px_u256 &k_in)
{
	px_u256 k = k_in;
	memset(key.digits, 0, sizeof(key.digits));
	int i = 0;
	auto is_zero = [&]() { return (k.w[0] | k.w[1] | k.w[2] | k.w[3]) == 0; };
	while (!is_zero() && i < 256) {
		int d = 0;
		if (k.w[0] & 1) {
			d = (int)(k.w[0] & ((1u << PX_WNAF_W) - 1));
			if (d >= (1 << (PX_WNAF_W - 1))) d -= (1 << PX_WNAF_W);
			/* k -= d */
			if (d > 0) {
				px_u256 dd = {{(uint64_t)d, 0, 0, 0}}; px_u256_sub(k, dd);
			} else {
				unsigned __int128 c = (uint64_t)(-d);
				for (int j = 0; j < 4; j++) { c += k.w[j]; k.w[j] = (uint64_t)c; c >>= 64; }
			}
		}
		key.digits[i++] = (int8_t)d;
		/* k >>= 1 */
		k.w[0] = (k.w[0] >> 1) | (k.w[1] << 63);
		k.w[1] = (k.w[1] >> 1) | (k.w[2] << 63);
		k.w[2] = (k.w[2] >> 1) | (k.w[3] << 63);
		k.w[3] >>= 1;
	}
	key.ndigits = i;
	while (key.ndigits > 0 && key.digits[key.ndigits - 1] == 0) key.ndigits--;
}

/* generic scalar multiplication (host): r = s * P, binary, for the public key and the tests */
static inline void px_scalarmult_generic(ge_p3 &r, const px_u256 &s, const ge_p3 &P)
{
	ge_p3 acc; ge_p1p1 t; ge_cached c; ge_p3 base = P;
	fe_set_small(acc.X, 0); fe_set_small(acc.Y, 1); fe_set_small(acc.Z, 1); fe_set_small(acc.T, 0);
	for (int i = 0; i < 256; i++) {
		if ((s.w[i >> 6] >> (i & 63)) & 1) {
			ge_p3_to_cached(c, base);
			ge_add(t, acc, c); ge_p1p1_to_p3(acc, t);
		}
		ge_p3_to_cached(c, base);
		ge_add(t, base, c); ge_p1p1_to_p3(base, t);
	}
	r = acc;
}

static inline void px_fe_from_bytes(fe &r, const uint8_t b[32])
{
	for (int i = 0; i < 8; i++) r.v[i] = (uint32_t)b[4 * i] | ((uint32_t)b[4 * i + 1] << 8) | ((uint32_t)b[4 * i + 2] << 16) | ((uint32_t)b[4 * i + 3] << 24);
}
static inline void px_limbs_to_bytes(uint8_t out[32], const uint32_t v[8])
{
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(v[i >> 2] >> (8 * (i & 3)));
}

/* decode a 32-byte point encoding into p3; false if not a point */
static inline bool px_decode_point(ge_p3 &P, const uint8_t b[32])
{
	fe y, x;
	px_fe_from_bytes(y, b);
	uint32_t sign = y.v[7] >> 31;
	y.v[7] &= 0x7fffffffu;
	if (!ge_decode_xy(x, y, sign)) return false;
	P.X = x; P.Y = y; fe_set_small(P.Z, 1); fe_mul(P.T, x, y);
	return true;
}

static inline void px_encode_p3(uint8_t out[32], const ge_p3 &P)
{
	ge_p2 p2; p2.X = P.X; p2.Y = P.Y; p2.Z = P.Z;
	uint32_t e[8]; ge_encode_p2(e, p2);
	px_limbs_to_bytes(out, e);
}

static inline bool px_is_identity(const ge_p3 &P)
{
	fe z; fe_set_small(z, 0);
	return fe_equal(P.X, z) && fe_equal(P.Y, P.Z);
}

static inline void px_secret_from_seed(px_secret &sec, const uint8_t seed[32])
{
	memcpy(sec.seed, seed, 32);
	uint8_t h[64];
	px_sha512(h, seed, 32);
	h[0] &= 248; h[31] &= 127; h[31] |= 64;
	for (int i = 0; i < 4; i++) {
		uint64_t x = 0;
		for (int j = 7; j >= 0; j--) x = (x << 8) | h[8 * i + j];
		sec.x.w[i] = x;
	}
	px_u256_modL(sec.x, 0);
	/* k = 8x mod L */
	px_u256 k = sec.x;
	uint64_t top = k.w[3] >> 61;
	k.w[3] = (k.w[3] << 3) | (k.w[2] >> 61);
	k.w[2] = (k.w[2] << 3) | (k.w[1] >> 61);
	k.w[1] = (k.w[1] << 3) | (k.w[0] >> 61);
	k.w[0] <<= 3;
	px_u256_modL(k, top);
	sec.k = k;
	px_wnaf(sec.key, sec.k);
	/* public key = x B */
	static const uint8_t B[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
	ge_p3 base, Y;
	px_decode_point(base, B);
	px_scalarmult_generic(Y, sec.x, base);
	px_encode_p3(sec.pk, Y);
}

/* ------------------------------------------------------------------ reference output (all counters) */

/* beta of (pk, alpha) under sec, through px_stage2 (the GPU code path) after a generic hash-to-curve.
   Returns the counter used, or -1 if no counter in 0..255 gives a point. */
static inline int px_reference_beta(uint8_t beta[64], const px_secret &sec, const uint8_t *alpha, size_t alen, uint8_t H_out[32] = nullptr)
{
	std::vector<uint8_t> m;
	for (int ctr = 0; ctr < 256; ctr++) {
		m.clear();
		m.push_back(3); m.push_back(1);
		m.insert(m.end(), sec.pk, sec.pk + 32);
		m.insert(m.end(), alpha, alpha + alen);
		m.push_back((uint8_t)ctr); m.push_back(0);
		uint8_t h[64];
		px_sha512(h, m.data(), m.size());
		ge_p3 P;
		if (!px_decode_point(P, h)) continue;
		/* H = 8 P must not be the identity */
		ge_p3 H; px_u256 eight = {{8, 0, 0, 0}};
		px_scalarmult_generic(H, eight, P);
		if (px_is_identity(H)) continue;
		if (H_out) px_encode_p3(H_out, H);
		uint64_t bw[8];
		px_stage2(sec.key, P.X, P.Y, bw);
		px_beta_bytes(beta, bw);
		return ctr;
	}
	return -1;
}

/* ------------------------------------------------------------------ job constants */

/* nonce bytes for (n0, counter): n0 || counter as 7 big-endian bytes */
static inline void px_nonce_bytes(uint8_t out[8], uint8_t n0, uint64_t counter)
{
	out[0] = n0;
	for (int i = 0; i < 7; i++) out[1 + i] = (uint8_t)(counter >> (8 * (6 - i)));
}

/* builds the job constants for alpha_prefix (37 bytes), pk, n0 */
static inline bool px_make_job(px_job &job, const uint8_t pk[32], const uint8_t *prefix, size_t plen, uint8_t n0, uint32_t k)
{
	if (plen != 37) return false;
	uint8_t m[128];
	memset(m, 0, sizeof(m));
	m[0] = 3; m[1] = 1;
	memcpy(m + 2, pk, 32);
	memcpy(m + 34, prefix, 37);
	m[71] = n0;
	/* 72..78 counter, 79 ctr = 0, 80 = 0x00 */
	m[81] = 0x80;
	uint64_t bits = 81 * 8;
	for (int i = 0; i < 8; i++) m[120 + i] = (uint8_t)(bits >> (56 - 8 * i));
	for (int i = 0; i < 16; i++) {
		uint64_t x = 0;
		for (int j = 0; j < 8; j++) x = (x << 8) | m[8 * i + j];
		job.w[i] = x;
	}
	uint64_t s[8], w[16];
	px_sha512_iv(s);
	for (int i = 0; i < 16; i++) w[i] = job.w[i];
	/* rounds 0..8 only: run the generic rounds on a copy with from = 0, stopping early is not
	   possible there, so do the 9 rounds by hand here */
	{
		uint64_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
		for (int t = 0; t < PX_MID_ROUNDS; t++) {
			uint64_t S1 = PX_ROTR64(e, 14) ^ PX_ROTR64(e, 18) ^ PX_ROTR64(e, 41);
			uint64_t ch = (e & f) ^ (~e & g);
			uint64_t t1 = h + S1 + ch + px_sha512_k(t) + w[t];
			uint64_t S0 = PX_ROTR64(a, 28) ^ PX_ROTR64(a, 34) ^ PX_ROTR64(a, 39);
			uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
			uint64_t t2 = S0 + mj;
			h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
		}
		job.mid[0] = a; job.mid[1] = b; job.mid[2] = c; job.mid[3] = d;
		job.mid[4] = e; job.mid[5] = f; job.mid[6] = g; job.mid[7] = h;
	}
	job.k = k;
	job.pad = 0;
	return true;
}

static inline std::string px_hex(const uint8_t *p, size_t n)
{
	static const char *d = "0123456789abcdef";
	std::string s;
	for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
	return s;
}
static inline bool px_unhex(const std::string &h, std::vector<uint8_t> &out)
{
	auto v = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; };
	if (h.size() % 2) return false;
	out.clear();
	for (size_t i = 0; i < h.size(); i += 2) {
		int a = v(h[i]), b = v(h[i + 1]);
		if (a < 0 || b < 0) return false;
		out.push_back((uint8_t)(a * 16 + b));
	}
	return true;
}
