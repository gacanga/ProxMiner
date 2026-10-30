/**
 * ProxMiner - GPU nonce seeker for Proxima (PROX) mining, for `proxi node mine` (external nonce seeker
 * protocol, kb/external_nonce_seeker.md of the Proxima repository).  NVIDIA CUDA, Windows and Linux.
 *
 *   proxminer --proxi http://127.0.0.1:8100 --token T --key-file proxima.key --gpus 0,1
 *   proxminer --test   [--gpus ...]        GPU against the CPU reference, RFC 9381 vectors
 *   proxminer --bench S [--gpus ...]       S seconds per GPU on a synthetic job
 *
 * The miner (`proxi node mine`) follows the mine chain, verifies, proves, signs and submits; this program
 * only searches nonces.  Every GPU candidate is recomputed on the CPU before it is sent.
 * License: Apache-2.0.  No developer fee.
 */
#include "util.h"
#include "http.h"
#include "px_gpu.h"
#include "px_host.h"
#include <thread>
#include <atomic>
#include <random>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>

#define PX_VERSION "0.3.0"

static std::atomic<bool> g_stop(false);

/* ------------------------------------------------------------------ options */

struct Opts {
	std::string proxi = "http://127.0.0.1:8100";
	std::string token;
	std::string key_file = "proxima.key";
	std::string name = "proxminer";
	std::string log;
	std::vector<int> gpus;
	double batch_ms = 300;
	uint32_t max_items = 1u << 22;
	int tpb1 = 0, tpb2 = 0, blocks2 = 0;
	bool test = false;
	double bench = 0;
	int selfcheck_min = 10;
};

static std::vector<int> parse_list(const std::string &s)
{
	std::vector<int> v; std::stringstream ss(s); std::string x;
	while (std::getline(ss, x, ',')) if (!x.empty()) v.push_back(atoi(x.c_str()));
	return v;
}

static void usage()
{
	printf("ProxMiner " PX_VERSION " - GPU nonce seeker for Proxima (proxi node mine)\n"
		"  --proxi URL        job server of proxi node mine (mine.seeker.listen), default http://127.0.0.1:8100\n"
		"  --token T          mine.seeker.token of the wallet profile\n"
		"  --key-file F       wallet key file (unencrypted), default proxima.key; or env NONCE_SEEKER_SEED (hex)\n"
		"  --gpus LIST        e.g. 0,1,2 (default: all)\n"
		"  --name NAME        seeker name in the miner statistics (a -gN suffix per GPU)\n"
		"  --log FILE         also write the log to FILE\n"
		"  --batch-ms MS      target GPU time per batch (default 300)\n"
		"  --tpb1 N --tpb2 N --blocks2 N   launch geometry (0 = defaults)\n"
		"  --selfcheck MIN    GPU self-check period in minutes (default 10, 0 = off); exit code 6 on error\n"
		"  --args-file F      read more options from F (one line)\n"
		"  --test             GPU against the CPU reference, then exit\n"
		"  --bench S          S seconds per GPU on a synthetic job, then exit\n");
}

static bool parse_args(std::vector<std::string> a, Opts &o)
{
	for (size_t i = 0; i < a.size(); i++) {
		auto next = [&](std::string &v) { if (i + 1 >= a.size()) return false; v = a[++i]; return true; };
		std::string v;
		if (a[i] == "--proxi") { if (!next(o.proxi)) return false; }
		else if (a[i] == "--token") { if (!next(o.token)) return false; }
		else if (a[i] == "--key-file") { if (!next(o.key_file)) return false; }
		else if (a[i] == "--name") { if (!next(o.name)) return false; }
		else if (a[i] == "--log") { if (!next(o.log)) return false; }
		else if (a[i] == "--gpus") { if (!next(v)) return false; o.gpus = parse_list(v); }
		else if (a[i] == "--batch-ms") { if (!next(v)) return false; o.batch_ms = atof(v.c_str()); }
		else if (a[i] == "--tpb1") { if (!next(v)) return false; o.tpb1 = atoi(v.c_str()); }
		else if (a[i] == "--tpb2") { if (!next(v)) return false; o.tpb2 = atoi(v.c_str()); }
		else if (a[i] == "--blocks2") { if (!next(v)) return false; o.blocks2 = atoi(v.c_str()); }
		else if (a[i] == "--selfcheck") { if (!next(v)) return false; o.selfcheck_min = atoi(v.c_str()); }
		else if (a[i] == "--test") o.test = true;
		else if (a[i] == "--bench") { if (!next(v)) return false; o.bench = atof(v.c_str()); }
		else if (a[i] == "--args-file") {
			if (!next(v)) return false;
			std::ifstream f(v); std::string line, all;
			while (std::getline(f, line)) all += line + " ";
			std::stringstream ss(all); std::vector<std::string> more; std::string w;
			while (ss >> w) more.push_back(w);
			if (!parse_args(more, o)) return false;
		}
		else if (a[i] == "-h" || a[i] == "--help") { usage(); exit(0); }
		else { printf("unknown option %s\n", a[i].c_str()); return false; }
	}
	return true;
}

/* ------------------------------------------------------------------ key */

static bool load_key(const Opts &o, px_secret &sec, std::string &err)
{
	std::vector<uint8_t> seed;
	const char *env = getenv("NONCE_SEEKER_SEED");
	std::string pub_hex;
	if (env && *env) {
		if (!px_unhex(env, seed) || seed.size() != 32) { err = "NONCE_SEEKER_SEED must be 32 bytes in hex"; return false; }
	} else {
		std::ifstream f(o.key_file, std::ios::binary);
		if (!f) { err = "cannot read the key file " + o.key_file; return false; }
		std::stringstream ss; ss << f.rdbuf();
		JVal root;
		if (!JParser(ss.str()).parse(root) || root.t != JVal::OBJ) { err = "the key file is not a Proxima JSON keystore"; return false; }
		const JVal *cr = root.get("crypto");
		if (cr && !cr->is_null()) { err = "the key file is encrypted: not supported, use an unencrypted mining key or NONCE_SEEKER_SEED"; return false; }
		std::vector<uint8_t> pk;
		if (!px_unhex(root.str("private_key"), pk) || (pk.size() != 64 && pk.size() != 32)) { err = "private_key missing or malformed in " + o.key_file; return false; }
		seed.assign(pk.begin(), pk.begin() + 32);
		pub_hex = root.str("public_key");
	}
	px_secret_from_seed(sec, seed.data());
	if (!pub_hex.empty() && pub_hex != px_hex(sec.pk, 32)) { err = "the public key derived from the seed differs from the key file's public_key"; return false; }
	return true;
}

/* ------------------------------------------------------------------ job state */

struct Job {
	uint64_t id = 0;
	std::vector<uint8_t> prefix;
	uint32_t k = 0;
	std::vector<uint8_t> beat;       /* empty: none */
	double deadline = 0;              /* steady clock */
	uint64_t slot = 0;
	int version = 0;
};

static std::mutex g_jm;
static Job g_job;
static std::atomic<uint64_t> g_attempts_unreported(0);

static Job job_snapshot() { std::lock_guard<std::mutex> g(g_jm); return g_job; }

static void lower_beat(uint64_t id, const std::vector<uint8_t> &beat)
{
	std::lock_guard<std::mutex> g(g_jm);
	if (g_job.id != id || beat.size() != 64) return;
	if (g_job.beat.empty() || memcmp(beat.data(), g_job.beat.data(), 64) < 0) { g_job.beat = beat; g_job.version++; }
}

static void end_job(uint64_t id)
{
	std::lock_guard<std::mutex> g(g_jm);
	if (g_job.id == id) { g_job.deadline = 0; g_job.version++; }
}

static void poller(Opts o, std::string pk_hex)
{
	Http h; std::string err; h.set_url(o.proxi, err); h.token = o.token;
	uint64_t cur = 0; double backoff = 1; bool warned_key = false, was_down = false;
	while (!g_stop) {
		std::string path = "/seeker/job";
		if (cur) path += "?after=" + std::to_string(cur) + "&wait=8000";
		std::string body;
		int st = h.request("GET", path, "", body, err, 15);
		if (st != 200) {
			if (!was_down) LOG("job server %s: %s", o.proxi.c_str(), st ? ("HTTP " + std::to_string(st) + " " + body.substr(0, 120)).c_str() : err.c_str());
			was_down = true;
			{ std::lock_guard<std::mutex> g(g_jm); if (g_job.id) { g_job = Job(); g_job.version = 1; } }
			cur = 0;
			std::this_thread::sleep_for(std::chrono::milliseconds((int)(backoff * 1000)));
			backoff = backoff < 5 ? backoff * 1.5 : 5;
			continue;
		}
		if (was_down) LOG("job server %s reachable", o.proxi.c_str());
		was_down = false; backoff = 1;
		double t = now_s();
		JVal j;
		if (!JParser(body).parse(j)) { LOG("bad job JSON: %s", body.substr(0, 200).c_str()); std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
		uint64_t id = j.u64("id");
		Job nj;
		nj.id = id;
		if (id) {
			std::string pk = j.str("pubkey");
			if (pk != pk_hex) {
				if (!warned_key) LOG("!!! WRONG KEY: the job is for public key %s, this seeker holds %s - job refused", pk.c_str(), pk_hex.c_str());
				warned_key = true;
				nj.id = 0;
			} else {
				warned_key = false;
				px_unhex(j.str("alpha_prefix"), nj.prefix);
				nj.k = (uint32_t)j.num("k");
				std::string b = j.str("beat");
				if (!b.empty()) px_unhex(b, nj.beat);
				nj.deadline = t + j.num("ttl_ms") / 1000.0;
				nj.slot = j.u64("slot");
				if (nj.prefix.size() != 37) { LOG("job %llu: alpha_prefix of %d bytes, expected 37 - ignored", (unsigned long long)id, (int)nj.prefix.size()); nj.id = 0; }
			}
		}
		{
			std::lock_guard<std::mutex> g(g_jm);
			bool changed = nj.id != g_job.id || nj.k != g_job.k || nj.prefix != g_job.prefix;
			if (changed) {
				nj.version = g_job.version + 1;
				if (nj.id) LOG("job %llu: slot %llu, k = %u, %.1f s%s", (unsigned long long)nj.id, (unsigned long long)nj.slot, nj.k,
					nj.deadline - t, nj.beat.empty() ? "" : ", with beat");
				g_job = nj;
			} else if (nj.id) {
				/* same job: refresh the deadline, keep the lowest beat */
				g_job.deadline = nj.deadline;
				if (!nj.beat.empty() && (g_job.beat.empty() || memcmp(nj.beat.data(), g_job.beat.data(), 64) < 0)) { g_job.beat = nj.beat; g_job.version++; }
			}
		}
		cur = nj.id;
		if (!nj.id) std::this_thread::sleep_for(std::chrono::milliseconds(300));
	}
}

static void reporter(Opts o)
{
	Http h; std::string err; h.set_url(o.proxi, err); h.token = o.token;
	while (!g_stop) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		uint64_t n = g_attempts_unreported.exchange(0);
		if (!n) continue;
		uint64_t id = job_snapshot().id;
		std::string body = "{\"id\":" + std::to_string(id) + ",\"attempts\":" + std::to_string(n) + ",\"seeker\":" + json_escape(o.name) + "}";
		std::string resp;
		int st = h.request("POST", "/seeker/report", body, resp, err, 5);
		if (st != 200) g_attempts_unreported += n;          /* keep them for the next report */
	}
}

/* ------------------------------------------------------------------ GPU worker */

struct GpuStat {
	std::atomic<uint64_t> valid{0}, counters{0}, found{0}, accepted{0}, better{0}, stale{0}, refused{0};
	std::atomic<double> ms{0};
};

static bool cpu_check(const px_secret &sec, const std::vector<uint8_t> &prefix, uint8_t n0, uint64_t counter, uint32_t k, uint8_t beta[64], std::string &why)
{
	uint8_t alpha[45];
	memcpy(alpha, prefix.data(), 37);
	px_nonce_bytes(alpha + 37, n0, counter);
	int ctr = px_reference_beta(beta, sec, alpha, 45);
	if (ctr != 0) { why = "first hash try is not a point (ctr " + std::to_string(ctr) + ")"; return false; }
	uint64_t w[8];
	for (int i = 0; i < 8; i++) { uint64_t x = 0; for (int j = 0; j < 8; j++) x = (x << 8) | beta[8 * i + j]; w[i] = x; }
	int tz = px_trailing_zeros(w);
	if ((uint32_t)tz < k) { why = "only " + std::to_string(tz) + " trailing zero bits"; return false; }
	return true;
}

/* GPU self-check: debug kernel on n counters of a random job against the CPU */
static bool gpu_selfcheck(void *ctx, const px_secret &sec, int gpu, uint32_t n, std::mt19937_64 &rng, bool verbose)
{
	uint8_t prefix[37];
	for (auto &b : prefix) b = (uint8_t)rng();
	uint8_t n0 = (uint8_t)rng();
	px_job job; px_make_job(job, sec.pk, prefix, 37, n0, 0);
	px_set_job(ctx, &job);
	uint64_t base = rng() & 0x00ffffffffffffffULL;
	std::vector<uint8_t> valid(n), betas(64ull * n);
	int e = px_debug(ctx, base, n, valid.data(), betas.data());
	if (e) { LOG("GPU %d self-check: CUDA error %s", gpu, px_error_string(e)); return false; }
	int bad = 0, nv = 0;
	for (uint32_t i = 0; i < n; i++) {
		uint64_t c = (base + i) & 0x00ffffffffffffffULL;
		uint8_t alpha[45]; memcpy(alpha, prefix, 37); px_nonce_bytes(alpha + 37, n0, c);
		uint8_t rb[64];
		int ctr = px_reference_beta(rb, sec, alpha, 45);
		bool rv = ctr == 0;
		if (rv != (valid[i] != 0) || (rv && memcmp(rb, &betas[64ull * i], 64) != 0)) {
			if (bad < 3) LOG("GPU %d self-check: counter %llu differs (decode cpu %d gpu %d)", gpu, (unsigned long long)c, (int)rv, (int)valid[i]);
			bad++;
		}
		nv += rv;
	}
	if (verbose || bad) LOG("GPU %d self-check: %u counters, %d decodable, %d differences", gpu, n, nv, bad);
	return bad == 0;
}

static void worker(Opts o, int gpu, const px_secret *sec, GpuStat *st, std::atomic<int> *exit_code)
{
	char err[256] = {0};
	void *ctx = px_create(gpu, o.max_items, o.tpb1, o.tpb2, o.blocks2, err, sizeof err);
	if (!ctx) { LOG("GPU %d: %s", gpu, err); *exit_code = 3; g_stop = true; return; }
	px_set_key(ctx, &sec->key);
	std::random_device rd;
	std::mt19937_64 rng(((uint64_t)rd() << 32) ^ rd() ^ ((uint64_t)gpu << 56) ^ (uint64_t)time(nullptr));
	if (!gpu_selfcheck(ctx, *sec, gpu, 512, rng, true)) { *exit_code = 6; g_stop = true; px_destroy(ctx); return; }
	Http h; std::string herr; h.set_url(o.proxi, herr); h.token = o.token;
	std::string seeker = o.name + "-g" + std::to_string(gpu);
	uint32_t count = 1u << 16;
	uint64_t cur_id = 0; int cur_ver = -1; uint8_t n0 = 0; uint64_t base = 0; uint32_t cur_k = 0;
	std::vector<uint8_t> prefix;
	double next_check = now_s() + o.selfcheck_min * 60.0;
	bool idle_logged = false;
	while (!g_stop) {
		Job j = job_snapshot();
		double t = now_s();
		if (o.selfcheck_min > 0 && t > next_check) {
			if (!gpu_selfcheck(ctx, *sec, gpu, 256, rng, false)) { LOG("GPU %d: SELF-CHECK FAILED - stopping (exit code 6)", gpu); *exit_code = 6; g_stop = true; break; }
			next_check = t + o.selfcheck_min * 60.0;
			cur_id = 0;             /* the self-check replaced the job constants */
		}
		if (!j.id || t > j.deadline) {
			if (!idle_logged && cur_id) LOG("GPU %d: waiting for a job", gpu);
			idle_logged = true;
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			continue;
		}
		idle_logged = false;
		if (j.id != cur_id || j.k != cur_k || j.prefix != prefix) {
			n0 = (uint8_t)rng();
			base = rng() & 0x00ffffffffffffffULL;
			px_job pj;
			px_make_job(pj, sec->pk, j.prefix.data(), 37, n0, j.k);
			px_set_job(ctx, &pj);
			cur_id = j.id; cur_k = j.k; prefix = j.prefix;
		}
		(void)cur_ver;
		uint64_t found[PX_MAX_FOUND]; int nf = 0; uint32_t nv = 0; float ms = 0;
		int e = px_scan(ctx, base, count, found, PX_MAX_FOUND, &nf, &nv, &ms);
		if (e) { LOG("GPU %d: CUDA error %s - stopping", gpu, px_error_string(e)); *exit_code = 4; g_stop = true; break; }
		base = (base + count) & 0x00ffffffffffffffULL;
		st->valid += nv; st->counters += count; st->ms = st->ms + ms;
		g_attempts_unreported += nv;
		if (nf > PX_MAX_FOUND) nf = PX_MAX_FOUND;
		for (int i = 0; i < nf; i++) {
			uint8_t beta[64]; std::string why;
			if (!cpu_check(*sec, prefix, n0, found[i], cur_k, beta, why)) {
				LOG("GPU %d: WRONG candidate %llu: %s", gpu, (unsigned long long)found[i], why.c_str());
				st->refused++;
				continue;
			}
			st->found++;
			Job now = job_snapshot();
			if (now.id != cur_id) { st->stale++; continue; }
			if (!now.beat.empty() && memcmp(beta, now.beat.data(), 64) >= 0) { st->better++; continue; }
			uint8_t nonce[8]; px_nonce_bytes(nonce, n0, found[i]);
			uint64_t att = g_attempts_unreported.exchange(0);
			std::string body = "{\"id\":" + std::to_string(cur_id) + ",\"nonce\":\"" + px_hex(nonce, 8) + "\",\"beta\":\"" + px_hex(beta, 64) +
				"\",\"attempts\":" + std::to_string(att) + ",\"seeker\":" + json_escape(seeker) + "}";
			std::string resp, rerr;
			int code = h.request("POST", "/seeker/result", body, resp, rerr, 10);
			JVal r; JParser(resp).parse(r);
			if (code == 200) {
				std::vector<uint8_t> nb; px_unhex(r.str("beat"), nb);
				bool acc = r.boolean("accepted");
				lower_beat(cur_id, nb);
				if (acc) st->accepted++; else st->better++;
				LOG("GPU %d: solution for slot %llu (k %u): %s", gpu, (unsigned long long)j.slot, cur_k, acc ? "ACCEPTED by the miner" : "valid, but a better one is known");
			} else if (code == 409) {
				st->stale++; end_job(cur_id);
				LOG("GPU %d: solution too late (stale job)", gpu);
			} else {
				if (code == 0) g_attempts_unreported += att;
				st->refused++;
				LOG("GPU %d: solution REFUSED: HTTP %d %s %s", gpu, code, resp.substr(0, 200).c_str(), rerr.c_str());
			}
		}
		/* batch size: aim at batch_ms of GPU time, multiple of 4096 */
		if (ms > 1) {
			double f = o.batch_ms / ms;
			if (f > 2) f = 2;
			if (f < 0.5) f = 0.5;
			uint64_t nc = (uint64_t)(count * f);
			nc = (nc / 4096) * 4096;
			if (nc < 4096) nc = 4096;
			if (nc > o.max_items) nc = o.max_items;
			count = (uint32_t)nc;
		}
	}
	px_destroy(ctx);
}

/* ------------------------------------------------------------------ test / bench */

static int run_test(const Opts &o, const std::vector<int> &gpus)
{
	int fails = 0;
	/* RFC 9381 B.4 vector 2 on the CPU code path */
	{
		std::vector<uint8_t> sk; px_unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", sk);
		px_secret s; px_secret_from_seed(s, sk.data());
		uint8_t a = 0x72, beta[64];
		px_reference_beta(beta, s, &a, 1);
		bool ok = px_hex(s.pk, 32) == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c" &&
			px_hex(beta, 64) == "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031";
		LOG("CPU: RFC 9381 vector %s", ok ? "OK" : "FAILED");
		fails += !ok;
	}
	std::mt19937_64 rng(20261028);
	for (int g : gpus) {
		char err[256] = {0};
		void *ctx = px_create(g, o.max_items, o.tpb1, o.tpb2, o.blocks2, err, sizeof err);
		if (!ctx) { LOG("GPU %d: %s", g, err); fails++; continue; }
		int r1 = 0, l1 = 0, r2 = 0, l2 = 0;
		px_kernel_info(ctx, &r1, &l1, &r2, &l2);
		LOG("GPU %d: stage 1 %d registers %d B local, stage 2 %d registers %d B local", g, r1, l1, r2, l2);
		for (int rep = 0; rep < 3; rep++) {
			uint8_t seed[32]; for (auto &b : seed) b = (uint8_t)rng();
			px_secret s; px_secret_from_seed(s, seed);
			px_set_key(ctx, &s.key);
			if (!gpu_selfcheck(ctx, s, g, 4096, rng, true)) fails++;
		}
		/* scan + filter: k = 7, compare the found set with the debug betas */
		{
			uint8_t seed[32]; for (auto &b : seed) b = (uint8_t)rng();
			px_secret s; px_secret_from_seed(s, seed);
			px_set_key(ctx, &s.key);
			uint8_t prefix[37]; for (auto &b : prefix) b = (uint8_t)rng();
			uint8_t n0 = (uint8_t)rng();
			const uint32_t k = 7, n = 8192;
			px_job pj; px_make_job(pj, s.pk, prefix, 37, n0, k);
			px_set_job(ctx, &pj);
			uint64_t base = rng() & 0x00ffffffffffffffULL;
			std::vector<uint8_t> valid(n), betas(64ull * n);
			px_debug(ctx, base, n, valid.data(), betas.data());
			std::vector<uint64_t> want; uint32_t nvalid_want = 0;
			for (uint32_t i = 0; i < n; i++) {
				if (!valid[i]) continue;
				nvalid_want++;
				uint64_t w[8];
				for (int a = 0; a < 8; a++) { uint64_t x = 0; for (int b = 0; b < 8; b++) x = (x << 8) | betas[64ull * i + 8 * a + b]; w[a] = x; }
				if ((uint32_t)px_trailing_zeros(w) >= k) want.push_back((base + i) & 0x00ffffffffffffffULL);
			}
			uint64_t found[PX_MAX_FOUND]; int nf = 0; uint32_t nv = 0; float ms = 0;
			int e = px_scan(ctx, base, n, found, PX_MAX_FOUND, &nf, &nv, &ms);
			std::vector<uint64_t> got(found, found + (nf < PX_MAX_FOUND ? nf : PX_MAX_FOUND));
			std::sort(got.begin(), got.end()); std::sort(want.begin(), want.end());
			bool ok = !e && nv == nvalid_want && got == want;
			int cpu_ok = 0;
			for (uint64_t c : got) { uint8_t b[64]; std::string why; cpu_ok += cpu_check(s, std::vector<uint8_t>(prefix, prefix + 37), n0, c, k, b, why); }
			ok = ok && cpu_ok == (int)got.size();
			LOG("GPU %d: scan k=%u: %u decodable (expected %u), %d candidates (expected %d), CPU-verified %d: %s",
				g, k, nv, nvalid_want, nf, (int)want.size(), cpu_ok, ok ? "OK" : "FAILED");
			fails += !ok;
		}
		px_destroy(ctx);
	}
	LOG(fails ? "TEST FAILED (%d)" : "TEST ALL OK", fails);
	return fails ? 1 : 0;
}

static int run_bench(const Opts &o, const std::vector<int> &gpus, const px_secret &sec)
{
	std::vector<std::thread> th;
	std::vector<double> rate(gpus.size(), 0), raw(gpus.size(), 0);
	for (size_t gi = 0; gi < gpus.size(); gi++) {
		th.emplace_back([&, gi]() {
			int g = gpus[gi];
			char err[256] = {0};
			void *ctx = px_create(g, o.max_items, o.tpb1, o.tpb2, o.blocks2, err, sizeof err);
			if (!ctx) { LOG("GPU %d: %s", g, err); return; }
			px_set_key(ctx, &sec.key);
			std::mt19937_64 rng(g * 77 + 1);
			uint8_t prefix[37]; for (auto &b : prefix) b = (uint8_t)rng();
			px_job pj; px_make_job(pj, sec.pk, prefix, 37, (uint8_t)rng(), 64);
			px_set_job(ctx, &pj);
			uint32_t count = 1u << 16; uint64_t base = 0, tv = 0, tc = 0; double tms = 0;
			double t0 = now_s(), warm = t0 + 3;
			bool measuring = false; double tstart = 0;
			while (now_s() - t0 < o.bench + 3) {
				uint64_t found[PX_MAX_FOUND]; int nf = 0; uint32_t nv = 0; float ms = 0;
				int e = px_scan(ctx, base, count, found, PX_MAX_FOUND, &nf, &nv, &ms);
				if (e) { LOG("GPU %d: CUDA error %s", g, px_error_string(e)); break; }
				base += count;
				if (!measuring && now_s() > warm) { measuring = true; tstart = now_s(); tv = tc = 0; tms = 0; continue; }
				if (measuring) { tv += nv; tc += count; tms += ms; }
				if (ms > 1) {
					double f = o.batch_ms / ms; if (f > 2) f = 2; if (f < 0.5) f = 0.5;
					uint64_t nc = ((uint64_t)(count * f) / 4096) * 4096; if (nc < 4096) nc = 4096; if (nc > o.max_items) nc = o.max_items;
					count = (uint32_t)nc;
				}
			}
			double el = now_s() - tstart;
			rate[gi] = tv / el; raw[gi] = tc / el;
			int r1 = 0, l1 = 0, r2 = 0, l2 = 0;
			px_kernel_info(ctx, &r1, &l1, &r2, &l2);
			LOG("GPU %d: %.1f kH/s (attempts = decodable nonces; %.1f k counters/s), batch %u, %.0f ms/batch, regs %d/%d local %d/%d",
				g, rate[gi] / 1e3, raw[gi] / 1e3, count, tms / ((double)tc / count), r1, r2, l1, l2);
			px_destroy(ctx);
		});
	}
	for (auto &t : th) t.join();
	double tot = 0; for (double r : rate) tot += r;
	LOG("BENCH total: %.1f kH/s on %d GPU(s)", tot / 1e3, (int)gpus.size());
	return 0;
}

/* ------------------------------------------------------------------ main */

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	Opts o;
	std::vector<std::string> args(argv + 1, argv + argc);
	if (!parse_args(args, o)) { usage(); return 2; }
	if (!o.log.empty()) Log::get().open(o.log);
	net_init();
	int ndev = px_device_count();
	if (ndev <= 0) { LOG("no CUDA device (%d)", ndev); return 3; }
	std::vector<int> gpus = o.gpus;
	if (gpus.empty()) for (int i = 0; i < ndev; i++) gpus.push_back(i);
	for (int g : gpus) {
		if (g < 0 || g >= ndev) { LOG("GPU %d does not exist (%d devices)", g, ndev); return 2; }
		char nm[256]; px_device_name(g, nm, sizeof nm);
		LOG("GPU %d: %s", g, nm);
	}
	LOG("ProxMiner " PX_VERSION " - Proxima nonce seeker (ECVRF-EDWARDS25519-SHA512-TAI), no fee");
	if (o.test) return run_test(o, gpus);

	px_secret sec;
	std::string err;
	if (!load_key(o, sec, err)) {
		if (o.bench > 0) {
			uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);
			px_secret_from_seed(sec, seed);
		} else { LOG("key: %s", err.c_str()); return 2; }
	}
	if (o.bench > 0) return run_bench(o, gpus, sec);

	LOG("key: public key %s, wNAF %d digits", px_hex(sec.pk, 32).c_str(), sec.key.ndigits);
	LOG("job server %s%s", o.proxi.c_str(), o.token.empty() ? " (no token)" : " (token set)");
	std::thread tp(poller, o, px_hex(sec.pk, 32));
	std::thread tr(reporter, o);
	std::vector<GpuStat> stats(gpus.size());
	std::atomic<int> exit_code(0);
	std::vector<std::thread> tw;
	for (size_t i = 0; i < gpus.size(); i++) tw.emplace_back(worker, o, gpus[i], &sec, &stats[i], &exit_code);
	double t0 = now_s(), last = t0;
	std::vector<uint64_t> lastv(gpus.size(), 0);
	while (!g_stop) {
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		double t = now_s();
		if (t - last < 30) continue;
		std::string line; double tot = 0;
		for (size_t i = 0; i < gpus.size(); i++) {
			uint64_t v = stats[i].valid;
			double r = (v - lastv[i]) / (t - last);
			lastv[i] = v; tot += r;
			char b[64]; snprintf(b, sizeof b, " GPU%d %.1f", gpus[i], r / 1e3); line += b;
		}
		uint64_t fo = 0, ac = 0, be = 0, stl = 0, rf = 0;
		for (auto &s : stats) { fo += s.found; ac += s.accepted; be += s.better; stl += s.stale; rf += s.refused; }
		Job j = job_snapshot();
		LOG("%.1f kH/s (%s kH/s) | solutions %llu: accepted %llu, beaten %llu, stale %llu, refused %llu | %s",
			tot / 1e3, line.c_str() + 1, (unsigned long long)fo, (unsigned long long)ac, (unsigned long long)be,
			(unsigned long long)stl, (unsigned long long)rf, j.id ? ("slot " + std::to_string(j.slot) + " k " + std::to_string(j.k)).c_str() : "no job");
		last = t;
	}
	for (auto &t : tw) t.join();
	tp.detach(); tr.detach();
	return exit_code;
}
