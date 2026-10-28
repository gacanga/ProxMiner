/**
 * ProxMiner - small helpers: JSON parser, logging, time.
 */
#pragma once
#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <utility>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <chrono>

/* ------------------------------------------------------------------ JSON */

struct JVal {
	enum Type { NUL, BOOL, NUM, STR, ARR, OBJ } t = NUL;
	bool b = false;
	std::string s;                                  /* string value, or the raw text of a number */
	std::vector<JVal> a;
	std::vector<std::pair<std::string, JVal>> o;
	const JVal *get(const char *k) const
	{
		if (t != OBJ) return nullptr;
		for (auto &kv : o) if (kv.first == k) return &kv.second;
		return nullptr;
	}
	bool is_null() const { return t == NUL; }
	long long as_int(long long def = 0) const { return t == NUM ? strtoll(s.c_str(), nullptr, 10) : def; }
	unsigned long long as_u64(unsigned long long def = 0) const { return t == NUM ? strtoull(s.c_str(), nullptr, 10) : def; }
	std::string str(const char *k, const char *def = "") const { const JVal *v = get(k); return (v && v->t == STR) ? v->s : def; }
	long long num(const char *k, long long def = 0) const { const JVal *v = get(k); return v ? v->as_int(def) : def; }
	unsigned long long u64(const char *k, unsigned long long def = 0) const { const JVal *v = get(k); return v ? v->as_u64(def) : def; }
	bool boolean(const char *k, bool def = false) const { const JVal *v = get(k); return (v && v->t == BOOL) ? v->b : def; }
};

class JParser {
public:
	explicit JParser(const std::string &txt) : p_(txt.c_str()), e_(txt.c_str() + txt.size()) {}
	bool parse(JVal &v) { ws(); if (!value(v, 0)) return false; ws(); return p_ == e_; }
private:
	const char *p_, *e_;
	void ws() { while (p_ < e_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\r' || *p_ == '\n')) p_++; }
	bool lit(const char *w) { size_t n = strlen(w); if ((size_t)(e_ - p_) < n || strncmp(p_, w, n)) return false; p_ += n; return true; }
	static void utf8(std::string &out, unsigned c)
	{
		if (c < 0x80) out += (char)c;
		else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
		else if (c < 0x10000) { out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
		else { out += (char)(0xF0 | (c >> 18)); out += (char)(0x80 | ((c >> 12) & 0x3F)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
	}
	bool string(std::string &out)
	{
		if (p_ >= e_ || *p_ != '"') return false;
		p_++;
		while (p_ < e_ && *p_ != '"') {
			char c = *p_++;
			if (c != '\\') { out += c; continue; }
			if (p_ >= e_) return false;
			c = *p_++;
			switch (c) {
			case '"': out += '"'; break; case '\\': out += '\\'; break; case '/': out += '/'; break;
			case 'b': out += '\b'; break; case 'f': out += '\f'; break; case 'n': out += '\n'; break;
			case 'r': out += '\r'; break; case 't': out += '\t'; break;
			case 'u': {
				if (e_ - p_ < 4) return false;
				unsigned u = (unsigned)strtoul(std::string(p_, 4).c_str(), nullptr, 16); p_ += 4;
				utf8(out, u); break;
			}
			default: return false;
			}
		}
		if (p_ >= e_) return false;
		p_++;
		return true;
	}
	bool value(JVal &v, int depth)
	{
		if (depth > 64 || p_ >= e_) return false;
		char c = *p_;
		if (c == '{') {
			v.t = JVal::OBJ; p_++; ws();
			if (p_ < e_ && *p_ == '}') { p_++; return true; }
			for (;;) {
				std::string k; ws(); if (!string(k)) return false; ws();
				if (p_ >= e_ || *p_ != ':') return false;
				p_++; ws();
				JVal x; if (!value(x, depth + 1)) return false;
				v.o.emplace_back(std::move(k), std::move(x)); ws();
				if (p_ < e_ && *p_ == ',') { p_++; continue; }
				if (p_ < e_ && *p_ == '}') { p_++; return true; }
				return false;
			}
		}
		if (c == '[') {
			v.t = JVal::ARR; p_++; ws();
			if (p_ < e_ && *p_ == ']') { p_++; return true; }
			for (;;) {
				JVal x; ws(); if (!value(x, depth + 1)) return false;
				v.a.push_back(std::move(x)); ws();
				if (p_ < e_ && *p_ == ',') { p_++; continue; }
				if (p_ < e_ && *p_ == ']') { p_++; return true; }
				return false;
			}
		}
		if (c == '"') { v.t = JVal::STR; return string(v.s); }
		if (lit("true")) { v.t = JVal::BOOL; v.b = true; return true; }
		if (lit("false")) { v.t = JVal::BOOL; v.b = false; return true; }
		if (lit("null")) { v.t = JVal::NUL; return true; }
		const char *s = p_;
		if (p_ < e_ && (*p_ == '-' || *p_ == '+')) p_++;
		while (p_ < e_ && ((*p_ >= '0' && *p_ <= '9') || *p_ == '.' || *p_ == 'e' || *p_ == 'E' || *p_ == '-' || *p_ == '+')) p_++;
		if (p_ == s) return false;
		v.t = JVal::NUM; v.s.assign(s, p_);
		return true;
	}
};

static inline std::string json_escape(const std::string &s)
{
	std::string o = "\"";
	for (char c : s) {
		if (c == '"' || c == '\\') { o += '\\'; o += c; }
		else if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
		else o += c;
	}
	return o + "\"";
}

/* ------------------------------------------------------------------ time / logging */

static inline double now_s()
{
	return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

class Log {
public:
	static Log &get() { static Log l; return l; }
	void open(const std::string &path) { std::lock_guard<std::mutex> g(m_); if (f_) fclose(f_); f_ = fopen(path.c_str(), "a"); }
	void write(const char *fmt, ...)
	{
		char msg[4096];
		va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof(msg), fmt, ap); va_end(ap);
		time_t t = time(nullptr);
		std::lock_guard<std::mutex> g(m_);
		struct tm tm = *localtime(&t);
		char ts[32]; strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
		printf("[%s] %s\n", ts, msg); fflush(stdout);
		if (f_) { fprintf(f_, "[%s] %s\n", ts, msg); fflush(f_); }
	}
private:
	std::mutex m_; FILE *f_ = nullptr;
};
#define LOG(...) Log::get().write(__VA_ARGS__)
