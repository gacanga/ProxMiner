/**
 * ProxMiner - minimal HTTP/1.1 client (plain HTTP, one connection per request) for the job server of
 * `proxi node mine` (kb/external_nonce_seeker.md): GET /seeker/job, POST /seeker/result, /seeker/report.
 */
#pragma once
#include "util.h"
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define SOCK_BAD INVALID_SOCKET
#define sock_close closesocket
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
typedef int sock_t;
#define SOCK_BAD (-1)
#define sock_close close
#endif

static inline void net_init()
{
#if defined(_WIN32)
	WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
#endif
}

class Http {
public:
	std::string host = "127.0.0.1";
	int port = 8100;
	std::string token;

	/* http://host[:port] */
	bool set_url(const std::string &url, std::string &err)
	{
		std::string u = url;
		if (u.rfind("https://", 0) == 0) { err = "https is not supported, the job server is plain HTTP"; return false; }
		if (u.rfind("http://", 0) == 0) u = u.substr(7);
		size_t s = u.find('/');
		if (s != std::string::npos) u = u.substr(0, s);
		size_t c = u.rfind(':');
		port = 80;
		if (c != std::string::npos) { port = atoi(u.substr(c + 1).c_str()); u = u.substr(0, c); }
		host = u;
		if (host.empty() || port <= 0 || port > 65535) { err = "bad URL " + url; return false; }
		return true;
	}

	/* returns the HTTP status (> 0) and the body, or 0 and err */
	int request(const std::string &method, const std::string &path, const std::string &body, std::string &out, std::string &err, int timeout_s = 15)
	{
		std::string resp;
		if (!roundtrip(method, path, body, resp, err, timeout_s)) return 0;
		size_t he = resp.find("\r\n\r\n");
		if (he == std::string::npos) { err = "bad HTTP response"; return 0; }
		std::string head = resp.substr(0, he);
		out = resp.substr(he + 4);
		int status = 0;
		if (sscanf(head.c_str(), "HTTP/%*s %d", &status) != 1) { err = "bad HTTP status line"; return 0; }
		std::string lower = head;
		for (auto &ch : lower) ch = (char)tolower((unsigned char)ch);
		if (lower.find("transfer-encoding: chunked") != std::string::npos) out = dechunk(out);
		return status;
	}

private:
	static std::string dechunk(const std::string &in)
	{
		std::string out; size_t p = 0;
		while (p < in.size()) {
			size_t e = in.find("\r\n", p);
			if (e == std::string::npos) break;
			unsigned long n = strtoul(in.substr(p, e - p).c_str(), nullptr, 16);
			if (n == 0) break;
			out += in.substr(e + 2, n);
			p = e + 2 + n + 2;
		}
		return out;
	}
	static bool complete(const std::string &resp)
	{
		size_t he = resp.find("\r\n\r\n");
		if (he == std::string::npos) return false;
		std::string lower = resp.substr(0, he);
		for (auto &c : lower) c = (char)tolower((unsigned char)c);
		size_t cl = lower.find("content-length:");
		if (cl != std::string::npos) return resp.size() >= he + 4 + strtoul(lower.c_str() + cl + 15, nullptr, 10);
		if (lower.find("transfer-encoding: chunked") != std::string::npos) return resp.find("\r\n0\r\n\r\n", he) != std::string::npos;
		return false;
	}
	bool roundtrip(const std::string &method, const std::string &path, const std::string &body, std::string &resp, std::string &err, int timeout_s)
	{
		struct addrinfo hints, *res = nullptr;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) { err = "cannot resolve " + host; return false; }
		sock_t s = SOCK_BAD;
		for (struct addrinfo *a = res; a; a = a->ai_next) {
			s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
			if (s == SOCK_BAD) continue;
#if defined(_WIN32)
			DWORD tv = (DWORD)timeout_s * 1000;
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
			setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
			struct timeval tv; tv.tv_sec = timeout_s; tv.tv_usec = 0;
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
			if (connect(s, a->ai_addr, (int)a->ai_addrlen) == 0) break;
			sock_close(s); s = SOCK_BAD;
		}
		freeaddrinfo(res);
		if (s == SOCK_BAD) { err = "cannot connect to " + host + ":" + std::to_string(port) + " (is proxi node mine running with mine.seeker.listen?)"; return false; }
		std::string req = method + " " + path + " HTTP/1.1\r\nHost: " + host + ":" + std::to_string(port) +
			"\r\nUser-Agent: ProxMiner\r\nConnection: close\r\nAccept: application/json\r\n";
		if (!token.empty()) req += "Authorization: Bearer " + token + "\r\n";
		if (method == "POST") req += "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
		req += "\r\n" + body;
		size_t off = 0;
		while (off < req.size()) {
			int n = send(s, req.data() + off, (int)(req.size() - off), 0);
			if (n <= 0) { sock_close(s); err = "send failed"; return false; }
			off += (size_t)n;
		}
		resp.clear();
		char buf[16384];
		for (;;) {
			int n = recv(s, buf, sizeof(buf), 0);
			if (n < 0) { sock_close(s); err = "receive failed or timed out"; return false; }
			if (n == 0) break;
			resp.append(buf, (size_t)n);
			if (complete(resp)) break;
		}
		sock_close(s);
		if (resp.empty()) { err = "empty response"; return false; }
		return true;
	}
};
