#!/usr/bin/env python3
"""ProxMiner - fake job server of `proxi node mine` (external nonce seeker protocol) for tests without
the network: new job every --slot seconds, results verified with tests/ref_vrf.py (independent code).
  python3 -I tests/fake_proxi.py --key key.json --port 8100 --k 6 --seconds 40"""
import argparse, json, os, sys, threading, time, random
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ref_vrf

ap = argparse.ArgumentParser()
ap.add_argument("--key", required=True); ap.add_argument("--port", type=int, default=8100)
ap.add_argument("--k", type=int, default=6); ap.add_argument("--slot", type=float, default=10.0)
ap.add_argument("--seconds", type=float, default=40); ap.add_argument("--token", default="tok")
a = ap.parse_args()
seed = bytes.fromhex(json.load(open(a.key))["private_key"])[:32]
pk = ref_vrf.public_key(seed)
lock = threading.Condition()
state = {"id": 0, "prefix": b"", "beat": None, "end": 0, "slot": 1000}
stats = {"jobs": 0, "accepted": 0, "not_better": 0, "stale": 0, "bad": 0, "reports": 0, "attempts": 0}

def new_job():
    with lock:
        state["id"] = int(time.time() * 1000)
        state["prefix"] = os.urandom(37)
        state["beat"] = None
        state["end"] = time.time() + a.slot
        state["slot"] += 1
        stats["jobs"] += 1
        lock.notify_all()

def job_json():
    if not state["id"] or time.time() > state["end"]:
        return {"id": 0}
    j = {"id": state["id"], "alpha_prefix": state["prefix"].hex(), "k": a.k, "ttl_ms": int((state["end"] - time.time()) * 1000),
         "pubkey": pk.hex(), "pred": "00" * 33, "slot": state["slot"]}
    if state["beat"]: j["beat"] = state["beat"].hex()
    return j

class H(BaseHTTPRequestHandler):
    def log_message(self, *x): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def auth(self):
        if self.headers.get("Authorization") != "Bearer " + a.token:
            self.send(401, {"error": "unauthorized"}); return False
        return True
    def do_GET(self):
        if not self.auth(): return
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        after = int(q.get("after", ["0"])[0]); wait = min(int(q.get("wait", ["0"])[0]), 10000) / 1000
        with lock:
            if after and after == state["id"]:
                lock.wait_for(lambda: state["id"] != after, timeout=wait)
            self.send(200, job_json())
    def do_POST(self):
        if not self.auth(): return
        n = int(self.headers.get("Content-Length", "0")); r = json.loads(self.rfile.read(n))
        if self.path == "/seeker/report":
            stats["reports"] += 1; stats["attempts"] += r.get("attempts", 0); self.send(200, {}); return
        if self.path != "/seeker/result": self.send(404, {}); return
        stats["attempts"] += r.get("attempts", 0)
        with lock:
            if r["id"] != state["id"] or time.time() > state["end"]:
                stats["stale"] += 1; self.send(409, {"error": "stale job"}); return
            prefix = state["prefix"]
        beta, ctr = ref_vrf.beta_of(seed, prefix + bytes.fromhex(r["nonce"]))
        if beta.hex() != r.get("beta") or ref_vrf.trailing_zero_bits(beta) < a.k:
            stats["bad"] += 1; self.send(422, {"error": "beta mismatch or too few zero bits (ctr %d)" % ctr}); return
        with lock:
            if state["beat"] is None or beta < state["beat"]:
                state["beat"] = beta; stats["accepted"] += 1; acc = True
            else:
                stats["not_better"] += 1; acc = False
            self.send(200, {"accepted": acc, "beat": state["beat"].hex()})

srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
t0 = time.time()
while time.time() - t0 < a.seconds:
    new_job(); time.sleep(a.slot)
print("fake_proxi:", json.dumps(stats)); sys.stdout.flush()
ok = stats["accepted"] > 0 and stats["bad"] == 0 and stats["reports"] > 0
print("FAKE PROXI TEST", "OK" if ok else "FAILED")
srv.shutdown()
sys.exit(0 if ok else 1)
