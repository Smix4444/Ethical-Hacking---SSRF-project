"""
SSRF Lab — Rebinding DNS server  (lab component)
================================================
⚠️  LAB-ONLY.  Internal, deterministic DNS rebinding server for the zone
`rebind.lab`, used to demonstrate a TOCTOU (check-then-use) SSRF bypass.

Behaviour for `rebind.lab` (A records, TTL 0 so nothing is cached):
  - 1st A query after a reset  -> a SAFE, public-looking IP (validated, never
    actually connected to).
  - 2nd and later A queries     -> the INTERNAL metadata IP 169.254.169.254.
So a filter that resolves+validates once (query 1 = safe) but lets the HTTP
client resolve again at connect (query 2 = internal) is defeated. Our L3
resolve-then-pin only resolves once and pins the IP, so it is immune.

Every OTHER name is forwarded to Docker's embedded resolver (127.0.0.11), so the
rest of the lab keeps resolving normally. A tiny HTTP control API makes demos
deterministic:  GET /reset  ·  GET /log  ·  GET /state

Everything here is internal and fake. Realism note: in the wild the attacker
owns a domain whose authoritative server does exactly this (cf. CVE-2024-24759,
MindsDB DNS rebinding).
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from dnslib import A, QTYPE, RR, RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSServer

ZONE = "rebind.lab"
SAFE_IP = os.environ.get("REBIND_SAFE_IP", "1.1.1.1")           # only validated, never connected
INTERNAL_IP = os.environ.get("REBIND_INTERNAL_IP", "169.254.169.254")
UPSTREAM = os.environ.get("REBIND_UPSTREAM", "127.0.0.11")      # Docker embedded resolver

_state = {"count": 0, "log": []}
_lock = threading.Lock()


class RebindResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        if qname == ZONE:
            if qtype == "A":
                with _lock:
                    _state["count"] += 1
                    n = _state["count"]
                    ip = SAFE_IP if n == 1 else INTERNAL_IP
                    _state["log"].append(f"A query #{n} -> {ip}")
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=0))
            # AAAA / other types for rebind.lab: empty NOERROR (prevents retries)
            return reply

        # Everything else: forward to the embedded resolver so the lab still works.
        try:
            raw = DNSRecord.question(qname, qtype).send(UPSTREAM, 53, timeout=3)
            forwarded = DNSRecord.parse(raw)
            forwarded.header.id = request.header.id
            return forwarded
        except Exception:
            reply.header.rcode = RCODE.SERVFAIL
            return reply


class Control(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/reset":
            with _lock:
                _state["count"] = 0
                _state["log"].clear()
            self._send("reset ok\n")
        elif self.path == "/log":
            with _lock:
                self._send(("\n".join(_state["log"]) + "\n") if _state["log"] else "(no queries yet)\n")
        else:  # / or /state
            with _lock:
                self._send(f"rebind.lab DNS (lab-only). count={_state['count']} "
                           f"safe={SAFE_IP} internal={INTERNAL_IP}\n")

    def log_message(self, *args):  # silence default logging
        return


if __name__ == "__main__":
    dns = DNSServer(RebindResolver(), port=53, address="0.0.0.0")
    dns.start_thread()
    HTTPServer(("0.0.0.0", 80), Control).serve_forever()
