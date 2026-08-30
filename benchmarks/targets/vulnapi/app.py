#!/usr/bin/env python3
"""
VulnAPI — a deliberately-vulnerable REST API for benchmarking.

Purpose: a target whose vulnerabilities are *known in advance* (see
ground_truth.yaml), so a scanner's output can be scored as detection rate
against ground truth rather than compared blindly against another tool's raw
count. Neither Bulwark's count nor ZAP's count is "truth"; the planted list is.

It is written against the Python standard library only — no framework, no pip
install — so it runs anywhere (`python3 app.py`) and starts in milliseconds,
which keeps the benchmark cheap and reproducible.

Every vulnerability here is intentional. Do not deploy this. It binds to
127.0.0.1 by default.

Planted issues (see ground_truth.yaml for the authoritative list):
  * GET /api/users/{id}      spec says secured, returns object data unauth  → BOLA (API1/A01)
  * GET /api/admin/config    spec says secured, returns 200 unauth          → broken auth (API2/A07)
  * GET /api/search?q=       unhandled quote triggers a 500 + stack trace   → error handling (A05/API8)
  * missing security headers on every response                             → misconfig (A05)

Control (must NOT be flagged — a finding here is a false positive):
  * GET /api/account/{id}    spec says secured, returns 401 unauth          → properly enforced
"""
import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_spec() -> bytes:
    with open(os.path.join(HERE, "openapi.yaml"), "rb") as fh:
        return fh.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnAPI/1.0"

    def log_message(self, *args):
        pass  # quiet by default; the benchmark captures scanner output instead

    # Deliberately omits every security header — a real misconfiguration that
    # both Bulwark's header scanner and ZAP's passive rules should report.
    def _respond(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _has_auth(self) -> bool:
        return bool(self.headers.get("Authorization"))

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        if path in ("/openapi.yaml", "/openapi.json"):
            return self._respond(200, _load_spec(), "text/yaml")

        if path == "/health":
            return self._respond(200, b'{"status":"ok"}')

        # PLANTED: BOLA — spec marks this secured, but it never checks auth and
        # returns the object regardless.
        if path.startswith("/api/users/"):
            uid = path.rsplit("/", 1)[-1]
            return self._respond(200, json.dumps({
                "id": uid, "email": f"user{uid}@example.com",
                "role": "customer", "ssn": "000-00-0000",
            }).encode())

        # PLANTED: broken authentication — sensitive admin endpoint, spec marks
        # it secured, but it answers 200 to anyone.
        if path == "/api/admin/config":
            return self._respond(200, json.dumps({
                "debug": True, "db_dsn": "postgres://admin:hunter2@db/prod",
                "feature_flags": {"unsafe_eval": True},
            }).encode())

        # PLANTED: improper error handling — a quote in `q` reaches a naive
        # backend and throws, leaking a stack trace.
        if path == "/api/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            if "'" in q or '"' in q:
                trace = (
                    "Traceback (most recent call last):\n"
                    '  File "/srv/app/search.py", line 42, in run_query\n'
                    "    cur.execute(\"SELECT * FROM items WHERE name = '\" + q + \"'\")\n"
                    "psycopg2.errors.SyntaxError: syntax error at or near \"'\"\n"
                )
                return self._respond(500, trace.encode(), "text/plain")
            return self._respond(200, b'{"results":[]}')

        # CONTROL: properly enforced — returns 401 without a credential. A
        # scanner that flags this is producing a false positive.
        if path.startswith("/api/account/"):
            if not self._has_auth():
                return self._respond(401, b'{"error":"authentication required"}')
            return self._respond(200, b'{"id":"me","balance":0}')

        return self._respond(404, b'{"error":"not found"}')


def main():
    ap = argparse.ArgumentParser(description="Deliberately-vulnerable benchmark API")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("VULNAPI_PORT", "8000")))
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"VulnAPI listening on http://{args.host}:{args.port} — DO NOT deploy.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
