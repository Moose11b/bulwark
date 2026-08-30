"""
OpenAPI scanner active checks, end-to-end against a live mock API.

A real HTTP server (loopback) stands in for the target so the scanner exercises
its actual request/response path — pinned client, status interpretation, body
reading — not a mocked-out httpx. The mock is deliberately vulnerable in the
exact ways the checks look for, and safe in the ways they must not false-positive
on.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

import pytest

from app.services.scanners.api_scanner import OpenAPIScanner

# A spec that declares four secured endpoints and one public one. The mock
# below enforces auth on only ONE of them, which is what the scanner should
# catch.
SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Mock API"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/secure-open": {"get": {}},                       # secured, NOT enforced
        "/secure-closed": {"get": {}},                     # secured, enforced (401)
        "/users/{id}": {                                   # secured, BOLA
            "get": {"parameters": [
                {"name": "id", "in": "path", "required": True,
                 "schema": {"type": "integer"}}
            ]},
        },
        "/public": {"get": {"security": []}},              # public, ignored
        "/search": {                                       # public, fuzzable
            "get": {"security": [], "parameters": [
                {"name": "q", "in": "query", "schema": {"type": "string"}}
            ]},
        },
        "/admin/purge": {"post": {}},                      # write — must be skipped
    },
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _record(self):
        self.server.requests.append((self.command, urlsplit(self.path).path))

    def do_GET(self):
        self._record()
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/openapi.json":
            return self._send(200, json.dumps(SPEC).encode())
        if path == "/secure-open":
            return self._send(200, b'{"data":"leaked without a token"}')
        if path.startswith("/users/"):
            return self._send(200, b'{"id":1,"name":"Alice","ssn":"redacted"}')
        if path == "/secure-closed":
            return self._send(401, b'{"error":"unauthorized"}')
        if path == "/public":
            return self._send(200, b'{"ok":true}')
        if path == "/search":
            q = parse_qs(parsed.query).get("q", [""])[0]
            if "'" in q:                      # naive backend chokes on a quote
                return self._send(
                    500,
                    b"Traceback (most recent call last):\n  File 'app.py'\n"
                    b"psycopg2.errors.SyntaxError: syntax error at or near",
                )
            return self._send(200, b'{"results":[]}')
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        self._record()
        self._send(200, b'{}')


@pytest.fixture
def mock_api():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.requests = []
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server, server.server_address[1]
    finally:
        server.shutdown()


def _by_title(findings):
    return {f["title"]: f for f in findings}


async def _scan(port, spec_file):
    scanner = OpenAPIScanner(spec_source=spec_file, allow_private=True)
    return await scanner.scan("127.0.0.1", pinned_ip="127.0.0.1", port=port)


async def test_finds_auth_bola_and_error_handling(mock_api, tmp_path):
    server, port = mock_api
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(SPEC))

    findings = await _scan(port, str(spec_file))
    titles = _by_title(findings)

    # Broken auth on the endpoint that doesn't enforce it
    assert "Authentication not enforced: GET /secure-open" in titles
    assert titles["Authentication not enforced: GET /secure-open"]["severity"] == "HIGH"
    assert titles["Authentication not enforced: GET /secure-open"]["cwe_id"] == "CWE-306"

    # BOLA on the object-id endpoint (escalated to critical, returns a body)
    assert "Broken object-level authorization: GET /users/{id}" in titles
    assert titles["Broken object-level authorization: GET /users/{id}"]["severity"] == "CRITICAL"

    # Error handling from param fuzzing
    assert "Improper error handling: GET /search" in titles
    assert titles["Improper error handling: GET /search"]["severity"] == "MEDIUM"


async def test_no_false_positive_on_enforced_or_public(mock_api, tmp_path):
    server, port = mock_api
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(SPEC))

    findings = await _scan(port, str(spec_file))
    titles = _by_title(findings)

    # /secure-closed enforces auth (401) — must NOT be flagged
    assert "Authentication not enforced: GET /secure-closed" not in titles
    # /public is not secured in the spec — never an auth finding
    assert not any("/public" in t for t in titles)


async def test_write_methods_skipped_by_default(mock_api, tmp_path):
    server, port = mock_api
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(SPEC))

    await _scan(port, str(spec_file))

    # Read-only by default: the POST endpoint must never have been requested.
    methods = {m for m, _ in server.requests}
    assert "POST" not in methods
    assert not any(p == "/admin/purge" for _, p in server.requests)


async def test_auto_discovery_from_target(mock_api):
    server, port = mock_api
    # No spec supplied → the scanner should discover /openapi.json on the target.
    scanner = OpenAPIScanner(spec_source=None, allow_private=True)
    findings = await scanner.scan("127.0.0.1", pinned_ip="127.0.0.1", port=port)
    titles = _by_title(findings)
    assert "Broken object-level authorization: GET /users/{id}" in titles
    assert any("/openapi.json" == p for _, p in server.requests)


async def test_unparseable_spec_reports_gap_not_crash(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("this is not a spec")
    scanner = OpenAPIScanner(spec_source=str(bad), allow_private=True)
    findings = await scanner.scan("127.0.0.1", pinned_ip="127.0.0.1", port=1)
    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert "could not be parsed" in findings[0]["description"]
