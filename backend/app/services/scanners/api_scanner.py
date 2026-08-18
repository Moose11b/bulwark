"""
OpenAPI-driven API scanner.

Modern targets are mostly APIs, and an API's biggest risks are authorization
ones that a blind crawler can't reason about: it has no way to know that
`GET /accounts/{id}` is supposed to require a token. The spec does. This
scanner uses the spec as an oracle — it reads which operations are declared as
secured and then checks whether the running service actually enforces that.

Checks (all read-only by default):

  1. Broken authentication (OWASP API2 / CWE-306)
     A spec-secured operation that answers 2xx to an UNauthenticated request
     is not enforcing the auth it advertises.

  2. Broken object-level authorization / BOLA (OWASP API1 / CWE-639)
     The same, but for an operation keyed on an object identifier
     (`/users/{id}`) that returns a body — the highest-impact API flaw, so it
     is escalated in severity.

  3. Improper error handling / injection surface (OWASP API8 / CWE-209)
     Bounded fuzzing of query parameters with edge-case values; a 5xx or a
     leaked stack trace means unhandled input reaches the backend.

Safety:
  - Only GET/HEAD/OPTIONS are sent unless writes are explicitly enabled, so a
    scan never mutates data by default.
  - Every request is pinned to the validated target IP (SSRF), and the spec's
    declared host is ignored entirely — only its path templates are used.
  - Endpoint count, concurrency, request timeout, and response body size are
    all bounded, because the spec and the target are both untrusted.
"""
from __future__ import annotations

import asyncio
import re

import structlog

from app.services.scanners.availability import empty_or_demo, fallback, unavailable
from app.services.scanners.openapi_parser import (
    Operation,
    ParsedSpec,
    SpecParseError,
    load_spec_document,
    parse_spec,
)

logger = structlog.get_logger()

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Bounds — the spec and the target are both untrusted input.
MAX_ENDPOINTS = 150
CONCURRENCY = 10
REQUEST_TIMEOUT = 10
MAX_BODY_BYTES = 256_000
MAX_SPEC_BYTES = 5_000_000

# Common locations a running service publishes its spec at, tried in order for
# auto-discovery when no spec is supplied.
DISCOVERY_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/openapi.json",
    "/api/swagger.json", "/swagger/v1/swagger.json", "/docs/openapi.json",
)

# Edge-case query values for the fuzzing check. All benign — the goal is to
# reach an unhandled code path, not to exploit one.
_FUZZ_VALUES = (
    "'",                       # breaks naive SQL string building
    '"><x>',                   # reflection / naive templating
    "../../../../etc/passwd",  # path traversal marker
    "-1",                      # boundary for numeric ids
    "A" * 4096,                # length / buffer handling
    "%00",                     # null byte
)

# Signatures of a leaked stack trace or backend error in a response body.
_ERROR_SIGNATURES = re.compile(
    r"(traceback \(most recent call last\)|"
    r"sqlstate|ora-\d{5}|psqlexception|"
    r"java\.lang\.[a-z]|at [a-z0-9_.]+\([a-z0-9_]+\.java:\d+\)|"
    r"system\.[a-z.]+exception|"
    r"nullpointerexception|undefined index|call to a member function|"
    r"stack trace:|\.rb:\d+:in )",
    re.IGNORECASE,
)


class OpenAPIScanner:
    """Active API security checks driven by an OpenAPI/Swagger spec."""

    def __init__(self, *, spec_source: str | None = None,
                 allow_private: bool = False, include_writes: bool = False):
        self.spec_source = spec_source
        self.allow_private = allow_private
        self.include_writes = include_writes

    async def scan(self, target: str, pinned_ip: str | None = None,
                   port: int | None = None) -> list[dict]:
        hostname = re.sub(r"^https?://", "", target).split("/")[0]
        scheme = "https" if port in (None, 443) else "http"
        authority = f"{hostname}:{port}" if port else hostname
        origin = f"{scheme}://{authority}"

        from app.core.pinned_connection import pinned_async_client

        # ── Load the spec ────────────────────────────────────────
        try:
            spec, spec_origin = await self._load_spec(hostname, pinned_ip, origin)
        except SpecParseError as e:
            return [unavailable(
                "OpenAPI", "api_scanner",
                f"The provided API spec could not be parsed: {e}",
                "Point --api-spec at a valid OpenAPI 3.x or Swagger 2.0 "
                "document (JSON or YAML).",
            )]

        if spec is None:
            # Couldn't run: no spec given and none discoverable. Report the gap
            # honestly (or demo fixtures if demo mode is on) rather than
            # silently running no API checks.
            return fallback(
                "OpenAPI", "api_scanner",
                "No API spec was supplied and none was found at the usual "
                "locations on the target.",
                "Pass --api-spec <file-or-url> to enable API scanning.",
                self._demo_results,
            )

        base = (origin + spec.base_path).rstrip("/")
        testable = self._testable_operations(spec)
        logger.info(
            "api_scanner.spec_loaded", title=spec.title, version=spec.version,
            source=spec_origin, operations=len(spec.operations),
            testable=len(testable),
        )

        findings: list[dict] = []
        sem = asyncio.Semaphore(CONCURRENCY)

        async def run_op(op: Operation):
            async with sem:
                async with pinned_async_client(
                    hostname, pinned_ip,
                    follow_redirects=False,       # a 3xx to /login = auth works
                    timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": "Bulwark-Scanner/2.0"},
                ) as client:
                    return await self._check_operation(client, base, op)

        results = await asyncio.gather(
            *(run_op(op) for op in testable), return_exceptions=True
        )
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return empty_or_demo(findings, "api_scanner", self._demo_results)

    # ── Spec loading ─────────────────────────────────────────────

    async def _load_spec(self, hostname, pinned_ip, origin) -> tuple[ParsedSpec | None, str]:
        """Return (ParsedSpec | None, source-description).

        Order: explicit --api-spec (file or URL), else auto-discovery against
        the target. A None spec with no error means nothing was found.
        """
        if self.spec_source:
            text = await self._read_source(self.spec_source, hostname, pinned_ip)
            return parse_spec(load_spec_document(text)), self.spec_source

        # Auto-discovery: try each well-known path; first that parses wins.
        from app.core.pinned_connection import pinned_async_client
        async with pinned_async_client(
            hostname, pinned_ip, timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Bulwark-Scanner/2.0"},
        ) as client:
            for path in DISCOVERY_PATHS:
                try:
                    text = await self._read_url(client, f"{origin}{path}")
                    if not text:
                        continue
                    spec = parse_spec(load_spec_document(text))
                    if spec.operations:
                        return spec, f"{origin}{path}"
                except Exception:
                    continue
        return None, ""

    async def _read_source(self, source: str, hostname, pinned_ip) -> str:
        """Read a spec from a local file path or a URL (SSRF-validated)."""
        if re.match(r"^https?://", source):
            from app.core.target_validation import (
                validate_target_pinned, TargetValidationError,
            )
            from app.core.pinned_connection import pinned_async_client
            try:
                v = validate_target_pinned(source, allow_private=self.allow_private)
            except TargetValidationError as e:
                raise SpecParseError(f"spec URL rejected ({e})")
            spec_authority = f"{v.host}:{v.port}" if v.port else v.host
            spec_scheme = "https" if v.port in (None, 443) else "http"
            spec_path = re.sub(r"^https?://[^/]+", "", source) or "/"
            async with pinned_async_client(
                v.host, v.pinned_ip, timeout=REQUEST_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": "Bulwark-Scanner/2.0"},
            ) as client:
                text = await self._read_url(
                    client, f"{spec_scheme}://{spec_authority}{spec_path}"
                )
            if not text:
                raise SpecParseError(f"spec URL returned no usable body: {source}")
            return text

        # Local file. Bounded read so a huge/hostile file can't exhaust memory.
        try:
            with open(source, "rb") as fh:
                data = fh.read(MAX_SPEC_BYTES + 1)
        except OSError as e:
            raise SpecParseError(f"could not read spec file {source}: {e}")
        if len(data) > MAX_SPEC_BYTES:
            raise SpecParseError(f"spec file exceeds {MAX_SPEC_BYTES} bytes: {source}")
        return data.decode("utf-8", errors="replace")

    async def _read_url(self, client, url: str) -> str:
        """Stream a URL body, capped, returning "" on any non-200 or oversize."""
        try:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return ""
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_SPEC_BYTES:
                        return ""
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception:
            return ""

    # ── Operation selection ──────────────────────────────────────

    def _testable_operations(self, spec: ParsedSpec) -> list[Operation]:
        ops = []
        for op in spec.operations:
            if op.method not in SAFE_METHODS and not self.include_writes:
                continue
            ops.append(op)
        if len(ops) > MAX_ENDPOINTS:
            logger.info("api_scanner.truncated", total=len(ops), cap=MAX_ENDPOINTS)
            ops = ops[:MAX_ENDPOINTS]
        return ops

    # ── Per-operation checks ─────────────────────────────────────

    async def _check_operation(self, client, base: str, op: Operation) -> list[dict]:
        findings: list[dict] = []
        url = base + _fill_path(op.path, op)

        # Check 1 & 2: does a spec-secured op enforce auth?
        if op.secured:
            f = await self._check_auth_enforced(client, url, op)
            if f:
                findings.append(f)

        # Check 3: bounded query-parameter fuzzing (GET only, read-only).
        if op.method == "GET" and op.query_params:
            f = await self._fuzz_query_params(client, url, op)
            if f:
                findings.append(f)

        return findings

    async def _check_auth_enforced(self, client, url: str, op: Operation) -> dict | None:
        try:
            resp = await client.request(op.method, url)
        except Exception:
            return None

        # 2xx to an unauthenticated request against a spec-secured endpoint is
        # the finding. 401/403 = enforced (good). 3xx = redirect to login,
        # treated as enforced. 404/405/400 = inconclusive (skip).
        if not (200 <= resp.status_code < 300):
            return None

        body = await _read_capped_body(resp)
        endpoint = f"{op.method} {op.path}"

        if op.is_object_lookup and body.strip():
            return {
                "title": f"Broken object-level authorization: {endpoint}",
                "source": "api_scanner",
                "severity": "CRITICAL",
                "cwe_id": "CWE-639",
                "owasp_category": "A01",
                "killchain_phase": "exploitation",
                "mitre_technique_id": "T1190",
                "description": (
                    f"The spec marks {endpoint} as requiring authentication, but "
                    f"an unauthenticated request returned {resp.status_code} with "
                    f"a response body. Because the endpoint is keyed on an object "
                    f"identifier, any object may be readable without "
                    f"authorization (BOLA / IDOR)."
                ),
                "evidence": f"Unauthenticated {op.method} {url} -> {resp.status_code} "
                            f"({len(body)} bytes returned)",
                "remediation": (
                    "Enforce authentication and per-object authorization on this "
                    "endpoint: verify the caller is allowed to access the specific "
                    "object id, not merely authenticated."
                ),
                "references": [
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                ],
            }

        return {
            "title": f"Authentication not enforced: {endpoint}",
            "source": "api_scanner",
            "severity": "HIGH",
            "cwe_id": "CWE-306",
            "owasp_category": "A07",
            "killchain_phase": "exploitation",
            "mitre_technique_id": "T1190",
            "description": (
                f"The API spec declares {endpoint} as secured, but an "
                f"unauthenticated request returned {resp.status_code}. The "
                f"advertised authentication is not being enforced."
            ),
            "evidence": f"Unauthenticated {op.method} {url} -> {resp.status_code}",
            "remediation": (
                "Enforce the declared security scheme on this endpoint at the "
                "gateway or application layer; reject requests without a valid "
                "credential with 401."
            ),
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            ],
        }

    async def _fuzz_query_params(self, client, url: str, op: Operation) -> dict | None:
        """Send edge-case values through query params; flag 5xx / stack traces.

        One finding per endpoint (the first payload that trips it), so a broadly
        fragile endpoint is reported once rather than six times.
        """
        for param in op.query_params:
            for payload in _FUZZ_VALUES:
                try:
                    resp = await client.request(
                        op.method, url, params={param.name: payload}
                    )
                except Exception:
                    continue

                if resp.status_code >= 500:
                    return self._error_finding(
                        op, url, param.name, payload, resp.status_code,
                        "returned a server error",
                    )
                body = await _read_capped_body(resp)
                if _ERROR_SIGNATURES.search(body):
                    return self._error_finding(
                        op, url, param.name, payload, resp.status_code,
                        "leaked a backend error / stack trace",
                    )
        return None

    def _error_finding(self, op, url, param, payload, status, what) -> dict:
        endpoint = f"{op.method} {op.path}"
        safe_payload = payload if len(payload) <= 40 else payload[:37] + "..."
        return {
            "title": f"Improper error handling: {endpoint}",
            "source": "api_scanner",
            "severity": "MEDIUM",
            "cwe_id": "CWE-209",
            "owasp_category": "A05",
            "killchain_phase": "exploitation",
            "mitre_technique_id": "T1190",
            "description": (
                f"An edge-case value in the '{param}' parameter of {endpoint} "
                f"{what} (HTTP {status}). Unhandled input reaching the backend "
                f"indicates missing input validation and can leak internal "
                f"details or signal an injection point."
            ),
            "evidence": f"{op.method} {url}?{param}={safe_payload} -> {status}",
            "remediation": (
                "Validate and coerce input against the declared schema, and "
                "return a generic error without internal details on failure."
            ),
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            ],
        }

    def _demo_results(self) -> list[dict]:
        return [
            {
                "title": "Authentication not enforced: GET /api/users/{id}",
                "source": "api_scanner", "severity": "HIGH",
                "cwe_id": "CWE-306", "owasp_category": "A07",
                "killchain_phase": "exploitation", "mitre_technique_id": "T1190",
                "description": "Demo — spec-secured endpoint answered 200 to an "
                               "unauthenticated request.",
                "evidence": "Demo — unauthenticated GET returned 200",
                "remediation": "Enforce the declared security scheme.",
                "references": [],
            },
        ]


# ── Module helpers ───────────────────────────────────────────────

def _fill_path(template: str, op: Operation) -> str:
    """Replace {param} placeholders with safe, plausible values.

    Integers/ids get "1" (a plausible first object, which makes the auth check
    meaningful); everything else gets a benign string. Never guesses real
    identifiers.
    """
    types = {p.name: p.type for p in op.path_params}

    def repl(m: re.Match) -> str:
        name = m.group(1)
        return "1" if types.get(name) in ("integer", "number") or \
            name.lower().endswith("id") else "test"

    return re.sub(r"\{([^}]+)\}", repl, template)


async def _read_capped_body(resp) -> str:
    """Best-effort read of an already-sent response body, size-capped."""
    try:
        raw = await resp.aread()
    except Exception:
        return ""
    return raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
