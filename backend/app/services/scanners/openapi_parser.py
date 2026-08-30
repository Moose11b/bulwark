"""
OpenAPI / Swagger spec parsing.

The spec is the thing that makes API scanning better than blind crawling: it
declares every endpoint, its parameters, and — crucially — which endpoints are
supposed to require authentication. A generic scanner has no way to know that
`GET /users/{id}` is meant to be protected; the spec says so outright, which
turns "should this be public?" from a guess into a check.

This module is deliberately pure — it takes a parsed document (dict) and
returns a normalised, network-free model. All the active probing lives in
api_scanner.py, so this half is trivially unit-testable.

Two input dialects are supported:
  - OpenAPI 3.x  (openapi: 3.x.x, `servers`, `components.securitySchemes`)
  - Swagger 2.0  (swagger: "2.0", `basePath`/`host`, `securityDefinitions`)

Security note: the spec's declared host/servers are NEVER used to decide what
to connect to — a spec is untrusted input and could name an internal host to
turn the scanner into an SSRF tool. Only the URL *path* component of a server
is taken (as a base path); the host always comes from the validated scan
target. See `base_path`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# HTTP methods that can appear as operation keys under a path item.
_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

# Path/query parameter names that name an object identifier. An endpoint keyed
# on one of these is a Broken-Object-Level-Authorization (BOLA) candidate: the
# id is the access-control boundary, so "reachable without auth" is worse here.
_ID_PARAM_HINTS = ("id", "uuid", "guid", "slug", "key", "ref", "number", "no")


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str          # "path" | "query" | "header" | "cookie" | "body"
    type: str              # coarse JSON-schema type: integer/string/... or ""
    required: bool


@dataclass(frozen=True)
class Operation:
    method: str            # upper-case: GET, POST, ...
    path: str              # template as written in the spec, e.g. /users/{id}
    secured: bool          # does the effective security make auth mandatory?
    parameters: tuple[Parameter, ...] = ()
    operation_id: str = ""
    summary: str = ""

    @property
    def path_params(self) -> tuple[Parameter, ...]:
        return tuple(p for p in self.parameters if p.location == "path")

    @property
    def query_params(self) -> tuple[Parameter, ...]:
        return tuple(p for p in self.parameters if p.location == "query")

    @property
    def is_object_lookup(self) -> bool:
        """True when a path parameter looks like an object identifier."""
        for p in self.path_params:
            low = p.name.lower()
            if p.type in ("integer", "number"):
                return True
            if any(h == low or low.endswith(h) or low.endswith("_" + h) for h in _ID_PARAM_HINTS):
                return True
        return False


@dataclass(frozen=True)
class ParsedSpec:
    version: str                       # "openapi-3" | "swagger-2"
    base_path: str                     # path-only, host stripped; e.g. "/api/v1"
    title: str
    operations: tuple[Operation, ...] = field(default=())


class SpecParseError(ValueError):
    """The document is not a spec we can parse. Fails loudly rather than
    silently scanning nothing."""


def load_spec_document(text: str) -> dict:
    """Parse spec text (JSON or YAML) into a dict.

    JSON is tried first (it is also valid YAML but far cheaper to parse); YAML
    is the fallback so `.yaml` specs work too.
    """
    text = text.strip()
    if not text:
        raise SpecParseError("Spec is empty.")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
            doc = yaml.safe_load(text)
        except Exception as e:            # yaml.YAMLError or ImportError
            raise SpecParseError(f"Spec is neither valid JSON nor YAML: {e}")
    if not isinstance(doc, dict):
        raise SpecParseError("Spec root is not an object.")
    return doc


def parse_spec(doc: dict) -> ParsedSpec:
    """Normalise an OpenAPI 3.x or Swagger 2.0 document into a ParsedSpec."""
    if not isinstance(doc, dict):
        raise SpecParseError("Spec root is not an object.")

    if str(doc.get("openapi", "")).startswith("3"):
        return _parse_openapi3(doc)
    if str(doc.get("swagger", "")).startswith("2"):
        return _parse_swagger2(doc)
    raise SpecParseError(
        "Unrecognised spec: expected 'openapi: 3.x' or 'swagger: 2.0'."
    )


# ── OpenAPI 3.x ──────────────────────────────────────────────────

def _parse_openapi3(doc: dict) -> ParsedSpec:
    info = doc.get("info") or {}
    title = str(info.get("title") or "API")

    # Only the path component of the first server is used; the host is ignored
    # on purpose (SSRF — see module docstring).
    base_path = ""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base_path = _path_of(str(servers[0].get("url") or ""))

    top_security = doc.get("security")
    operations: list[Operation] = []
    paths = doc.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = _resolve_params(item.get("parameters"), doc)
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = shared + _resolve_params(op.get("parameters"), doc)
            operations.append(Operation(
                method=method.upper(),
                path=str(path),
                secured=_is_secured(op.get("security"), top_security),
                parameters=tuple(_dedupe_params(params)),
                operation_id=str(op.get("operationId") or ""),
                summary=str(op.get("summary") or ""),
            ))
    return ParsedSpec("openapi-3", base_path, title, tuple(operations))


# ── Swagger 2.0 ──────────────────────────────────────────────────

def _parse_swagger2(doc: dict) -> ParsedSpec:
    info = doc.get("info") or {}
    title = str(info.get("title") or "API")
    base_path = _path_of(str(doc.get("basePath") or ""))

    top_security = doc.get("security")
    operations: list[Operation] = []
    paths = doc.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = _resolve_params(item.get("parameters"), doc)
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = shared + _resolve_params(op.get("parameters"), doc)
            operations.append(Operation(
                method=method.upper(),
                path=str(path),
                secured=_is_secured(op.get("security"), top_security),
                parameters=tuple(_dedupe_params(params)),
                operation_id=str(op.get("operationId") or ""),
                summary=str(op.get("summary") or ""),
            ))
    return ParsedSpec("swagger-2", base_path, title, tuple(operations))


# ── Shared helpers ───────────────────────────────────────────────

def _path_of(url: str) -> str:
    """Return the path component of a server/base URL, host discarded.

    Accepts a full URL ("https://api.example.com/v1"), a scheme-relative
    ("//host/v1"), or a bare path ("/v1"). Trailing slash trimmed.
    """
    if not url:
        return ""
    path = urlsplit(url).path if ("://" in url or url.startswith("//")) else url
    path = path.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path
    return path


def _is_secured(op_security, top_security) -> bool:
    """Decide whether an operation requires authentication.

    Operation-level `security` overrides the top-level default. An explicit
    empty list (`security: []`) means "public" and overrides a secured default
    — this is exactly how a spec marks a login or health endpoint as open.
    """
    effective = op_security if op_security is not None else top_security
    if not effective:                       # None or []
        return False
    # A non-empty requirement list with at least one non-empty requirement
    # object means auth is expected.
    return any(req for req in effective if req)


def _resolve_params(raw, doc: dict) -> list[Parameter]:
    """Turn a raw `parameters` list into Parameter objects, resolving local
    `$ref`s (e.g. #/components/parameters/Foo or #/parameters/Foo)."""
    if not isinstance(raw, list):
        return []
    out: list[Parameter] = []
    for p in raw:
        if isinstance(p, dict) and "$ref" in p:
            p = _resolve_ref(p["$ref"], doc) or {}
        if not isinstance(p, dict) or not p.get("name"):
            continue
        # Type lives under `schema.type` in OAS3, directly under `type` in
        # Swagger 2.0.
        schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
        ptype = str(schema.get("type") or p.get("type") or "")
        out.append(Parameter(
            name=str(p["name"]),
            location=str(p.get("in") or "query"),
            type=ptype,
            required=bool(p.get("required", p.get("in") == "path")),
        ))
    return out


def _resolve_ref(ref: str, doc: dict):
    """Resolve a local JSON-pointer ref within the same document.

    Only same-document refs (`#/...`) are supported; external refs are skipped
    (returns None) rather than fetched, since fetching an attacker-named URL
    would be an SSRF vector.
    """
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")   # JSON-pointer unescape
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _dedupe_params(params: list[Parameter]) -> list[Parameter]:
    """Operation params override path-level params with the same name+location
    (per the spec). Later entries win."""
    seen: dict[tuple[str, str], Parameter] = {}
    for p in params:
        seen[(p.name, p.location)] = p
    return list(seen.values())
