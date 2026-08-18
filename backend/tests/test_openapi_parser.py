"""
OpenAPI / Swagger spec parsing.

Pure, network-free. The parser decides which endpoints get probed and whether
each is treated as "should be authenticated", so a mistake here silently
changes what the scanner tests — exactly the kind of thing that must be pinned
down by unit tests rather than noticed in an end-to-end run.
"""
import pytest

from app.services.scanners.openapi_parser import (
    SpecParseError,
    load_spec_document,
    parse_spec,
)

OAS3 = {
    "openapi": "3.0.1",
    "info": {"title": "Widget API"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "security": [{"bearerAuth": []}],          # secured by default
    "components": {
        "parameters": {
            "IdParam": {
                "name": "id", "in": "path", "required": True,
                "schema": {"type": "integer"},
            }
        }
    },
    "paths": {
        "/widgets": {
            "get": {                            # inherits top-level security
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                ],
            },
            "post": {"security": [{"bearerAuth": []}]},
        },
        "/widgets/{id}": {
            "get": {
                "parameters": [{"$ref": "#/components/parameters/IdParam"}],
            }
        },
        "/health": {
            "get": {"security": []},            # explicitly public
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy API"},
    "basePath": "/api",
    "security": [{"apiKey": []}],
    "paths": {
        "/orders/{orderId}": {
            "get": {
                "parameters": [
                    {"name": "orderId", "in": "path", "required": True, "type": "string"}
                ]
            }
        },
        "/ping": {"get": {"security": []}},
    },
}


def test_openapi3_shapes_and_security():
    spec = parse_spec(OAS3)
    assert spec.version == "openapi-3"
    assert spec.base_path == "/v2"           # host stripped, path kept
    assert spec.title == "Widget API"

    ops = {(o.method, o.path): o for o in spec.operations}
    assert ops[("GET", "/widgets")].secured is True         # inherited
    assert ops[("POST", "/widgets")].secured is True
    assert ops[("GET", "/widgets/{id}")].secured is True
    assert ops[("GET", "/health")].secured is False         # security: []


def test_openapi3_resolves_ref_and_detects_object_lookup():
    spec = parse_spec(OAS3)
    op = next(o for o in spec.operations if o.path == "/widgets/{id}")
    # $ref parameter resolved to a real integer path param
    assert [(p.name, p.location, p.type) for p in op.path_params] == [("id", "path", "integer")]
    assert op.is_object_lookup is True
    # /widgets has only a query param → not an object lookup
    listing = next(o for o in spec.operations if o.path == "/widgets" and o.method == "GET")
    assert listing.is_object_lookup is False
    assert [p.name for p in listing.query_params] == ["limit"]


def test_swagger2_base_path_and_security():
    spec = parse_spec(SWAGGER2)
    assert spec.version == "swagger-2"
    assert spec.base_path == "/api"
    ops = {(o.method, o.path): o for o in spec.operations}
    assert ops[("GET", "/orders/{orderId}")].secured is True
    assert ops[("GET", "/orders/{orderId}")].is_object_lookup is True   # name ends with 'id'
    assert ops[("GET", "/ping")].secured is False


def test_server_host_is_ignored_only_path_kept():
    # An attacker-controlled spec must not be able to redirect the scanner via
    # the server URL; we only ever keep the path component.
    spec = parse_spec({
        "openapi": "3.0.0", "info": {"title": "x"},
        "servers": [{"url": "https://169.254.169.254/internal"}],
        "paths": {},
    })
    assert spec.base_path == "/internal"
    assert "169.254" not in spec.base_path


def test_load_document_json_and_yaml():
    assert load_spec_document('{"openapi":"3.0.0","paths":{}}')["openapi"] == "3.0.0"
    yaml_doc = load_spec_document("openapi: 3.0.0\npaths: {}\n")
    assert yaml_doc["openapi"] == "3.0.0"


def test_unrecognised_and_malformed_specs_raise():
    with pytest.raises(SpecParseError):
        parse_spec({"paths": {}})               # no openapi/swagger key
    with pytest.raises(SpecParseError):
        load_spec_document("")                  # empty
    with pytest.raises(SpecParseError):
        load_spec_document("[1, 2, 3]")         # not an object


def test_security_empty_list_document_default_is_public():
    # No top-level security and none per-op → nothing is treated as secured.
    spec = parse_spec({
        "openapi": "3.0.0", "info": {"title": "x"},
        "paths": {"/open": {"get": {}}},
    })
    assert spec.operations[0].secured is False
