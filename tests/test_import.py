"""
Scan import: Bulwark native JSON and SARIF → findings, under an engagement.
"""
import importlib
import io
import json

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "imp.db"))
    monkeypatch.setenv("SIEGE_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec; importlib.reload(sec)
    import server.db as db; importlib.reload(db)
    import server.app as app_mod; importlib.reload(app_mod)
    with TestClient(app_mod.app) as c:
        yield c


def _auth(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    return {"Authorization": "Bearer " + r.json()["token"]}


BULWARK = {
    "target": "https://acme.example.com",
    "profile": "web",
    "findings": [
        {"title": "Missing Strict-Transport-Security header", "severity": "MEDIUM",
         "description": "HSTS not set.", "remediation": "Add HSTS.",
         "source": "headers", "owasp_category": "A05", "cwe_id": 319,
         "references": ["https://owasp.org/hsts"]},
        {"title": "Outdated OpenSSL (CVE-2022-0778)", "severity": "HIGH",
         "description": "Vulnerable TLS lib.", "cve_id": "CVE-2022-0778",
         "cvss_score": 7.5, "source": "tls"},
    ],
}

SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Bulwark", "rules": [
            {"id": "bulwark/headers/CWE-319", "shortDescription": {"text": "Cleartext transmission"},
             "fullDescription": {"text": "Sensitive data over HTTP."},
             "help": {"text": "Use TLS."}, "helpUri": "https://example/help",
             "properties": {"security-severity": "6.5"}},
        ]}},
        "results": [
            {"ruleId": "bulwark/headers/CWE-319", "level": "warning",
             "message": {"text": "Cleartext transmission of sensitive data"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://acme.example.com/login"}}}],
             "properties": {"severity": "MEDIUM", "source": "headers"}},
        ],
        "properties": {"target": "https://acme.example.com"},
    }],
}


def _import(client, h, eid, payload, name="scan.json"):
    return client.post("/api/imports", headers=h,
                       data={"engagement_id": eid},
                       files={"file": (name, json.dumps(payload).encode(), "application/json")})


def test_import_bulwark_json(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    r = _import(client, h, eid, BULWARK)
    assert r.status_code == 201, r.text
    assert r.json()["source"] == "bulwark"
    assert r.json()["imported"] == 2

    findings = client.get("/api/findings", headers=h, params={"engagement_id": eid}).json()["findings"]
    by_title = {f["title"]: f for f in findings}
    hsts = by_title["Missing Strict-Transport-Security header"]
    assert hsts["severity"] == "medium"
    assert hsts["cwe"] == "CWE-319"
    assert "https://acme.example.com" in hsts["affected_assets"]
    tls = by_title["Outdated OpenSSL (CVE-2022-0778)"]
    assert tls["severity"] == "high" and tls["cvss_score"] == 7.5
    assert "CVE-2022-0778" in tls["references"]


def test_import_sarif(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    r = _import(client, h, eid, SARIF, name="results.sarif")
    assert r.status_code == 201, r.text
    assert r.json()["source"] == "sarif" and r.json()["imported"] == 1
    f = client.get("/api/findings", headers=h, params={"engagement_id": eid}).json()["findings"][0]
    assert f["severity"] == "medium"
    assert f["cvss_score"] == 6.5   # from security-severity
    assert "https://acme.example.com/login" in f["affected_assets"]


def test_import_dedupes(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    dupe = {"target": "t", "findings": [
        {"title": "Same", "severity": "LOW"}, {"title": "Same", "severity": "LOW"}]}
    r = _import(client, h, eid, dupe)
    assert r.json()["imported"] == 1


def test_import_rejects_garbage(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    r = client.post("/api/imports", headers=h, data={"engagement_id": eid},
                    files={"file": ("x.json", b"{\"nope\": 1}", "application/json")})
    assert r.status_code == 400


def test_import_requires_auth(client):
    r = client.post("/api/imports", data={"engagement_id": "x"},
                    files={"file": ("x.json", b"{}", "application/json")})
    assert r.status_code == 401
