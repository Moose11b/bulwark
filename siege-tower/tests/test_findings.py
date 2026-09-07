"""
Findings + findings library: CRUD, CVSS auto-scoring, tenancy, and reuse.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "find.db"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec
    importlib.reload(sec)
    import server.db as db
    importlib.reload(db)
    import server.app as app_mod
    importlib.reload(app_mod)
    return app_mod, db


@pytest.fixture()
def client(env):
    app_mod, _ = env
    with TestClient(app_mod.app) as c:
        yield c


def _auth(client, u="admin", p=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_findings_require_auth(client):
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/library").status_code == 401


def test_cvss_endpoint(client):
    h = _auth(client)
    r = client.get("/api/cvss", headers=h,
                   params={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert r.status_code == 200
    assert r.json()["score"] == 9.8 and r.json()["severity"] == "critical"


def test_finding_crud_with_cvss_autoscore(client):
    h = _auth(client)
    # No severity/score given — derived from the CVSS vector.
    r = client.post("/api/findings", headers=h, json={
        "title": "SQL injection in /login",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Boolean-based blind SQLi.",
        "remediation": "Parameterize queries.",
        "technique_ids": ["T1190"],
    })
    assert r.status_code == 201, r.text
    f = r.json()
    assert f["cvss_score"] == 9.8 and f["severity"] == "critical"
    fid = f["id"]

    # Update status (retest workflow).
    up = client.put(f"/api/findings/{fid}", headers=h, json={"status": "fixed"})
    assert up.status_code == 200 and up.json()["status"] == "fixed"

    # Invalid enum rejected.
    assert client.put(f"/api/findings/{fid}", headers=h,
                      json={"severity": "spicy"}).status_code == 400

    got = client.get(f"/api/findings/{fid}", headers=h).json()
    assert got["title"].startswith("SQL injection")

    assert client.delete(f"/api/findings/{fid}", headers=h).status_code == 204
    assert client.get(f"/api/findings/{fid}", headers=h).status_code == 404


def test_finding_scoped_to_engagement(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    client.post("/api/findings", headers=h,
                json={"title": "Finding A", "engagement_id": eid})
    client.post("/api/findings", headers=h, json={"title": "Standalone finding"})
    # Filter by engagement.
    eng_only = client.get("/api/findings", headers=h,
                          params={"engagement_id": eid}).json()["findings"]
    assert len(eng_only) == 1 and eng_only[0]["title"] == "Finding A"
    # All findings.
    assert len(client.get("/api/findings", headers=h).json()["findings"]) == 2
    # Unknown engagement on create is rejected.
    assert client.post("/api/findings", headers=h,
                       json={"title": "x", "engagement_id": "nope"}).status_code == 404


def test_library_reuse_flow(client):
    h = _auth(client)
    # Create a finding, save it to the library, then instantiate a new finding.
    fid = client.post("/api/findings", headers=h, json={
        "title": "Missing HSTS", "severity": "low",
        "remediation": "Add Strict-Transport-Security.",
    }).json()["id"]
    lib = client.post(f"/api/findings/{fid}/save-to-library", headers=h)
    assert lib.status_code == 201
    lid = lib.json()["id"]
    assert lib.json()["title"] == "Missing HSTS"

    listed = client.get("/api/library", headers=h).json()["library"]
    assert any(x["id"] == lid for x in listed)

    inst = client.post(f"/api/library/{lid}/instantiate", headers=h)
    assert inst.status_code == 201
    new_f = inst.json()
    assert new_f["title"] == "Missing HSTS" and new_f["library_id"] == lid
    assert new_f["id"] != fid


def test_library_tenant_isolation(client, env):
    _app, db = env
    h = _auth(client)
    lid = client.post("/api/library", headers=h,
                      json={"title": "Org A template"}).json()["id"]
    org_b = db.create_org("Org B")
    db.create_user(org_b["id"], "bob", "bob-password-123", role="operator")
    hb = _auth(client, "bob", "bob-password-123")
    assert client.get("/api/library", headers=hb).json()["library"] == []
    assert client.get(f"/api/library/{lid}", headers=hb).status_code == 404
