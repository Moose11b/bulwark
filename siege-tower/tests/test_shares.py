"""
Shareable client report links: create, public read, revoke, expiry, tenancy.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "sh.db"))
    monkeypatch.setenv("SIEGE_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec; importlib.reload(sec)
    import server.db as db; importlib.reload(db)
    import server.app as app_mod; importlib.reload(app_mod)
    return app_mod, db


@pytest.fixture()
def client(env):
    with TestClient(env[0].app) as c:
        yield c


def _auth(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def eng(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={
        "name": "ACME Assessment", "client": "ACME", "objective": "domain_admin"}).json()["id"]
    client.post("/api/findings", headers=h, json={
        "title": "SQLi", "engagement_id": eid, "severity": "critical"})
    return h, eid


def test_create_and_public_read(client, eng):
    h, eid = eng
    r = client.post(f"/api/engagements/{eid}/shares", headers=h, json={"ttl_days": 14})
    assert r.status_code == 201
    token = r.json()["token"]
    assert r.json()["url"].startswith("/share.html#")

    # Public read needs NO auth and returns the report with findings.
    pub = client.get(f"/api/share/{token}")
    assert pub.status_code == 200
    body = pub.json()
    assert body["shared"] is True
    assert body["engagement"]["name"] == "ACME Assessment"
    assert len(body["findings"]) == 1

    # Public PDF download works unauthenticated.
    pdf = client.get(f"/api/share/{token}/download?format=pdf")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"


def test_bad_token_404(client):
    assert client.get("/api/share/nonexistent-token").status_code == 404


def test_revoke_disables_link(client, eng):
    h, eid = eng
    created = client.post(f"/api/engagements/{eid}/shares", headers=h, json={}).json()
    token = created["token"]
    assert client.get(f"/api/share/{token}").status_code == 200
    # Revoke via the listed share id.
    sid = client.get(f"/api/engagements/{eid}/shares", headers=h).json()["shares"][0]["id"]
    assert client.delete(f"/api/shares/{sid}", headers=h).status_code == 204
    assert client.get(f"/api/share/{token}").status_code == 404


def test_expired_link_404(client, eng, env):
    _app, db = env
    h, eid = eng
    # Create a share that already expired by writing directly.
    token, share = db.create_share(
        db.get_user_by_username("admin")["org_id"], eid,
        db.get_user_by_username("admin")["id"], ttl_days=1)
    import sqlite3, os
    con = sqlite3.connect(os.environ["SIEGE_DB"])
    con.execute("UPDATE shares SET expires_at=? WHERE id=?",
                ("2000-01-01T00:00:00+00:00", share["id"]))
    con.commit(); con.close()
    assert client.get(f"/api/share/{token}").status_code == 404


def test_share_tenant_isolation(client, eng, env):
    _app, db = env
    h, eid = eng
    org_b = db.create_org("Org B")
    db.create_user(org_b["id"], "bob", "bob-password-123", role="operator")
    rb = client.post("/api/auth/login", json={"username": "bob", "password": "bob-password-123"})
    hb = {"Authorization": "Bearer " + rb.json()["token"]}
    # Bob can't create a share on org A's engagement.
    assert client.post(f"/api/engagements/{eid}/shares", headers=hb, json={}).status_code == 404
