"""
Reusable engagement templates: built-ins, CRUD, tenancy, built-in guards.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "tm.db"))
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


def _auth(client, u="admin", p=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": u, "password": p})
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_builtins_present(client):
    h = _auth(client)
    ts = client.get("/api/engagement-templates", headers=h).json()["templates"]
    ids = {t["id"] for t in ts}
    assert "builtin:internal-ad" in ids and "builtin:external-web" in ids
    ad = next(t for t in ts if t["id"] == "builtin:internal-ad")
    assert ad["builtin"] is True and ad["objective"] == "domain_admin"


def test_create_and_list(client):
    h = _auth(client)
    r = client.post("/api/engagement-templates", headers=h, json={
        "name": "My AD preset", "objective": "domain_admin", "box_type": "grey",
        "scope_platforms": ["windows"], "time_budget_hours": 30})
    assert r.status_code == 201
    tid = r.json()["id"]
    ts = client.get("/api/engagement-templates", headers=h).json()["templates"]
    mine = next(t for t in ts if t["id"] == tid)
    assert mine["name"] == "My AD preset" and mine.get("builtin") is None


def test_update_and_delete(client):
    h = _auth(client)
    tid = client.post("/api/engagement-templates", headers=h,
                      json={"name": "P", "objective": "domain_admin"}).json()["id"]
    up = client.put(f"/api/engagement-templates/{tid}", headers=h,
                    json={"name": "P2", "objective": "cloud_takeover"})
    assert up.status_code == 200 and up.json()["name"] == "P2"
    assert client.delete(f"/api/engagement-templates/{tid}", headers=h).status_code == 204
    ids = {t["id"] for t in client.get("/api/engagement-templates", headers=h).json()["templates"]}
    assert tid not in ids


def test_builtins_are_immutable(client):
    h = _auth(client)
    assert client.put("/api/engagement-templates/builtin:internal-ad", headers=h,
                      json={"name": "x"}).status_code == 400
    assert client.delete("/api/engagement-templates/builtin:internal-ad",
                         headers=h).status_code == 400


def test_template_tenant_isolation(client, env):
    _app, db = env
    h = _auth(client)
    tid = client.post("/api/engagement-templates", headers=h,
                      json={"name": "Org A"}).json()["id"]
    org_b = db.create_org("Org B")
    db.create_user(org_b["id"], "bob", "bob-password-123", role="operator")
    hb = _auth(client, "bob", "bob-password-123")
    ids = {t["id"] for t in client.get("/api/engagement-templates", headers=hb).json()["templates"]}
    assert tid not in ids  # only sees built-ins + its own
    assert client.put(f"/api/engagement-templates/{tid}", headers=hb,
                      json={"name": "x"}).status_code == 404
