"""
Standalone server API — end-to-end via Starlette's TestClient (no network).

Exercises the bootstrap payload, live plan ranking, engagement persistence, and
report compilation — all behind the new authentication layer. Uses a temporary
SQLite file and a known admin password so it never touches real data.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def app_mod(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    # A real key so the encryption-at-rest path is exercised in tests.
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec
    importlib.reload(sec)
    import server.db as db
    importlib.reload(db)
    import server.app as app_mod
    importlib.reload(app_mod)
    return app_mod


@pytest.fixture()
def client(app_mod):
    with TestClient(app_mod.app) as c:
        yield c


def _login(client, username="admin", password=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def auth(client):
    return _login(client)


def test_health_is_public(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_api_requires_auth(client):
    assert client.get("/api/bootstrap").status_code == 401
    assert client.get("/api/engagements").status_code == 401
    assert client.post("/api/plan", json={"objective": "domain_admin"}).status_code == 401


def test_bad_login_rejected(client):
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": "wrong"}).status_code == 401


def test_bootstrap_shape(client, auth):
    b = client.get("/api/bootstrap", headers=auth).json()
    assert len(b["playbook"]) >= 40
    assert "domain_admin|grey" in b["results"]
    assert b["results"]["domain_admin|grey"]["options"]


def test_live_plan(client, auth):
    r = client.post("/api/plan", headers=auth,
                    json={"objective": "domain_admin", "box_type": "grey",
                          "scope_platforms": ["windows", "active_directory"]})
    assert r.status_code == 200
    assert r.json()["options"]
    assert "recommended_tools" in r.json()["options"][0]["steps"][0]


def test_invalid_plan_rejected(client, auth):
    assert client.post("/api/plan", headers=auth, json={"objective": "nope"}).status_code == 400


def test_engagement_crud_and_report(client, auth):
    payload = {
        "name": "ACME external", "client": "ACME Corp", "authorization_ref": "SOW-1",
        "objective": "domain_admin", "box_type": "grey",
        "scope_platforms": ["windows"], "restrictions": ["no_phishing"],
        "in_scope_targets": ["10.0.0.0/24"], "time_budget_hours": 40, "status": "active",
        "plan": [{"uid": "s1", "tid": "T1087"}, {"uid": "s2", "tid": "T1649"}],
        "logs": {"s1": {"outcome": "succeeded", "operator": "shamus",
                        "notes": "Found ESC1.", "evidence": ["bh.zip"], "targets": ["DC01"]},
                 "s2": {"outcome": "fell_back", "operator": "shamus",
                        "notes": "Used ESC8.", "evidence": [], "targets": []}},
    }
    created = client.post("/api/engagements", headers=auth, json=payload)
    assert created.status_code == 201
    eid = created.json()["id"]

    lst = client.get("/api/engagements", headers=auth).json()["engagements"]
    row = next(e for e in lst if e["id"] == eid)
    assert row["progress"]["pct"] == 100

    got = client.get(f"/api/engagements/{eid}", headers=auth).json()
    assert got["name"] == "ACME external" and len(got["plan"]) == 2

    upd = client.put(f"/api/engagements/{eid}", headers=auth, json={"status": "complete"})
    assert upd.json()["status"] == "complete" and upd.json()["name"] == "ACME external"

    rep = client.get(f"/api/engagements/{eid}/report", headers=auth).json()
    assert rep["coverage"]["coverage_pct"] == 100.0
    assert set(rep["summary"]["techniques_succeeded"]) == {"T1087", "T1649"}

    md = client.get(f"/api/engagements/{eid}/report?format=markdown", headers=auth)
    assert md.status_code == 200 and "Engagement Report" in md.text
    assert "msfvenom" not in md.text  # documents, never runnable commands

    assert client.delete(f"/api/engagements/{eid}", headers=auth).status_code == 204
    assert client.get(f"/api/engagements/{eid}", headers=auth).status_code == 404


def test_report_404(client, auth):
    assert client.get("/api/engagements/nope/report", headers=auth).status_code == 404


def test_followups_endpoint(client, auth):
    r = client.post("/api/followups", headers=auth, json={
        "failed_technique_id": "T1649", "objective": "domain_admin", "box_type": "grey",
        "succeeded_technique_ids": [],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["failed_technique_id"] == "T1649"
    assert body["suggestions"]
    first = body["suggestions"][0]
    assert first["is_fallback"] and "reason" in first and "keeps_path_open" in first


def test_followups_requires_auth(client):
    assert client.post("/api/followups",
                       json={"failed_technique_id": "T1649", "objective": "domain_admin"}
                       ).status_code == 401
