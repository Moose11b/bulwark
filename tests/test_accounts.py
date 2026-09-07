"""
Phase-2 account UX: admin-created users must change password, admin reset, and
change-password clears the forced-change flag.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "acc.db"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec; importlib.reload(sec)
    import server.db as db; importlib.reload(db)
    import server.app as app_mod; importlib.reload(app_mod)
    with TestClient(app_mod.app) as c:
        yield c


def _tok(client, u="admin", p=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _h(t):
    return {"Authorization": "Bearer " + t}


def test_admin_created_user_must_change(client):
    at = _tok(client)
    r = client.post("/api/users", headers=_h(at),
                    json={"username": "op", "password": "temp-password-123", "role": "operator"})
    assert r.status_code == 201 and r.json()["must_change"] is True
    # The new user logs in; /me shows the forced-change flag.
    ot = _tok(client, "op", "temp-password-123")
    me = client.get("/api/auth/me", headers=_h(ot)).json()
    assert me["must_change"] is True
    # After changing password, the flag clears and the temp no longer works.
    assert client.post("/api/auth/change-password", headers=_h(ot),
                       json={"current_password": "temp-password-123",
                             "new_password": "brand-new-password-9"}).status_code == 200
    ot2 = _tok(client, "op", "brand-new-password-9")
    assert client.get("/api/auth/me", headers=_h(ot2)).json()["must_change"] is False
    assert client.post("/api/auth/login",
                       json={"username": "op", "password": "temp-password-123"}).status_code == 401


def test_admin_reset_password(client):
    at = _tok(client)
    uid = client.post("/api/users", headers=_h(at),
                      json={"username": "bob", "password": "bob-first-password-1"}).json()["id"]
    bt = _tok(client, "bob", "bob-first-password-1")
    # (clear bob's forced-change so we test reset independently)
    client.post("/api/auth/change-password", headers=_h(bt),
                json={"current_password": "bob-first-password-1", "new_password": "bob-second-pass-22"})
    # Admin resets → returns a temp, revokes sessions, forces change.
    r = client.post(f"/api/users/{uid}/reset-password", headers=_h(at))
    assert r.status_code == 200 and r.json()["must_change"] is True
    temp = r.json()["temp_password"]
    # Bob's old session is dead; the temp works and forces a change.
    assert client.post("/api/auth/login",
                       json={"username": "bob", "password": "bob-second-pass-22"}).status_code == 401
    bt2 = _tok(client, "bob", temp)
    assert client.get("/api/auth/me", headers=_h(bt2)).json()["must_change"] is True


def test_reset_is_admin_only(client, tmp_path):
    at = _tok(client)
    uid = client.post("/api/users", headers=_h(at),
                      json={"username": "viewer1", "password": "viewer-pass-123", "role": "viewer"}).json()["id"]
    vt = _tok(client, "viewer1", "viewer-pass-123")
    assert client.post(f"/api/users/{uid}/reset-password", headers=_h(vt)).status_code == 403
