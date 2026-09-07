"""
Security guarantees for the standalone app.

These tests are the executable form of the security review: authentication is
required, tenants are isolated, roles are enforced, passwords are hashed and
strength-checked, the data blob is encrypted at rest, security headers ship on
every response, and deletes are soft (retained).
"""
import importlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    dbfile = tmp_path / "sec.db"
    monkeypatch.setenv("SIEGE_DB", str(dbfile))
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
    return app_mod, db, dbfile


@pytest.fixture()
def client(env):
    app_mod, _db, _ = env
    with TestClient(app_mod.app) as c:
        yield c


def _login(client, username="admin", password=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _hdr(token):
    return {"Authorization": "Bearer " + token}


# ── Password hashing ──────────────────────────────────────────────

def test_password_hash_roundtrip_and_strength():
    from server.security import hash_password, verify_password
    h = hash_password("correct horse battery")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    with pytest.raises(ValueError):
        hash_password("short")  # < 12 chars


# ── Auth required ─────────────────────────────────────────────────

def test_unauthenticated_calls_rejected(client):
    for path in ("/api/bootstrap", "/api/engagements", "/api/users", "/api/audit"):
        assert client.get(path).status_code == 401


def test_invalid_token_rejected(client):
    assert client.get("/api/engagements", headers=_hdr("garbage")).status_code == 401


def test_logout_revokes_token(client):
    tok = _login(client)
    assert client.get("/api/engagements", headers=_hdr(tok)).status_code == 200
    assert client.post("/api/auth/logout", headers=_hdr(tok)).status_code == 200
    assert client.get("/api/engagements", headers=_hdr(tok)).status_code == 401


# ── Tenant isolation ──────────────────────────────────────────────

def test_tenants_are_isolated(client, env):
    app_mod, db, _ = env
    admin_tok = _login(client)
    # Admin (org A) creates an engagement.
    r = client.post("/api/engagements", headers=_hdr(admin_tok),
                    json={"name": "Org A job", "client": "A"})
    eid = r.json()["id"]

    # A second org with its own operator.
    org_b = db.create_org("Org B")
    db.create_user(org_b["id"], "bob", "bob-password-123", role="operator")
    bob_tok = _login(client, "bob", "bob-password-123")

    # Bob cannot see or fetch org A's engagement.
    assert client.get("/api/engagements", headers=_hdr(bob_tok)).json()["engagements"] == []
    assert client.get(f"/api/engagements/{eid}", headers=_hdr(bob_tok)).status_code == 404
    assert client.put(f"/api/engagements/{eid}", headers=_hdr(bob_tok),
                      json={"status": "x"}).status_code == 404
    assert client.delete(f"/api/engagements/{eid}", headers=_hdr(bob_tok)).status_code == 404


# ── Role enforcement ──────────────────────────────────────────────

def test_viewer_cannot_write(client, env):
    app_mod, db, _ = env
    admin_tok = _login(client)
    org = db.get_user_by_username("admin")["org_id"]
    db.create_user(org, "val", "viewer-password-123", role="viewer")
    v_tok = _login(client, "val", "viewer-password-123")
    # Viewer reads fine, but cannot create.
    assert client.get("/api/engagements", headers=_hdr(v_tok)).status_code == 200
    assert client.post("/api/engagements", headers=_hdr(v_tok),
                       json={"name": "nope"}).status_code == 403
    # Viewer cannot reach admin-only endpoints.
    assert client.get("/api/users", headers=_hdr(v_tok)).status_code == 403


def test_only_admin_manages_users(client):
    admin_tok = _login(client)
    r = client.post("/api/users", headers=_hdr(admin_tok),
                    json={"username": "newop", "password": "new-op-password-1", "role": "operator"})
    assert r.status_code == 201
    # Weak password rejected.
    assert client.post("/api/users", headers=_hdr(admin_tok),
                       json={"username": "weak", "password": "short"}).status_code == 422
    # Duplicate username rejected.
    assert client.post("/api/users", headers=_hdr(admin_tok),
                       json={"username": "newop", "password": "another-password-1"}).status_code == 409


# ── Encryption at rest ────────────────────────────────────────────

def test_engagement_blob_encrypted_on_disk(client, env):
    app_mod, db, dbfile = env
    tok = _login(client)
    secret = "SUPER-SECRET-CLIENT-NAME"
    client.post("/api/engagements", headers=_hdr(tok),
                json={"name": "enc test", "client": secret})
    # Read the raw SQLite bytes; the secret must not appear in plaintext.
    raw = sqlite3.connect(str(dbfile)).execute("SELECT data FROM engagements").fetchone()[0]
    assert raw.startswith("enc:v1:")
    assert secret not in raw
    # But it round-trips through the API.
    got = client.get("/api/engagements", headers=_hdr(tok)).json()["engagements"]
    full = client.get(f"/api/engagements/{got[0]['id']}", headers=_hdr(tok)).json()
    assert full["client"] == secret


# ── Soft delete / retention ───────────────────────────────────────

def test_delete_is_soft(client, env):
    app_mod, db, dbfile = env
    tok = _login(client)
    eid = client.post("/api/engagements", headers=_hdr(tok),
                      json={"name": "retained"}).json()["id"]
    assert client.delete(f"/api/engagements/{eid}", headers=_hdr(tok)).status_code == 204
    # Gone from the API…
    assert client.get(f"/api/engagements/{eid}", headers=_hdr(tok)).status_code == 404
    # …but the row is retained with a deleted_at stamp.
    row = sqlite3.connect(str(dbfile)).execute(
        "SELECT deleted_at FROM engagements WHERE id=?", (eid,)).fetchone()
    assert row is not None and row[0] is not None


# ── Security headers & CSP ────────────────────────────────────────

def test_security_headers_present(client):
    r = client.get("/api/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


# ── Body size limit ───────────────────────────────────────────────

def test_oversized_body_rejected(client):
    tok = _login(client)
    big = {"name": "x", "objective_note": "A" * 2_000_000}
    r = client.post("/api/engagements",
                    headers={**_hdr(tok), "Content-Type": "application/json"},
                    content=json.dumps(big))
    # 413 from the size middleware (content-length exceeds the cap).
    assert r.status_code == 413


# ── Audit trail ───────────────────────────────────────────────────

def test_audit_records_actions(client):
    tok = _login(client)
    client.post("/api/engagements", headers=_hdr(tok), json={"name": "audited"})
    entries = client.get("/api/audit", headers=_hdr(tok)).json()["entries"]
    actions = {e["action"] for e in entries}
    assert "login" in actions and "engagement_create" in actions
