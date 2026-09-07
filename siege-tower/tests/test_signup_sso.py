"""
Self-service signup (env-gated) and OIDC ID-token verification.
"""
import importlib
import time

import pytest
from fastapi.testclient import TestClient


def _reload_app(monkeypatch, tmp_path, signup="0"):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "su.db"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", "test-admin-pw-123")
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("SIEGE_ALLOW_SIGNUP", signup)
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec; importlib.reload(sec)
    import server.db as db; importlib.reload(db)
    import server.app as app_mod; importlib.reload(app_mod)
    return app_mod


# ── Signup ────────────────────────────────────────────────────────

def test_signup_disabled_by_default(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path, signup="0")
    with TestClient(app_mod.app) as c:
        assert c.get("/api/auth/config").json()["signup_enabled"] is False
        r = c.post("/api/auth/signup", json={
            "org_name": "New Co", "username": "newadmin", "password": "a-good-password-1"})
        assert r.status_code == 403


def test_signup_creates_org_and_admin(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path, signup="1")
    with TestClient(app_mod.app) as c:
        assert c.get("/api/auth/config").json()["signup_enabled"] is True
        r = c.post("/api/auth/signup", json={
            "org_name": "New Co", "username": "newadmin",
            "password": "a-good-password-1", "email": "a@new.co"})
        assert r.status_code == 201
        body = r.json()
        assert body["user"]["role"] == "admin" and body["token"]
        # The new admin is isolated in its own org (can't see the default org's data).
        h = {"Authorization": "Bearer " + body["token"]}
        assert c.get("/api/engagements", headers=h).json()["engagements"] == []
        # Duplicate username is refused.
        assert c.post("/api/auth/signup", json={
            "org_name": "Other", "username": "newadmin",
            "password": "another-good-1"}).status_code == 409


# ── OIDC ID-token verification (pure, offline) ────────────────────

def _keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def _token(priv, **over):
    import jwt
    now = int(time.time())
    claims = {"iss": "https://idp.example", "aud": "client1", "sub": "u-1",
              "preferred_username": "alice", "email": "alice@example",
              "nonce": "NONCE", "iat": now, "exp": now + 300}
    claims.update(over)
    return jwt.encode(claims, priv, algorithm="RS256")


def test_valid_id_token_decodes():
    from server import sso
    priv, pub = _keypair()
    claims = sso.decode_id_token(_token(priv), pub, audience="client1",
                                 issuer="https://idp.example", nonce="NONCE")
    assert claims["sub"] == "u-1"
    ident = sso.claims_identity(claims)
    assert ident["username"] == "alice" and ident["email"] == "alice@example"


def test_id_token_rejects_bad_audience_issuer_nonce_expiry():
    from server import sso
    import jwt
    priv, pub = _keypair()
    tok = _token(priv)
    with pytest.raises(Exception):
        sso.decode_id_token(tok, pub, audience="other", issuer="https://idp.example", nonce="NONCE")
    with pytest.raises(Exception):
        sso.decode_id_token(tok, pub, audience="client1", issuer="https://evil", nonce="NONCE")
    with pytest.raises(ValueError):
        sso.decode_id_token(tok, pub, audience="client1", issuer="https://idp.example", nonce="WRONG")
    expired = _token(priv, exp=int(time.time()) - 10)
    with pytest.raises(jwt.ExpiredSignatureError):
        sso.decode_id_token(expired, pub, audience="client1", issuer="https://idp.example", nonce=None)


def test_id_token_rejects_wrong_key():
    from server import sso
    priv, _pub = _keypair()
    _priv2, pub2 = _keypair()
    with pytest.raises(Exception):
        sso.decode_id_token(_token(priv), pub2, audience="client1",
                            issuer="https://idp.example", nonce="NONCE")
