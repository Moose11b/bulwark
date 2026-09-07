"""
Org report branding: colours, company name, footer, and logo; applied to the
report context and gated to admins.
"""
import base64
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"
# A 1x1 PNG.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "br.db"))
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


def test_set_and_get_branding(client):
    h = _auth(client)
    r = client.put("/api/branding", headers=h, json={
        "accent": "#123456", "company_name": "Acme Sec", "footer": "© Acme",
        "confidentiality": "RESTRICTED"})
    assert r.status_code == 200
    b = client.get("/api/branding", headers=h).json()
    assert b["accent"] == "#123456" and b["company_name"] == "Acme Sec"
    assert b["confidentiality"] == "RESTRICTED" and b["has_logo"] is False


def test_invalid_accent_rejected(client):
    h = _auth(client)
    assert client.put("/api/branding", headers=h, json={"accent": "red"}).status_code == 400


def test_logo_upload_serve_delete(client):
    h = _auth(client)
    up = client.post("/api/branding/logo", headers=h,
                     files={"file": ("logo.png", PNG, "image/png")})
    assert up.status_code == 201 and up.json()["has_logo"] is True
    got = client.get("/api/branding/logo", headers=h)
    assert got.status_code == 200 and got.content == PNG
    assert client.get("/api/branding", headers=h).json()["has_logo"] is True
    assert client.delete("/api/branding/logo", headers=h).status_code == 204
    assert client.get("/api/branding/logo", headers=h).status_code == 404


def test_non_image_logo_rejected(client):
    h = _auth(client)
    r = client.post("/api/branding/logo", headers=h,
                    files={"file": ("x.txt", b"hello", "text/plain")})
    assert r.status_code == 400


def test_branding_is_admin_only(client, env):
    _app, db = env
    h = _auth(client)
    org = db.get_user_by_username("admin")["org_id"]
    db.create_user(org, "op", "operator-password-1", role="operator")
    ro = client.post("/api/auth/login", json={"username": "op", "password": "operator-password-1"})
    ho = {"Authorization": "Bearer " + ro.json()["token"]}
    # Operator can read but not change branding.
    assert client.get("/api/branding", headers=ho).status_code == 200
    assert client.put("/api/branding", headers=ho, json={"accent": "#111111"}).status_code == 403


def test_branding_flows_into_report(client):
    h = _auth(client)
    client.put("/api/branding", headers=h, json={"accent": "#0A7E4F", "company_name": "Acme Sec"})
    client.post("/api/branding/logo", headers=h, files={"file": ("l.png", PNG, "image/png")})
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    # PDF/DOCX render without error when branding + logo are present.
    pdf = client.get(f"/api/engagements/{eid}/report?format=pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    docx = client.get(f"/api/engagements/{eid}/report?format=docx", headers=h)
    assert docx.status_code == 200 and docx.content[:2] == b"PK"
