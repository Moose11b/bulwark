"""
Evidence upload/download: hashing, encryption at rest, tenancy, linking.
"""
import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "ev.db"))
    monkeypatch.setenv("SIEGE_EVIDENCE_DIR", str(tmp_path / "evstore"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec
    importlib.reload(sec)
    import server.db as db
    importlib.reload(db)
    import server.evidence_store as es
    importlib.reload(es)
    import server.app as app_mod
    importlib.reload(app_mod)
    return app_mod, db, es, tmp_path


@pytest.fixture()
def client(env):
    with TestClient(env[0].app) as c:
        yield c


def _auth(client, u="admin", p=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_evidence_requires_auth(client):
    assert client.get("/api/evidence").status_code == 401


def test_upload_download_and_hash(client, env):
    _app, _db, es, tmp = env
    h = _auth(client)
    payload = b"\x89PNG fake screenshot bytes \x00\x01\x02SENSITIVE"
    up = client.post("/api/evidence", headers=h,
                     files={"file": ("screenshot.png", payload, "image/png")})
    assert up.status_code == 201, up.text
    meta = up.json()
    import hashlib
    assert meta["sha256"] == hashlib.sha256(payload).hexdigest()
    assert meta["size"] == len(payload) and meta["filename"] == "screenshot.png"

    # Round-trips byte-for-byte, always as an attachment.
    dl = client.get(f"/api/evidence/{meta['id']}/download", headers=h)
    assert dl.status_code == 200
    assert dl.content == payload
    assert dl.headers["content-disposition"].startswith("attachment")
    assert dl.headers["content-type"] == "application/octet-stream"


def test_evidence_encrypted_on_disk(client, env):
    _app, _db, es, tmp = env
    h = _auth(client)
    secret = b"TOP-SECRET-EVIDENCE-CONTENT-123"
    meta = client.post("/api/evidence", headers=h,
                       files={"file": ("notes.txt", secret, "text/plain")}).json()
    # Locate the stored file and confirm the plaintext isn't on disk.
    store = Path(tmp) / "evstore"
    files = [p for p in store.rglob("*") if p.is_file()]
    assert files, "evidence file not written"
    blob = files[0].read_bytes()
    assert blob.startswith(b"SGF1E:")   # encrypted marker
    assert secret not in blob


def test_upload_links_to_finding(client):
    h = _auth(client)
    fid = client.post("/api/findings", headers=h, json={"title": "F"}).json()["id"]
    meta = client.post("/api/evidence", headers=h,
                       data={"finding_id": fid},
                       files={"file": ("poc.txt", b"poc", "text/plain")}).json()
    # Evidence lists under the finding, and the finding references the evidence.
    lst = client.get("/api/evidence", headers=h, params={"finding_id": fid}).json()["evidence"]
    assert len(lst) == 1 and lst[0]["id"] == meta["id"]
    f = client.get(f"/api/findings/{fid}", headers=h).json()
    assert meta["id"] in f["evidence_ids"]


def test_evidence_tenant_isolation(client, env):
    _app, db, _es, _tmp = env
    h = _auth(client)
    meta = client.post("/api/evidence", headers=h,
                       files={"file": ("a.txt", b"a", "text/plain")}).json()
    org_b = db.create_org("Org B")
    db.create_user(org_b["id"], "bob", "bob-password-123", role="operator")
    hb = _auth(client, "bob", "bob-password-123")
    assert client.get("/api/evidence", headers=hb).json()["evidence"] == []
    assert client.get(f"/api/evidence/{meta['id']}", headers=hb).status_code == 404
    assert client.get(f"/api/evidence/{meta['id']}/download", headers=hb).status_code == 404


def test_empty_upload_rejected(client):
    h = _auth(client)
    r = client.post("/api/evidence", headers=h,
                    files={"file": ("empty.txt", b"", "text/plain")})
    assert r.status_code == 400
