"""
Retest / remediation tracking: status history and per-engagement summary.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "rt.db"))
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


def test_status_change_records_history(client):
    h = _auth(client)
    fid = client.post("/api/findings", headers=h,
                      json={"title": "F", "status": "open"}).json()["id"]
    client.put(f"/api/findings/{fid}", headers=h, json={"status": "in_remediation"})
    hist = client.get(f"/api/findings/{fid}/history", headers=h).json()
    assert hist["status"] == "in_remediation"
    assert len(hist["history"]) == 1
    assert hist["history"][0]["status"] == "in_remediation"
    assert hist["history"][0]["by"] == "admin"


def test_retest_endpoint_appends_dated_note(client):
    h = _auth(client)
    fid = client.post("/api/findings", headers=h, json={"title": "RCE"}).json()["id"]
    r = client.post(f"/api/findings/{fid}/retest", headers=h,
                    json={"status": "fixed", "note": "Patched in build 42; retested clean."})
    assert r.status_code == 200 and r.json()["status"] == "fixed"
    hist = client.get(f"/api/findings/{fid}/history", headers=h).json()["history"]
    assert hist[-1]["status"] == "fixed"
    assert hist[-1]["note"].startswith("Patched")
    assert hist[-1]["at"]  # timestamp recorded


def test_retest_rejects_invalid_status(client):
    h = _auth(client)
    fid = client.post("/api/findings", headers=h, json={"title": "F"}).json()["id"]
    assert client.post(f"/api/findings/{fid}/retest", headers=h,
                       json={"status": "banana"}).status_code == 400


def test_remediation_summary(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={"name": "Job"}).json()["id"]
    # Three findings in different states.
    f1 = client.post("/api/findings", headers=h, json={
        "title": "Critical open", "engagement_id": eid, "severity": "critical"}).json()["id"]
    client.post("/api/findings", headers=h, json={
        "title": "Fixed one", "engagement_id": eid, "severity": "medium", "status": "fixed"})
    client.post("/api/findings", headers=h, json={
        "title": "Low open", "engagement_id": eid, "severity": "low"})

    summ = client.get(f"/api/engagements/{eid}/remediation", headers=h).json()
    assert summ["total_findings"] == 3
    assert summ["resolved"] == 1
    assert summ["open"] == 2
    assert summ["remediation_pct"] == 33.3
    assert summ["open_by_severity"].get("critical") == 1
    assert any(x["id"] == f1 for x in summ["needing_retest"])


def test_remediation_summary_requires_engagement(client):
    h = _auth(client)
    assert client.get("/api/engagements/nope/remediation", headers=h).status_code == 404
