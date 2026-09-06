"""
Standalone server API — end-to-end via Starlette's TestClient (no network).

Exercises the bootstrap payload, live plan ranking, engagement persistence, and
report compilation. Uses a temporary SQLite file so it never touches real data.
"""
import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "test.db"))
    # Re-import db + app so they bind to the temp database path.
    import server.db as db
    importlib.reload(db)
    import server.app as app_mod
    importlib.reload(app_mod)
    with TestClient(app_mod.app) as c:
        yield c


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_bootstrap_shape(client):
    b = client.get("/api/bootstrap").json()
    assert len(b["playbook"]) >= 40
    assert "domain_admin|grey" in b["results"]
    assert any(o["value"] == "domain_admin" for o in b["reference"]["objectives"])
    assert b["results"]["domain_admin|grey"]["options"]


def test_live_plan(client):
    r = client.post("/api/plan", json={"objective": "domain_admin", "box_type": "grey",
                                       "scope_platforms": ["windows", "active_directory"]})
    assert r.status_code == 200
    assert r.json()["options"]
    step0 = r.json()["options"][0]["steps"][0]
    assert "recommended_tools" in step0


def test_invalid_plan_rejected(client):
    assert client.post("/api/plan", json={"objective": "nope"}).status_code == 400


def test_engagement_crud_and_report(client):
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
    created = client.post("/api/engagements", json=payload)
    assert created.status_code == 201
    eid = created.json()["id"]

    lst = client.get("/api/engagements").json()["engagements"]
    assert any(e["id"] == eid for e in lst)
    row = next(e for e in lst if e["id"] == eid)
    assert row["progress"]["pct"] == 100  # both steps worked

    got = client.get(f"/api/engagements/{eid}").json()
    assert got["name"] == "ACME external" and len(got["plan"]) == 2

    upd = client.put(f"/api/engagements/{eid}", json={"status": "complete"})
    assert upd.json()["status"] == "complete" and upd.json()["name"] == "ACME external"

    rep = client.get(f"/api/engagements/{eid}/report").json()
    assert rep["coverage"]["coverage_pct"] == 100.0
    assert set(rep["summary"]["techniques_succeeded"]) == {"T1087", "T1649"}

    md = client.get(f"/api/engagements/{eid}/report?format=markdown")
    assert md.status_code == 200 and "Engagement Report" in md.text
    assert "msfvenom" not in md.text  # documents, never runnable commands

    assert client.delete(f"/api/engagements/{eid}").status_code == 204
    assert client.get(f"/api/engagements/{eid}").status_code == 404


def test_report_404(client):
    assert client.get("/api/engagements/nope/report").status_code == 404
