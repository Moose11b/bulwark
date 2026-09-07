"""
Report rendering: JSON/Markdown/DOCX/PDF include findings and engagement data.
"""
import importlib
import io

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "test-admin-pw-123"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEGE_DB", str(tmp_path / "rep.db"))
    monkeypatch.setenv("SIEGE_EVIDENCE_DIR", str(tmp_path / "evstore"))
    monkeypatch.setenv("SIEGE_ADMIN_PASSWORD", ADMIN_PW)
    monkeypatch.setenv("SIEGE_ADMIN_USERNAME", "admin")
    from server.security import generate_key
    monkeypatch.setenv("SIEGE_ENCRYPTION_KEY", generate_key())
    import server.security as sec; importlib.reload(sec)
    import server.db as db; importlib.reload(db)
    import server.evidence_store as es; importlib.reload(es)
    import server.app as app_mod; importlib.reload(app_mod)
    with TestClient(app_mod.app) as c:
        yield c


def _auth(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def engagement_with_finding(client):
    h = _auth(client)
    eid = client.post("/api/engagements", headers=h, json={
        "name": "ACME external", "client": "ACME Corp", "objective": "domain_admin",
        "box_type": "grey", "in_scope_targets": ["10.0.0.0/24"],
    }).json()["id"]
    client.post("/api/findings", headers=h, json={
        "title": "SQL injection in /login", "engagement_id": eid,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Blind boolean SQLi.", "remediation": "Parameterize.",
        "technique_ids": ["T1190"],
    })
    return h, eid


def test_json_report_includes_findings(client, engagement_with_finding):
    h, eid = engagement_with_finding
    rep = client.get(f"/api/engagements/{eid}/report", headers=h).json()
    assert rep["org_name"] == "Default"
    assert len(rep["findings"]) == 1
    assert rep["findings"][0]["severity"] == "critical"


def test_markdown_report_includes_findings(client, engagement_with_finding):
    h, eid = engagement_with_finding
    md = client.get(f"/api/engagements/{eid}/report?format=markdown", headers=h)
    assert md.status_code == 200
    assert "## Findings" in md.text
    assert "SQL injection in /login" in md.text
    assert "CVSS 9.8" in md.text


def test_docx_report(client, engagement_with_finding):
    from docx import Document
    h, eid = engagement_with_finding
    r = client.get(f"/api/engagements/{eid}/report?format=docx", headers=h)
    assert r.status_code == 200
    assert r.content[:2] == b"PK"  # zip/OOXML magic
    assert "wordprocessingml" in r.headers["content-type"]
    assert r.headers["content-disposition"].startswith("attachment")
    # Re-open and confirm the finding title made it in.
    doc = Document(io.BytesIO(r.content))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "SQL injection in /login" in text


def test_pdf_report(client, engagement_with_finding):
    h, eid = engagement_with_finding
    r = client.get(f"/api/engagements/{eid}/report?format=pdf", headers=h)
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"
    assert r.headers["content-type"] == "application/pdf"
    assert len(r.content) > 1500


def test_unsupported_format_rejected(client, engagement_with_finding):
    h, eid = engagement_with_finding
    assert client.get(f"/api/engagements/{eid}/report?format=xml",
                      headers=h).status_code == 400


def test_navigator_layer_export(client, engagement_with_finding):
    h, eid = engagement_with_finding
    r = client.get(f"/api/engagements/{eid}/navigator", headers=h)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["content-disposition"].startswith("attachment")
    layer = r.json()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["navigator"]
    # The finding cited T1190, so it must appear as a technique in the layer.
    tids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1190" in tids
    assert any("legendItems" == k for k in layer)


def test_navigator_requires_auth(client, engagement_with_finding):
    _h, eid = engagement_with_finding
    assert client.get(f"/api/engagements/{eid}/navigator").status_code == 401
