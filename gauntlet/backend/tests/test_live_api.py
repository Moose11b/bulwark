"""End-to-end tests for M4 sandbox/real-time: the authorization gate."""
from fastapi.testclient import TestClient

from app.main import app


def _session(client, mode):
    scenario_id = client.get("/api/scenarios").json()[0]["id"]
    return client.post(
        "/api/sessions",
        json={"scenario_id": scenario_id, "name": f"{mode} run", "mode": mode},
    ).json()["id"]


def test_live_inject_refused_without_authorization():
    with TestClient(app) as client:
        sid = _session(client, "sandbox")
        r = client.post(f"/api/sessions/{sid}/live-inject",
                        json={"technique": "T1003.001", "target": "FIN-APP-02"})
        assert r.status_code == 403
        assert "authorization" in r.json()["detail"].lower()


def test_live_inject_refused_in_tabletop_mode():
    with TestClient(app) as client:
        sid = _session(client, "tabletop")
        client.post(f"/api/sessions/{sid}/authorize",
                    json={"scope": ["*"], "authorized_by": "CISO"})
        r = client.post(f"/api/sessions/{sid}/live-inject",
                        json={"technique": "T1003.001", "target": "FIN-APP-02"})
        assert r.status_code == 403
        assert "mode" in r.json()["detail"].lower()


def test_authorized_live_inject_executes_and_adjudicates():
    with TestClient(app) as client:
        sid = _session(client, "sandbox")
        client.post(f"/api/sessions/{sid}/authorize",
                    json={"scope": ["FIN-APP-02"], "authorized_by": "CISO", "ttl_minutes": 60})

        out = client.post(f"/api/sessions/{sid}/live-inject",
                          json={"technique": "T1003.001", "target": "FIN-APP-02"}).json()
        assert out["executed"] is True
        assert out["adapter"] == "simulation"
        assert out["ruling"]["detected"] is True
        assert out["telemetry"]  # synthetic telemetry from environment controls


def test_live_inject_refused_out_of_scope():
    with TestClient(app) as client:
        sid = _session(client, "real_time")
        client.post(f"/api/sessions/{sid}/authorize",
                    json={"scope": ["FIN-APP-02"], "authorized_by": "CISO"})
        r = client.post(f"/api/sessions/{sid}/live-inject",
                        json={"technique": "T1021", "target": "DC-01"})
        assert r.status_code == 403
        assert "scope" in r.json()["detail"].lower()
