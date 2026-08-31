"""End-to-end tests for M4 program analytics: coverage and improvements."""
from fastapi.testclient import TestClient

from app.main import app


def _play(client, scenario_id, name, rating):
    sid = client.post(
        "/api/sessions", json={"scenario_id": scenario_id, "name": name}
    ).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    client.post(f"/api/sessions/{sid}/advance",
                json={"when": "action_taken", "trigger": "investigate_and_block"})
    client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})
    client.post(f"/api/sessions/{sid}/adjudicate",
                json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"})
    client.post(f"/api/sessions/{sid}/observe",
                json={"objective_code": "OBJ-3", "rating": rating, "note": f"{name} containment"})
    return sid


def test_program_coverage():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        _play(client, scenario_id, "run 1", "missed")

        cov = client.get("/api/program/coverage").json()
        techs = {t["technique"]: t for t in cov["techniques"]}
        assert "T1003.001" in techs
        assert techs["T1003.001"]["tested"] is True
        assert techs["T1003.001"]["tactic"] == "Credential Access"
        # A technique in the scenario that was never adjudicated shows untested.
        assert cov["never_tested"]
        assert cov["tactics"]


def test_program_improvements_and_trend():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        _play(client, scenario_id, "quarter 1", "missed")   # gap
        _play(client, scenario_id, "quarter 2", "met")       # later run meets it

        imp = client.get("/api/program/improvements").json()
        obj3 = [i for i in imp["items"] if i["objective_code"] == "OBJ-3"]
        assert obj3, "the missed objective should surface as an improvement item"
        # The earlier gap is marked improved because a later run met OBJ-3.
        assert any(i["status"] == "improved" for i in obj3)
