"""End-to-end API tests over the seeded ransomware tabletop."""
from fastapi.testclient import TestClient

from app.main import app


def test_health_and_seed():
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        scenarios = client.get("/api/scenarios").json()
        assert len(scenarios) >= 1
        assert scenarios[0]["exercise_type"] == "tabletop"


def test_full_exercise_loop():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]

        # A scenario carries objectives and a full MSEL.
        scenario = client.get(f"/api/scenarios/{scenario_id}").json()
        assert len(scenario["objectives"]) == 4
        assert len(scenario["injects"]) == 9

        # Create and start a session -> the first inject fires.
        sid = client.post(
            "/api/sessions", json={"scenario_id": scenario_id, "name": "Q3 drill"}
        ).json()["id"]
        state = client.post(f"/api/sessions/{sid}/start").json()
        assert state["session"]["status"] == "running"
        assert state["current_inject"]["code"] == "INJ-01"
        assert len(state["available_branches"]) == 3

        # Take the "investigate" branch on an action.
        state = client.post(
            f"/api/sessions/{sid}/advance",
            json={"when": "action_taken", "trigger": "investigate_and_block"},
        ).json()
        assert state["current_inject"]["code"] == "INJ-02a"

        # Advance to the EDR alert, then adjudicate the credential-dump.
        client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})
        adj = client.post(
            f"/api/sessions/{sid}/adjudicate",
            json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"},
        ).json()
        assert adj["ruling"]["detected"] is True

        # Record an evaluator observation against an objective.
        client.post(
            f"/api/sessions/{sid}/observe",
            json={"objective_code": "OBJ-2", "rating": "met", "note": "Triaged within SLA."},
        )

        # The timeline is hash-chained and intact.
        verify = client.get(f"/api/sessions/{sid}/verify").json()
        assert verify["chain_valid"] is True
        assert verify["events"] >= 5

        # Reports render for every audience.
        for audience in ("executive", "technical", "grc", "training"):
            rep = client.post(
                f"/api/sessions/{sid}/reports", json={"audience": audience}
            ).json()
            assert rep["audience"] == audience
            assert len(rep["content"]) > 100
        exec_report = client.post(
            f"/api/sessions/{sid}/reports", json={"audience": "executive"}
        ).json()
        assert "Bottom line" in exec_report["content"]


def test_proctor_override_to_arbitrary_inject():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        sid = client.post(
            "/api/sessions", json={"scenario_id": scenario_id, "name": "Override run"}
        ).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        # Proctor jumps straight to the bad-ending branch by explicit goto.
        state = client.post(
            f"/api/sessions/{sid}/advance",
            json={"when": "proctor_choice", "goto": "INJ-02b", "note": "compress the intro"},
        ).json()
        assert state["current_inject"]["code"] == "INJ-02b"


def test_bad_branch_is_rejected():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        sid = client.post(
            "/api/sessions", json={"scenario_id": scenario_id, "name": "Bad branch"}
        ).json()["id"]
        client.post(f"/api/sessions/{sid}/start")
        r = client.post(
            f"/api/sessions/{sid}/advance",
            json={"when": "action_taken", "trigger": "does_not_exist"},
        )
        assert r.status_code == 422
