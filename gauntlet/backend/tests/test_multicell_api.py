"""End-to-end tests for M3: fog-of-war views and cross-session roll-up."""
from fastapi.testclient import TestClient

from app.main import app


def _run_session(client, scenario_id, name):
    sid = client.post(
        "/api/sessions", json={"scenario_id": scenario_id, "name": name}
    ).json()["id"]
    client.post(f"/api/sessions/{sid}/start")
    client.post(f"/api/sessions/{sid}/advance",
                json={"when": "action_taken", "trigger": "investigate_and_block"})
    client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})
    client.post(f"/api/sessions/{sid}/adjudicate",
                json={"techniques": ["T1003.001"], "target_asset": "FIN-APP-02"})
    return sid


def test_cell_view_applies_fog_of_war():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        sid = _run_session(client, scenario_id, "fog run")

        blue = client.get(f"/api/sessions/{sid}/cell/blue_cell").json()
        white = client.get(f"/api/sessions/{sid}/cell/white_cell").json()

        assert blue["can_see_all"] is False
        assert white["can_see_all"] is True

        blue_kinds = {e["kind"] for e in blue["timeline"]}
        white_kinds = {e["kind"] for e in white["timeline"]}
        # Blue never sees the adjudication reasoning; White does.
        assert "adjudication" not in blue_kinds
        assert "adjudication" in white_kinds
        # White's timeline is at least as complete as Blue's.
        assert len(white["timeline"]) > len(blue["timeline"])


def test_environment_view_redaction():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        env_id = client.get("/api/environments").json()[0]["id"]

        blue = client.get(
            f"/api/environments/{env_id}/view/blue_cell", params={"scenario_id": scenario_id}
        ).json()
        white = client.get(
            f"/api/environments/{env_id}/view/white_cell", params={"scenario_id": scenario_id}
        ).json()

        # The seeded env hides deception placement from the blue cell (grey box).
        assert blue["deception_assets"] == []
        assert "deception_assets" in blue["redacted"]
        # White Cell sees the deception assets.
        assert white["deception_assets"]
        assert white["redacted"] == []


def test_parallel_rollup_across_sessions():
    with TestClient(app) as client:
        scenario_id = client.get("/api/scenarios").json()[0]["id"]
        _run_session(client, scenario_id, "team A")
        _run_session(client, scenario_id, "team B")

        rollup = client.get(f"/api/scenarios/{scenario_id}/rollup").json()
        assert rollup["totals"]["sessions"] >= 2
        assert len(rollup["sessions"]) >= 2
        assert rollup["technique_coverage"]  # scenario techniques enumerated
        # T1003.001 was adjudicated as detected in both runs.
        cred = next(t for t in rollup["technique_coverage"] if t["technique"] == "T1003.001")
        assert cred["sessions_detected"] >= 2
