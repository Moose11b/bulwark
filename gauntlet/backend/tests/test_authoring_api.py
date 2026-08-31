"""End-to-end tests for the M2 authoring API: catalog, generate, delivery, edit."""
from fastapi.testclient import TestClient

from app.main import app


def test_catalog_endpoints():
    with TestClient(app) as client:
        actors = client.get("/api/catalog/actors").json()
        assert any(a["key"] == "ransomware_affiliate" for a in actors)
        templates = client.get("/api/catalog/templates").json()
        assert any(t["key"] == "ransomware_finance" for t in templates)
        bank = client.get("/api/catalog/injects", params={"channel": "email"}).json()
        assert bank and all(e["channel"] == "email" for e in bank)


def test_generate_and_play_generated_scenario():
    with TestClient(app) as client:
        # The seeded environment is id 1.
        env_id = client.get("/api/environments").json()[0]["id"]

        scenario = client.post(
            "/api/scenarios/generate",
            json={"environment_id": env_id, "template_key": "apt_intrusion",
                  "name": "Generated APT drill"},
        ).json()
        assert scenario["name"] == "Generated APT drill"
        assert len(scenario["injects"]) >= 5
        start = [i for i in scenario["injects"] if i["is_start"]]
        assert len(start) == 1

        # The generated scenario is immediately runnable end to end.
        sid = client.post(
            "/api/sessions", json={"scenario_id": scenario["id"], "name": "gen run"}
        ).json()["id"]
        state = client.post(f"/api/sessions/{sid}/start").json()
        assert state["current_inject"]["is_start"] is True

        # Walk the whole arc via proctor choices until a terminal inject.
        for _ in range(20):
            state = client.get(f"/api/sessions/{sid}").json()
            if state["terminal"]:
                break
            client.post(f"/api/sessions/{sid}/advance", json={"when": "proctor_choice"})
        assert client.get(f"/api/sessions/{sid}").json()["terminal"] is True

        # Timeline stayed intact across the whole run.
        assert client.get(f"/api/sessions/{sid}/verify").json()["chain_valid"] is True


def test_generate_requires_actor_or_template():
    with TestClient(app) as client:
        env_id = client.get("/api/environments").json()[0]["id"]
        r = client.post("/api/scenarios/generate", json={"environment_id": env_id})
        assert r.status_code == 400


def test_delivery_and_inject_edit():
    with TestClient(app) as client:
        env_id = client.get("/api/environments").json()[0]["id"]
        scenario = client.post(
            "/api/scenarios/generate",
            json={"environment_id": env_id, "actor_key": "bec_actor"},
        ).json()
        inject = scenario["injects"][0]

        # Delivery renders the inject in its channel.
        deliv = client.get(f"/api/injects/{inject['id']}/delivery").json()
        assert deliv["channel"] == inject["channel"]
        assert deliv["headline"] == inject["title"]

        # Editing a generated draft persists.
        client.patch(f"/api/injects/{inject['id']}", json={"title": "Edited title"})
        refreshed = client.get(f"/api/scenarios/{scenario['id']}").json()
        assert any(i["title"] == "Edited title" for i in refreshed["injects"])

        # Scenario metadata can be updated too.
        client.patch(f"/api/scenarios/{scenario['id']}", json={"scope": "Custom scope"})
        assert client.get(f"/api/scenarios/{scenario['id']}").json()["scope"] == "Custom scope"
