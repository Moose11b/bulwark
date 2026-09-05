"""
Siege Tower API — end-to-end engagement planning flow (requires the DB).

Creates an engagement, generates plans from its ROE, selects one, and cleans
up. Skips automatically if the engine package isn't mounted in the test image.
"""
import pytest

from app.services import siege_adapter as adapter

pytestmark = pytest.mark.skipif(
    not adapter.ENGINE_AVAILABLE, reason="siege_tower engine package not present"
)


async def test_reference_lists_objectives(client):
    r = await client.get("/api/siege/reference")
    assert r.status_code == 200
    body = r.json()
    assert body["engine_available"] is True
    assert any(o["value"] == "domain_admin" for o in body["objectives"])


async def test_full_planning_flow(client):
    # Create an engagement from a structured ROE.
    create = await client.post("/api/siege/engagements", json={
        "name": "ACME external red team",
        "client_name": "ACME Corp",
        "authorization_ref": "SOW-2026-014",
        "objective": "domain_admin",
        "box_type": "grey",
        "scope_platforms": ["windows", "active_directory"],
        "in_scope_targets": ["10.0.0.0/24", "acme.example"],
        "provided_access": ["domain_user", "internal_network"],
        "restrictions": ["no_phishing"],
        "time_budget_hours": 40,
    })
    assert create.status_code == 201, create.text
    eng = create.json()
    eid = eng["id"]
    assert eng["status"] == "draft"

    # Generate plans (pure computation from the ROE).
    gen = await client.post(f"/api/siege/engagements/{eid}/generate")
    assert gen.status_code == 200, gen.text
    gen_body = gen.json()
    assert gen_body["status"] == "planning"
    assert len(gen_body["plans"]) >= 1
    assert gen_body["last_plan_meta"]["goal_capability"] == "domain_admin"
    # Steps carry the drill-down + suggested tooling.
    step0 = gen_body["plans"][0]["steps"][0]
    assert "recommended_tools" in step0

    # Select a plan.
    key = gen_body["plans"][0]["plan_key"]
    sel = await client.post(f"/api/siege/engagements/{eid}/plans/{key}/select")
    assert sel.status_code == 200
    selected = [p for p in sel.json()["plans"] if p["is_selected"]]
    assert len(selected) == 1 and selected[0]["plan_key"] == key

    # Clean up.
    dele = await client.delete(f"/api/siege/engagements/{eid}")
    assert dele.status_code == 204


async def test_unknown_objective_rejected(client):
    r = await client.post("/api/siege/engagements", json={
        "name": "bad", "objective": "not_real", "box_type": "black",
    })
    assert r.status_code == 400
