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


async def _make_engagement(client):
    r = await client.post("/api/siege/engagements", json={
        "name": "log-flow", "objective": "domain_admin", "box_type": "grey",
        "scope_platforms": ["windows", "active_directory"],
        "provided_access": ["domain_user", "internal_network"],
    })
    eid = r.json()["id"]
    await client.post(f"/api/siege/engagements/{eid}/generate")
    plans = (await client.get(f"/api/siege/engagements/{eid}/plans")).json()["plans"]
    return eid, plans


async def test_log_and_report_flow(client):
    eid, plans = await _make_engagement(client)
    key = plans[0]["plan_key"]
    await client.post(f"/api/siege/engagements/{eid}/plans/{key}/select")
    first_step = plans[0]["steps"][0]

    # Document an action against the first step.
    mk = await client.post(f"/api/siege/engagements/{eid}/logs", json={
        "title": "Ran AD enumeration",
        "outcome": "succeeded",
        "plan_key": key,
        "step_index": 0,
        "technique_id": first_step["technique_id"],
        "notes": "Mapped a path to Tier-0.",
        "evidence_refs": ["bloodhound_export.zip"],
        "targets": ["DC01"],
    })
    assert mk.status_code == 201, mk.text
    log_id = mk.json()["id"]
    assert mk.json()["operator"]  # operator name resolved

    listed = await client.get(f"/api/siege/engagements/{eid}/logs")
    assert len(listed.json()["logs"]) == 1

    # Invalid outcome is rejected.
    bad = await client.post(f"/api/siege/engagements/{eid}/logs", json={
        "title": "x", "outcome": "exploded"})
    assert bad.status_code == 400

    # JSON report reflects the entry.
    rep = await client.get(f"/api/siege/engagements/{eid}/report")
    assert rep.status_code == 200
    body = rep.json()
    assert body["summary"]["total_entries"] == 1
    assert body["coverage"]["steps_worked"] >= 1

    # Markdown report renders.
    md = await client.get(f"/api/siege/engagements/{eid}/report?format=markdown")
    assert md.status_code == 200
    assert "Engagement Report" in md.text
    assert "Ran AD enumeration" in md.text

    # Update + delete the entry.
    up = await client.patch(f"/api/siege/engagements/{eid}/logs/{log_id}",
                            json={"outcome": "fell_back"})
    assert up.status_code == 200 and up.json()["outcome"] == "fell_back"
    dele = await client.delete(f"/api/siege/engagements/{eid}/logs/{log_id}")
    assert dele.status_code == 204

    await client.delete(f"/api/siege/engagements/{eid}")
