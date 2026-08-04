"""Findings list/stats + alerts CRUD."""


async def test_findings_empty_for_fresh_org(client):
    r = await client.get("/api/findings")
    assert r.status_code == 200
    assert r.json() == []


async def test_findings_stats_zeros_for_fresh_org(client):
    r = await client.get("/api/findings/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["by_severity"] == {}
    assert body["by_status"] == {}


async def test_alert_create_list_toggle_delete_cycle(client):
    # Empty list initially
    r = await client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json() == []

    # Create
    payload = {
        "name": "pytest slack alert",
        "channel": "slack",
        "webhook_url": "https://hooks.slack.com/services/pytest/test/hook",
        "min_severity": "HIGH",
    }
    r = await client.post("/api/alerts", json=payload)
    assert r.status_code == 201, r.text
    alert = r.json()
    alert_id = alert["id"]
    assert alert["is_active"] is True
    assert alert["min_severity"] == "HIGH"

    # Visible in list
    r = await client.get("/api/alerts")
    assert any(a["id"] == alert_id for a in r.json())

    # Toggle off
    r = await client.patch(f"/api/alerts/{alert_id}/toggle")
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    # Toggle back on
    r = await client.patch(f"/api/alerts/{alert_id}/toggle")
    assert r.json()["is_active"] is True

    # Delete
    r = await client.delete(f"/api/alerts/{alert_id}")
    assert r.status_code == 204

    # Gone from list
    r = await client.get("/api/alerts")
    assert not any(a["id"] == alert_id for a in r.json())


async def test_alert_create_rejects_missing_webhook(client):
    r = await client.post("/api/alerts", json={
        "name": "bad", "channel": "slack",  # no webhook_url
    })
    assert r.status_code == 400
    assert "webhook" in r.json()["detail"].lower()
