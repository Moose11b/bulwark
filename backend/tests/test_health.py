"""Health endpoints are unauthenticated and should always be 200."""
import pytest

HEALTH_PATHS = [
    "/health",
    "/api/admin/health",
    "/api/alerts/health",
    "/api/auth/health",
    "/api/compliance/health",
    "/api/findings/health",
    "/api/killchain/health",
    "/api/osint/health",
    "/api/owasp/health",
    "/api/reports/health",
    "/api/schedules/health",
    "/api/webhooks/health",
]


@pytest.mark.parametrize("path", HEALTH_PATHS)
async def test_health_endpoints_return_200(anon_client, path):
    r = await anon_client.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}: {r.text}"


async def test_root_health_returns_app_version(anon_client):
    r = await anon_client.get("/health")
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


async def test_openapi_spec_loads(anon_client):
    r = await anon_client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    # Sanity: we expect at least 40 paths registered (we had 44 last sprint)
    assert len(spec["paths"]) >= 40
