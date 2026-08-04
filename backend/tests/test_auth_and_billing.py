"""Auth identity and the public billing/plans endpoint."""


async def test_me_returns_logged_in_identity(client, test_user, test_org):
    r = await client.get("/api/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["id"] == test_user.id
    assert body["user"]["clerk_user_id"] == test_user.clerk_user_id
    assert body["user"]["role"] == "admin"
    assert body["org"]["id"] == test_org.id
    assert body["org"]["name"] == test_org.name


async def test_plans_returns_three_tiers(client):
    r = await client.get("/api/billing/plans")
    assert r.status_code == 200
    plans = r.json()
    assert len(plans) == 3
    ids = {p["id"] for p in plans}
    assert ids == {"starter", "pro", "enterprise"}


async def test_subscription_reflects_org(client, test_org):
    r = await client.get("/api/billing/subscription")
    assert r.status_code == 200
    body = r.json()
    # Starter is the default for a fresh org
    assert body["plan"].lower() == "starter"
    assert body["scan_limit"] == 25
