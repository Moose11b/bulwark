"""Clerk webhook end-to-end: signed payload → DB row mutation."""
from datetime import datetime, timezone
import json
import time
import uuid

import pytest_asyncio
from sqlalchemy import delete, select
from svix.webhooks import Webhook

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Organisation, User

SECRET = get_settings().clerk_webhook_secret


def _signed(payload: dict) -> tuple[str, dict]:
    """Sign a JSON payload with the configured Clerk webhook secret."""
    msg_id = f"msg_pytest_{uuid.uuid4().hex[:12]}"
    now = datetime.now(tz=timezone.utc)
    body = json.dumps(payload, separators=(",", ":"))
    sig = Webhook(SECRET).sign(msg_id, now, body)
    headers = {
        "svix-id": msg_id,
        "svix-timestamp": str(int(now.timestamp())),
        "svix-signature": sig,
        "content-type": "application/json",
    }
    return body, headers


async def test_rejects_unsigned_request(anon_client):
    r = await anon_client.post(
        "/api/webhooks/clerk",
        content=b'{"type":"user.created","data":{"id":"x"}}',
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 400


async def test_rejects_tampered_signature(anon_client):
    body, headers = _signed({"type": "user.created", "data": {"id": "x"}})
    headers["svix-signature"] = "v1,deadbeef"
    r = await anon_client.post("/api/webhooks/clerk", content=body, headers=headers)
    assert r.status_code == 400


async def test_user_created_then_updated_then_deleted(anon_client):
    """Full lifecycle through signed webhooks. Cleans up after itself."""
    clerk_uid = f"user_pytest_{uuid.uuid4().hex[:12]}"
    try:
        # user.created
        body, headers = _signed({
            "type": "user.created",
            "data": {
                "id": clerk_uid,
                "first_name": "Pytest", "last_name": "Webhook",
                "primary_email_address_id": "idn_1",
                "email_addresses": [{"id": "idn_1", "email_address": f"{clerk_uid}@pytest.local"}],
            },
        })
        r = await anon_client.post("/api/webhooks/clerk", content=body, headers=headers)
        assert r.status_code == 200, r.text

        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalar_one_or_none()
            assert u is not None
            assert u.email == f"{clerk_uid}@pytest.local"
            assert u.is_active is True
            org_id_created = u.org_id

        # user.updated — should change email & name, not org
        body, headers = _signed({
            "type": "user.updated",
            "data": {
                "id": clerk_uid,
                "first_name": "Pytest", "last_name": "Renamed",
                "primary_email_address_id": "idn_1",
                "email_addresses": [{"id": "idn_1", "email_address": f"updated-{clerk_uid}@pytest.local"}],
            },
        })
        r = await anon_client.post("/api/webhooks/clerk", content=body, headers=headers)
        assert r.status_code == 200

        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalar_one()
            assert u.email == f"updated-{clerk_uid}@pytest.local"
            assert u.name == "Pytest Renamed"
            assert u.org_id == org_id_created

        # user.deleted — soft delete (preserve audit trail)
        body, headers = _signed({"type": "user.deleted", "data": {"id": clerk_uid}})
        r = await anon_client.post("/api/webhooks/clerk", content=body, headers=headers)
        assert r.status_code == 200

        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalar_one()
            assert u.is_active is False
    finally:
        # Always clean up — even if asserts failed mid-way
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalar_one_or_none()
            if user:
                org_id = user.org_id
                await db.execute(delete(User).where(User.id == user.id))
                await db.execute(delete(Organisation).where(Organisation.id == org_id))
                await db.commit()


async def test_user_created_is_idempotent(anon_client):
    """Replaying the same user.created webhook must not create a duplicate."""
    clerk_uid = f"user_pytest_idem_{uuid.uuid4().hex[:8]}"
    payload = {
        "type": "user.created",
        "data": {
            "id": clerk_uid,
            "primary_email_address_id": "idn_1",
            "email_addresses": [{"id": "idn_1", "email_address": f"{clerk_uid}@pytest.local"}],
        },
    }
    try:
        for _ in range(3):
            body, headers = _signed(payload)
            r = await anon_client.post("/api/webhooks/clerk", content=body, headers=headers)
            assert r.status_code == 200

        async with AsyncSessionLocal() as db:
            users = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalars().all()
            assert len(users) == 1
    finally:
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.clerk_user_id == clerk_uid))).scalar_one_or_none()
            if user:
                org_id = user.org_id
                await db.execute(delete(User).where(User.id == user.id))
                await db.execute(delete(Organisation).where(Organisation.id == org_id))
                await db.commit()
