"""
Pytest fixtures for Bulwark.

Strategy:
- Spin up the FastAPI app in-process via httpx ASGITransport (no network).
- Override get_current_user / get_current_org to inject a test user
  pulled from the live DB. This skips the Clerk JWT verification path
  while still exercising the real router code and real database.
- Tests that create rows clean up after themselves via the cleanup fixture.

Run from /app inside the backend container:
    docker compose exec backend pytest
"""
from __future__ import annotations

import asyncio
import os
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# ── Swap the app's pooled engine for an unpooled one BEFORE importing the
#    app, so every test request gets a fresh connection bound to its own
#    loop. Pooled connections survive across pytest-asyncio's per-function
#    event loops and trigger "Future attached to a different loop" errors.

from app import database as _db
from app.config import get_settings as _get_settings

_test_engine = create_async_engine(_get_settings().database_url, poolclass=NullPool)
_db.engine = _test_engine
_db.AsyncSessionLocal = async_sessionmaker(_test_engine, expire_on_commit=False, autoflush=False, autocommit=False)

from app.core.auth import get_current_org, get_current_user  # noqa: E402
from app.database import AsyncSessionLocal  # noqa: E402  (now the NullPool-backed one)
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    AlertConfig,
    Asset,
    AssetCredential,
    AuditLog,
    Finding,
    Organisation,
    PlanTier,
    ScanSchedule,
    Scan,
    User,
)


TEST_USER_PREFIX = "pytest_user_"
TEST_ORG_NAME_PREFIX = "pytest-org-"


@pytest_asyncio.fixture
async def test_user_and_org():
    """Create an isolated User+Organisation row dedicated to ONE test.

    Function-scoped because session-scoped async fixtures collide with
    pytest-asyncio 0.24's per-test event loops (causes "Future attached to
    a different loop" errors on asyncpg connections).

    Yields (user_id, org_id). Cleaned up at end-of-test along with anything
    tagged to this org (assets/scans/findings/alerts/schedules).
    """
    suffix = uuid.uuid4().hex[:8]
    clerk_uid = f"{TEST_USER_PREFIX}{suffix}"
    org_name = f"{TEST_ORG_NAME_PREFIX}{suffix}"

    async with AsyncSessionLocal() as db:
        org = Organisation(name=org_name, slug=f"pytest-{suffix}", plan=PlanTier.STARTER)
        db.add(org)
        await db.flush()
        user = User(
            clerk_user_id=clerk_uid,
            org_id=org.id,
            email=f"{suffix}@pytest.local",
            name="Pytest User",
            role="admin",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        await db.refresh(org)
        user_id, org_id = user.id, org.id

    yield user_id, org_id

    # Teardown — wipe everything scoped to this org
    async with AsyncSessionLocal() as db:
        await db.execute(delete(Finding).where(Finding.org_id == org_id))
        await db.execute(delete(ScanSchedule).where(ScanSchedule.org_id == org_id))
        await db.execute(delete(Scan).where(Scan.org_id == org_id))
        # Audit rows reference the user, and credentials reference the asset,
        # so both must go before their parents.
        await db.execute(delete(AuditLog).where(AuditLog.org_id == org_id))
        await db.execute(delete(AssetCredential).where(AssetCredential.org_id == org_id))
        await db.execute(delete(Asset).where(Asset.org_id == org_id))
        await db.execute(delete(AlertConfig).where(AlertConfig.org_id == org_id))
        await db.execute(delete(User).where(User.org_id == org_id))
        await db.execute(delete(Organisation).where(Organisation.id == org_id))
        await db.commit()


@pytest_asyncio.fixture
async def test_user(test_user_and_org) -> User:
    user_id, _ = test_user_and_org
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(User).where(User.id == user_id))).scalar_one()


@pytest_asyncio.fixture
async def test_org(test_user_and_org) -> Organisation:
    _, org_id = test_user_and_org
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(Organisation).where(Organisation.id == org_id))).scalar_one()


@pytest_asyncio.fixture
async def client(test_user_and_org):
    """An httpx client with auth dependencies pre-overridden.

    The override re-loads the User/Org per-request to give each handler a
    fresh DB-attached instance (avoids stale ORM session issues).
    """
    user_id, org_id = test_user_and_org

    async def _override_user():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(User).where(User.id == user_id))).scalar_one()

    async def _override_org():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(Organisation).where(Organisation.id == org_id))).scalar_one()

    app.dependency_overrides[get_current_user] = _override_user
    app.dependency_overrides[get_current_org] = _override_org
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_current_org, None)


@pytest_asyncio.fixture
async def anon_client():
    """An httpx client with NO auth overrides — for testing public endpoints
    and verifying that protected endpoints reject unauthenticated requests."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
