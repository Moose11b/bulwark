import re
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from svix.webhooks import Webhook, WebhookVerificationError
import structlog

from app.config import get_settings
from app.database import get_db
from app.models import Organisation, PlanTier, User

router = APIRouter()
logger = structlog.get_logger()
settings = get_settings()


@router.get("/health")
async def health():
    return {"module": "webhooks", "status": "ok"}


@router.post("/clerk")
async def clerk_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    if not settings.clerk_webhook_secret or settings.clerk_webhook_secret == "whsec_changeme":
        raise HTTPException(status_code=500, detail="CLERK_WEBHOOK_SECRET not configured")

    body = await request.body()
    headers = {
        "svix-id": request.headers.get("svix-id", ""),
        "svix-timestamp": request.headers.get("svix-timestamp", ""),
        "svix-signature": request.headers.get("svix-signature", ""),
    }

    try:
        payload = Webhook(settings.clerk_webhook_secret).verify(body, headers)
    except WebhookVerificationError as exc:
        logger.warning("clerk.webhook.invalid_signature", error=str(exc))
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = payload.get("type")
    data = payload.get("data") or {}
    logger.info("clerk.webhook.received", type=event_type, id=data.get("id"))

    handlers = {
        "user.created": _user_created,
        "user.updated": _user_updated,
        "user.deleted": _user_deleted,
        "organization.created": _org_created,
        "organization.updated": _org_updated,
        "organization.deleted": _org_deleted,
        "organizationMembership.created": _membership_created,
    }
    handler = handlers.get(event_type)
    if handler:
        await handler(db, data)
    else:
        logger.info("clerk.webhook.ignored", type=event_type)

    return {"ok": True}


# ── Helpers ──────────────────────────────────────────────────────


def _primary_email(data: dict) -> str:
    emails = data.get("email_addresses") or []
    primary_id = data.get("primary_email_address_id")
    for entry in emails:
        if entry.get("id") == primary_id:
            return entry.get("email_address", "")
    return emails[0].get("email_address", "") if emails else ""


def _full_name(data: dict) -> str | None:
    name = f"{data.get('first_name') or ''} {data.get('last_name') or ''}".strip()
    return name or None


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-") or "org"


async def _unique_slug(db: AsyncSession, base: str) -> str:
    slug = _slugify(base)
    candidate = slug
    suffix = 1
    while True:
        existing = await db.execute(
            select(Organisation).where(Organisation.slug == candidate)
        )
        if existing.scalar_one_or_none() is None:
            return candidate
        suffix += 1
        candidate = f"{slug}-{suffix}"


# ── User events ──────────────────────────────────────────────────


async def _user_created(db: AsyncSession, data: dict) -> None:
    clerk_user_id = data.get("id")
    if not clerk_user_id:
        return

    existing = await db.execute(select(User).where(User.clerk_user_id == clerk_user_id))
    if existing.scalar_one_or_none():
        return  # idempotent — webhook redelivery

    email = _primary_email(data)
    org_base = email.split("@")[0] if email else clerk_user_id
    slug = await _unique_slug(db, org_base)

    org = Organisation(
        name=f"{org_base}'s workspace",
        slug=slug,
        plan=PlanTier.STARTER,
    )
    db.add(org)
    await db.flush()

    db.add(User(
        clerk_user_id=clerk_user_id,
        org_id=org.id,
        email=email,
        name=_full_name(data),
        role="admin",
    ))


async def _user_updated(db: AsyncSession, data: dict) -> None:
    result = await db.execute(select(User).where(User.clerk_user_id == data.get("id")))
    user = result.scalar_one_or_none()
    if not user:
        return
    if email := _primary_email(data):
        user.email = email
    if name := _full_name(data):
        user.name = name


async def _user_deleted(db: AsyncSession, data: dict) -> None:
    result = await db.execute(select(User).where(User.clerk_user_id == data.get("id")))
    user = result.scalar_one_or_none()
    if user:
        user.is_active = False


# ── Organization events ──────────────────────────────────────────


async def _org_created(db: AsyncSession, data: dict) -> None:
    clerk_org_id = data.get("id")
    if not clerk_org_id:
        return

    existing = await db.execute(
        select(Organisation).where(Organisation.clerk_org_id == clerk_org_id)
    )
    if existing.scalar_one_or_none():
        return

    name = data.get("name") or clerk_org_id
    slug = await _unique_slug(db, data.get("slug") or name)
    db.add(Organisation(clerk_org_id=clerk_org_id, name=name, slug=slug))


async def _org_updated(db: AsyncSession, data: dict) -> None:
    result = await db.execute(
        select(Organisation).where(Organisation.clerk_org_id == data.get("id"))
    )
    org = result.scalar_one_or_none()
    if not org:
        return
    if name := data.get("name"):
        org.name = name


async def _org_deleted(db: AsyncSession, data: dict) -> None:
    result = await db.execute(
        select(Organisation).where(Organisation.clerk_org_id == data.get("id"))
    )
    org = result.scalar_one_or_none()
    if org:
        org.is_active = False


async def _membership_created(db: AsyncSession, data: dict) -> None:
    clerk_org_id = (data.get("organization") or {}).get("id")
    clerk_user_id = (data.get("public_user_data") or {}).get("user_id")
    if not clerk_org_id or not clerk_user_id:
        return

    org_result = await db.execute(
        select(Organisation).where(Organisation.clerk_org_id == clerk_org_id)
    )
    org = org_result.scalar_one_or_none()
    user_result = await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )
    user = user_result.scalar_one_or_none()
    if not org or not user:
        return

    user.org_id = org.id
    if "admin" in (data.get("role") or ""):
        user.role = "admin"
