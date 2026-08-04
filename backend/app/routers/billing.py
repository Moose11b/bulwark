import stripe
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel

from app.database import get_db
from app.config import get_settings
from app.core.auth import get_current_user, get_current_org
from app.models import Organisation, User, PlanTier

logger = structlog.get_logger()

settings = get_settings()
stripe.api_key = settings.stripe_secret_key
router = APIRouter()

PLAN_LIMITS = {
    PlanTier.STARTER: 25,
    PlanTier.PRO: 250,
    PlanTier.ENTERPRISE: 99999,
}

PLAN_PRICE_MAP = {
    settings.stripe_starter_price_id: PlanTier.STARTER,
    settings.stripe_pro_price_id: PlanTier.PRO,
    settings.stripe_enterprise_price_id: PlanTier.ENTERPRISE,
}


@router.get("/plans")
async def list_plans():
    return [
        {
            "id": "starter",
            "name": "Starter",
            "price_monthly": 49,
            "price_id": settings.stripe_starter_price_id,
            "scan_limit": 25,
            "features": [
                "25 scans/month", "All scan modules", "PDF reports",
                "Slack alerts", "3 team members",
            ],
        },
        {
            "id": "pro",
            "name": "Pro",
            "price_monthly": 149,
            "price_id": settings.stripe_pro_price_id,
            "scan_limit": 250,
            "features": [
                "250 scans/month", "Scheduled scans", "Asset inventory",
                "Compliance mapping", "API access", "10 team members",
            ],
        },
        {
            "id": "enterprise",
            "name": "Enterprise",
            "price_monthly": None,
            "price_id": settings.stripe_enterprise_price_id,
            "scan_limit": "Unlimited",
            "features": [
                "Unlimited scans", "On-premise deployment", "SSO/SAML",
                "SLA", "Dedicated support", "Custom integrations",
            ],
        },
    ]


class CheckoutBody(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str


@router.post("/checkout")
async def create_checkout(
    body: CheckoutBody,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    try:
        session = stripe.checkout.Session.create(
            customer=org.stripe_customer_id or None,
            customer_email=user.email if not org.stripe_customer_id else None,
            payment_method_types=["card"],
            line_items=[{"price": body.price_id, "quantity": 1}],
            mode="subscription",
            success_url=body.success_url + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=body.cancel_url,
            metadata={"org_id": org.id},
        )
        return {"url": session.url}
    except stripe.StripeError as e:
        logger.error("billing.stripe_error", error=str(e))
        raise HTTPException(
            status_code=400,
            detail="Payment processing error. Please try again or contact support.",
        )


@router.post("/portal")
async def create_portal(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    if not org.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account found")
    session = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=f"{settings.allowed_origins.split(',')[0]}/settings/billing",
    )
    return {"url": session.url}


@router.get("/subscription")
async def get_subscription(
    org: Organisation = Depends(get_current_org),
):
    return {
        "plan": org.plan,
        "scan_count_month": org.scan_count_month,
        "scan_limit": org.scan_limit,
        "stripe_subscription_id": org.stripe_subscription_id,
    }
