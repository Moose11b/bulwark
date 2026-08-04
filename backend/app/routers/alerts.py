from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, get_current_user, require_admin
from app.database import get_db
from app.models import AlertConfig, Organisation, Severity, User

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "alerts", "status": "ok"}


def _serialize(c: AlertConfig) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "channel": c.channel,
        "webhook_url": c.webhook_url,
        "email_to": c.email_to,
        "min_severity": c.min_severity.value if c.min_severity else None,
        "on_new_scan": c.on_new_scan,
        "on_critical": c.on_critical,
        "on_new_cve": c.on_new_cve,
        "is_active": c.is_active,
        "created_at": c.created_at,
    }


@router.get("")
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    rows = (await db.execute(
        select(AlertConfig).where(AlertConfig.org_id == org.id).order_by(desc(AlertConfig.created_at))
    )).scalars().all()
    return [_serialize(c) for c in rows]


class AlertCreate(BaseModel):
    name: str
    channel: str  # "slack" | "email"
    webhook_url: str | None = None
    email_to: str | None = None
    min_severity: Severity = Severity.HIGH
    on_new_scan: bool = False
    on_critical: bool = True
    on_new_cve: bool = True


@router.post("", status_code=201)
async def create_alert(
    body: AlertCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    if body.channel == "slack" and not body.webhook_url:
        raise HTTPException(status_code=400, detail="webhook_url required for Slack channel")
    if body.channel == "email" and not body.email_to:
        raise HTTPException(status_code=400, detail="email_to required for email channel")

    cfg = AlertConfig(
        org_id=org.id,
        name=body.name,
        channel=body.channel,
        webhook_url=body.webhook_url,
        email_to=body.email_to,
        min_severity=body.min_severity,
        on_new_scan=body.on_new_scan,
        on_critical=body.on_critical,
        on_new_cve=body.on_new_cve,
        is_active=True,
    )
    db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return _serialize(cfg)


@router.patch("/{alert_id}/toggle")
async def toggle_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    cfg = (await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id, AlertConfig.org_id == org.id)
    )).scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Alert not found")
    cfg.is_active = not cfg.is_active
    await db.commit()
    return _serialize(cfg)


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    cfg = (await db.execute(
        select(AlertConfig).where(AlertConfig.id == alert_id, AlertConfig.org_id == org.id)
    )).scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(cfg)
    await db.commit()
