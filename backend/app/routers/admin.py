"""Admin-only endpoints: org-wide user and audit access."""
from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, require_admin
from app.database import get_db
from app.models import AuditLog, Finding, Organisation, Scan, User

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "admin", "status": "ok"}


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    rows = (await db.execute(
        select(User).where(User.org_id == org.id).order_by(desc(User.created_at))
    )).scalars().all()
    return [
        {
            "id": u.id, "clerk_user_id": u.clerk_user_id,
            "email": u.email, "name": u.name,
            "role": u.role, "is_active": u.is_active,
            "last_seen": u.last_seen, "created_at": u.created_at,
        }
        for u in rows
    ]


@router.get("/audit")
async def audit_log(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    rows = (await db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == org.id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
        .offset(offset)
    )).scalars().all()
    return [
        {
            "id": a.id, "user_id": a.user_id,
            "action": a.action,
            "resource_type": a.resource_type, "resource_id": a.resource_id,
            "detail": a.detail, "ip_address": a.ip_address,
            "created_at": a.created_at,
        }
        for a in rows
    ]


@router.get("/stats")
async def org_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    user_count    = (await db.execute(select(func.count()).select_from(User).where(User.org_id == org.id))).scalar() or 0
    scan_count    = (await db.execute(select(func.count()).select_from(Scan).where(Scan.org_id == org.id))).scalar() or 0
    finding_count = (await db.execute(select(func.count()).select_from(Finding).where(Finding.org_id == org.id))).scalar() or 0
    return {
        "org_id": org.id,
        "plan":         org.plan.value if hasattr(org.plan, "value") else org.plan,
        "scan_limit":   org.scan_limit,
        "scans_this_month": org.scan_count_month,
        "totals": {
            "users":    user_count,
            "scans":    scan_count,
            "findings": finding_count,
        },
    }
