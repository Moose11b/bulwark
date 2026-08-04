from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, get_current_user, require_admin
from app.database import get_db
from app.models import Asset, Organisation, ScanSchedule, ScanType, User

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "schedules", "status": "ok"}


def _serialize(s: ScanSchedule) -> dict:
    return {
        "id": s.id,
        "asset_id": s.asset_id,
        "scan_type": s.scan_type.value if s.scan_type else None,
        "cron_expression": s.cron_expression,
        "is_active": s.is_active,
        "last_run_at": s.last_run_at,
        "next_run_at": s.next_run_at,
        "created_at": s.created_at,
    }


@router.get("")
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    rows = (await db.execute(
        select(ScanSchedule).where(ScanSchedule.org_id == org.id).order_by(desc(ScanSchedule.created_at))
    )).scalars().all()
    return [_serialize(s) for s in rows]


class ScheduleCreate(BaseModel):
    asset_id: str
    scan_type: ScanType = ScanType.FULL
    cron_expression: str


@router.post("", status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    asset = (await db.execute(
        select(Asset).where(Asset.id == body.asset_id, Asset.org_id == org.id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    existing = (await db.execute(
        select(ScanSchedule).where(ScanSchedule.asset_id == body.asset_id)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Asset already has a schedule")

    sched = ScanSchedule(
        asset_id=body.asset_id,
        org_id=org.id,
        scan_type=body.scan_type,
        cron_expression=body.cron_expression,
        is_active=True,
    )
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    # Note: RedBeat registration is not wired here yet. The schedule row exists,
    # but the Celery beat scheduler must be configured to pick up changes from
    # ScanSchedule rows for it to actually fire. See workers/scheduler.py (TBD).
    return _serialize(sched)


@router.patch("/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    sched = (await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == org.id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    sched.is_active = not sched.is_active
    await db.commit()
    return _serialize(sched)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    sched = (await db.execute(
        select(ScanSchedule).where(ScanSchedule.id == schedule_id, ScanSchedule.org_id == org.id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(sched)
    await db.commit()
