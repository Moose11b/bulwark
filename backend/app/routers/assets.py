from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.database import get_db
from app.models import Asset, AssetType, RiskTier, Scan, ScanStatus
from app.core.auth import get_current_user, get_current_org, require_analyst, require_admin
from app.models import User, Organisation

router = APIRouter()


class AssetCreate(BaseModel):
    name: str
    target: str
    asset_type: AssetType = AssetType.DOMAIN
    risk_tier: RiskTier = RiskTier.MEDIUM
    owner: str | None = None
    tags: list[str] = []
    notes: str | None = None


class AssetUpdate(BaseModel):
    name: str | None = None
    risk_tier: RiskTier | None = None
    owner: str | None = None
    tags: list[str] | None = None
    notes: str | None = None
    is_active: bool | None = None


@router.get("")
async def list_assets(
    limit: int = 50,
    offset: int = 0,
    risk_tier: RiskTier | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    q = select(Asset).where(Asset.org_id == org.id, Asset.is_active == True)
    if risk_tier:
        q = q.where(Asset.risk_tier == risk_tier)
    q = q.order_by(desc(Asset.created_at)).limit(limit).offset(offset)
    result = await db.execute(q)
    assets = result.scalars().all()

    return [
        {
            "id": a.id, "name": a.name, "target": a.target,
            "asset_type": a.asset_type, "risk_tier": a.risk_tier,
            "owner": a.owner, "tags": a.tags, "notes": a.notes,
            "risk_score": a.risk_score, "last_scan_at": a.last_scan_at,
            "created_at": a.created_at,
        }
        for a in assets
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    from app.core.target_validation import validate_target, TargetValidationError
    try:
        clean_target = validate_target(body.target)
    except TargetValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    asset = Asset(
        org_id=org.id,
        name=body.name,
        target=clean_target,
        asset_type=body.asset_type,
        risk_tier=body.risk_tier,
        owner=body.owner,
        tags=body.tags,
        notes=body.notes,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return {"id": asset.id, "name": asset.name, "target": asset.target}


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get recent scans for this asset
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.asset_id == asset_id)
        .order_by(desc(Scan.created_at))
        .limit(10)
    )
    recent_scans = scans_result.scalars().all()

    return {
        "id": asset.id, "name": asset.name, "target": asset.target,
        "asset_type": asset.asset_type, "risk_tier": asset.risk_tier,
        "owner": asset.owner, "tags": asset.tags, "notes": asset.notes,
        "risk_score": asset.risk_score, "last_scan_at": asset.last_scan_at,
        "created_at": asset.created_at, "updated_at": asset.updated_at,
        "recent_scans": [
            {
                "id": s.id, "scan_type": s.scan_type, "status": s.status,
                "risk_score": s.risk_score, "created_at": s.created_at,
            }
            for s in recent_scans
        ],
    }


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)

    await db.commit()
    return {"id": asset.id, "name": asset.name}


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset.is_active = False
    await db.commit()


@router.post("/{asset_id}/scan", status_code=status.HTTP_202_ACCEPTED)
async def launch_asset_scan(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    """Quick-launch a full scan against an asset."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    from app.models import Scan, ScanType, ScanStatus
    from app.workers.tasks import run_scan

    scan = Scan(
        org_id=org.id,
        asset_id=asset.id,
        created_by_id=user.id,
        target=asset.target,
        scan_type=ScanType.FULL,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    org.scan_count_month += 1
    await db.commit()
    await db.refresh(scan)

    task = run_scan.delay(scan.id)
    scan.celery_task_id = task.id
    await db.commit()

    return {"scan_id": scan.id, "status": "queued"}
