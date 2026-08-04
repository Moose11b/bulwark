from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from app.database import get_db
from app.core.auth import get_current_user, get_current_org, require_admin
from app.models import User, Organisation, MitreTechnique, IOC, ThreatFeedSync

router = APIRouter()


@router.get("/status")
async def feed_status(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """Show last sync status for each threat feed."""
    feeds = {}
    for feed_name in ["mitre_attack", "otx", "kev"]:
        r = await db.execute(
            select(ThreatFeedSync)
            .where(ThreatFeedSync.feed_name == feed_name)
            .order_by(desc(ThreatFeedSync.started_at))
            .limit(1)
        )
        sync = r.scalar_one_or_none()
        feeds[feed_name] = {
            "status": sync.status if sync else "never_synced",
            "records": sync.records_synced if sync else 0,
            "last_sync": sync.completed_at if sync else None,
            "error": sync.error_message if sync else None,
        } if sync else {"status": "never_synced", "records": 0, "last_sync": None}

    tech_count = await db.execute(select(func.count(MitreTechnique.id)))
    ioc_count = await db.execute(
        select(func.count(IOC.id)).where(IOC.is_active == True)
    )

    return {
        "feeds": feeds,
        "mitre_techniques": tech_count.scalar(),
        "active_iocs": ioc_count.scalar(),
    }


@router.post("/sync/mitre", status_code=202)
async def trigger_mitre_sync(
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    """Manually trigger a MITRE ATT&CK sync."""
    from app.workers.tasks import sync_mitre_attack
    task = sync_mitre_attack.delay()
    return {"task_id": task.id, "status": "started"}


@router.post("/sync/otx", status_code=202)
async def trigger_otx_sync(
    user: User = Depends(require_admin),
    org: Organisation = Depends(get_current_org),
):
    """Manually trigger an OTX pulse sync."""
    from app.workers.tasks import sync_otx
    task = sync_otx.delay()
    return {"task_id": task.id, "status": "started"}


@router.get("/techniques/{technique_id}")
async def get_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """Look up a MITRE ATT&CK technique from synced data."""
    r = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id.upper())
    )
    t = r.scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Technique not found. Run a MITRE sync first.")
    return {
        "technique_id": t.technique_id, "name": t.name, "tactic": t.tactic,
        "description": t.description, "platforms": t.platforms,
        "detection": t.detection, "url": t.url, "synced_at": t.synced_at,
    }


@router.get("/iocs")
async def list_iocs(
    ioc_type: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """List active IOCs from synced threat feeds."""
    q = select(IOC).where(IOC.is_active == True)
    if ioc_type:
        q = q.where(IOC.ioc_type == ioc_type)
    q = q.order_by(desc(IOC.last_seen)).limit(limit)
    r = await db.execute(q)
    return [
        {
            "indicator": i.indicator, "type": i.ioc_type, "source": i.source,
            "threat_type": i.threat_type, "pulse_name": i.pulse_name,
            "confidence": i.confidence, "tags": i.tags, "last_seen": i.last_seen,
        }
        for i in r.scalars().all()
    ]


@router.get("/lookup/{indicator}")
async def lookup_indicator(
    indicator: str,
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """Live OTX lookup for a single indicator."""
    from app.services.threat_intel.otx import lookup_ioc
    result = await lookup_ioc(indicator)
    if not result:
        return {"indicator": indicator, "found": False}
    return {"indicator": indicator, "found": True, **result}
