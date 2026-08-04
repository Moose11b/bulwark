from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, get_current_user
from app.database import get_db
from app.models import Finding, Organisation, Scan, User
from app.services.analysis import build_killchain_report

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "killchain", "status": "ok"}


@router.get("/scan/{scan_id}")
async def killchain_for_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    scan = (await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    rows = (await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )).scalars().all()

    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if f.severity else "INFO",
            "cvss_score": f.cvss_score,
            "source": f.source,
            "cve_id": f.cve_id,
            "killchain_phase": f.killchain_phase,
            "description": f.description,
        }
        for f in rows
    ]
    return build_killchain_report(scan_id, findings)
