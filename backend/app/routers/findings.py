from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_org, get_current_user, require_analyst
from app.database import get_db
from app.models import Finding, FindingStatus, Organisation, Severity, User

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "findings", "status": "ok"}


@router.get("/stats")
async def findings_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    """Aggregate counts across the org — used by dashboard widgets."""
    sev_q = await db.execute(
        select(Finding.severity, func.count())
        .where(Finding.org_id == org.id)
        .group_by(Finding.severity)
    )
    by_severity = {sev.value: count for sev, count in sev_q.all()}

    status_q = await db.execute(
        select(Finding.status, func.count())
        .where(Finding.org_id == org.id)
        .group_by(Finding.status)
    )
    by_status = {st.value: count for st, count in status_q.all()}

    total = sum(by_severity.values())
    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@router.get("")
async def list_findings(
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    source: str | None = None,
    scan_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    q = select(Finding).where(Finding.org_id == org.id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    if source:
        q = q.where(Finding.source == source)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    q = q.order_by(desc(Finding.first_seen)).limit(limit).offset(offset)
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "cvss_score": f.cvss_score,
            "source": f.source,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
            "killchain_phase": f.killchain_phase,
            "is_in_kev": f.is_in_kev,
            "description": f.description,
            "remediation": f.remediation,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
        }
        for f in rows
    ]


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    finding = (await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org.id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


class FindingPatch(BaseModel):
    status: FindingStatus | None = None
    assigned_to: str | None = None
    notes: str | None = None


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    body: FindingPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    finding = (await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org.id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.status is not None:
        finding.status = body.status
    if body.assigned_to is not None:
        finding.assigned_to = body.assigned_to
    if body.notes is not None:
        finding.notes = body.notes
    await db.commit()
    return {"ok": True, "id": finding.id, "status": finding.status.value}
