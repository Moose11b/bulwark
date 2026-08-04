from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models import Finding, Scan, User, Organisation
from app.core.auth import get_current_user, get_current_org

router = APIRouter()

FRAMEWORKS = ["pci_dss", "iso_27001", "nist_csf", "cis_v8"]


@router.get("/health")
async def health():
    return {"module": "compliance", "status": "ok"}


@router.get("/disclaimer")
async def compliance_disclaimer():
    """Return the control-mapping disclaimer text."""
    from app.services.compliance import CONTROL_MAPPING_DISCLAIMER, FRAMEWORK_LABELS
    return {"disclaimer": CONTROL_MAPPING_DISCLAIMER, "frameworks": FRAMEWORK_LABELS}


@router.get("/scan/{scan_id}")
async def compliance_report(scan_id: str, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user), org: Organisation = Depends(get_current_org)):
    r = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id))
    if not r.scalar_one_or_none():
        raise HTTPException(404, "Scan not found")

    findings_r = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.org_id == org.id)
    )
    findings = findings_r.scalars().all()

    from app.services.compliance import (
        control_name, CONTROL_MAPPING_DISCLAIMER, FRAMEWORK_LABELS,
    )

    # Build per-framework control → findings maps
    maps: dict[str, dict] = {fw: {} for fw in FRAMEWORKS}
    for f in findings:
        fw_values = {
            "pci_dss": f.pci_dss, "iso_27001": f.iso_27001,
            "nist_csf": f.nist_csf, "cis_v8": getattr(f, "cis_v8", None),
        }
        for fw in FRAMEWORKS:
            for ctrl in (fw_values[fw] or []):
                maps[fw].setdefault(ctrl, []).append(
                    {"id": f.id, "title": f.title, "severity": f.severity.value}
                )

    def serialise(fw: str):
        return [
            {
                "control": ctrl,
                "name": control_name(fw, ctrl),
                "findings": items,
                "count": len(items),
            }
            for ctrl, items in sorted(maps[fw].items())
        ]

    result = {
        "scan_id": scan_id,
        # Matches the OWASP report shape, which callers and the dashboard
        # already rely on for a headline count.
        "total_findings": len(findings),
        "disclaimer": CONTROL_MAPPING_DISCLAIMER,
        "framework_labels": FRAMEWORK_LABELS,
    }
    for fw in FRAMEWORKS:
        result[fw] = serialise(fw)
        result[f"{fw}_controls_hit"] = len(maps[fw])

    return result
