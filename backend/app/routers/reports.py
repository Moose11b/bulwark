from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os
from app.database import get_db
from app.models import Scan, Finding, ScanStatus
from app.core.auth import get_current_user, get_current_org
from app.models import User, Organisation

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "reports", "status": "ok"}


@router.post("/scan/{scan_id}")
async def generate_report(scan_id: str, report_type: str="full",
    background_tasks: BackgroundTasks=BackgroundTasks(),
    db: AsyncSession=Depends(get_db), user: User=Depends(get_current_user),
    org: Organisation=Depends(get_current_org)):
    r = await db.execute(select(Scan).where(Scan.id==scan_id, Scan.org_id==org.id))
    scan = r.scalar_one_or_none()
    if not scan: raise HTTPException(404,"Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(400,"Scan must be completed before generating a report")
    from app.workers.tasks import generate_report as gen_task
    task = gen_task.delay(scan_id, report_type, user.id)
    return {"task_id":task.id,"status":"generating","message":"Report generation started"}

@router.get("/scan/{scan_id}/download")
async def download_report(scan_id: str, db: AsyncSession=Depends(get_db),
    user: User=Depends(get_current_user), org: Organisation=Depends(get_current_org)):
    r = await db.execute(select(Scan).where(Scan.id==scan_id, Scan.org_id==org.id))
    if not r.scalar_one_or_none(): raise HTTPException(404,"Scan not found")
    path = f"/app/reports/{scan_id}.pdf"
    if not os.path.exists(path):
        raise HTTPException(404,"Report not yet generated. POST /api/reports/scan/{id} first.")
    return FileResponse(path, media_type="application/pdf",
                        filename=f"bulwark-report-{scan_id[:8]}.pdf")

@router.get("/scan/{scan_id}/json")
async def export_json(scan_id: str, db: AsyncSession=Depends(get_db),
    user: User=Depends(get_current_user), org: Organisation=Depends(get_current_org)):
    r = await db.execute(select(Scan).where(Scan.id==scan_id, Scan.org_id==org.id))
    scan = r.scalar_one_or_none()
    if not scan: raise HTTPException(404,"Scan not found")
    fr = await db.execute(select(Finding).where(Finding.scan_id==scan_id))
    findings = fr.scalars().all()
    from app.services.compliance import CONTROL_MAPPING_DISCLAIMER
    return {
        "scan": {"id":scan.id,"target":scan.target,"scan_type":scan.scan_type,
                 "status":scan.status,"risk_score":scan.risk_score,
                 "created_at":scan.created_at,"completed_at":scan.completed_at},
        "findings": [
            {"id":f.id,"title":f.title,"severity":f.severity,"cvss_score":f.cvss_score,
             "cve_id":f.cve_id,"owasp_category":f.owasp_category,
             "killchain_phase":f.killchain_phase,"remediation":f.remediation,
             "compliance":{"pci_dss":f.pci_dss,"iso_27001":f.iso_27001,
                           "nist_csf":f.nist_csf,"cis_v8":getattr(f,"cis_v8",[])}}
            for f in findings
        ],
        "total_findings": len(findings),
        "compliance_disclaimer": CONTROL_MAPPING_DISCLAIMER,
    }
