from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel
import redis.asyncio as aioredis
import json
import structlog

from app.database import get_db
from app.models import Scan, Asset, ScanStatus, ScanType, Finding, Severity
from app.core.auth import get_current_user, get_current_org, require_analyst
from app.models import User, Organisation
from app.config import get_settings
from app.workers.tasks import run_scan

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()


class ScanCreate(BaseModel):
    target: str
    scan_type: ScanType = ScanType.FULL
    asset_id: str | None = None
    options: dict = {}


class ScanResponse(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    progress: int
    progress_message: str
    risk_score: float
    finding_counts: dict
    # The scan detail page renders this on failure; without it in the schema
    # the field was stripped from the response and the error panel was blank.
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    class Config:
        from_attributes = True


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    # Plan limit check
    if org.scan_count_month >= org.scan_limit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Monthly scan limit ({org.scan_limit}) reached. Upgrade your plan.",
        )

    # ── SSRF / target validation ─────────────────────────────────
    from app.core.target_validation import validate_target_pinned, TargetValidationError
    from app.core.audit import audit_log
    try:
        from app.core.target_validation import format_target
        validated = validate_target_pinned(body.target)
        # Persist host:port — the worker re-validates scan.target later, and
        # storing a bare host would drop the port before any scanner sees it.
        clean_target = format_target(validated.host, validated.port)
    except TargetValidationError as e:
        # Audit the blocked attempt
        await audit_log(
            db, org_id=org.id, user_id=user.id,
            action="scan.target_blocked",
            resource_type="scan", detail={"target": body.target[:200], "reason": str(e)},
            ip_address=request.client.host if request.client else None,
        )
        await db.commit()
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        org_id=org.id,
        asset_id=body.asset_id,
        created_by_id=user.id,
        target=clean_target,
        scan_type=body.scan_type,
        status=ScanStatus.QUEUED,
        scan_options=body.options,
    )
    db.add(scan)

    # Increment monthly counter
    org.scan_count_month += 1
    await db.commit()
    await db.refresh(scan)

    # Audit the launch
    await audit_log(
        db, org_id=org.id, user_id=user.id,
        action="scan.launched",
        resource_type="scan", resource_id=scan.id,
        detail={"target": clean_target, "scan_type": body.scan_type.value},
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # Dispatch to Celery
    task = run_scan.delay(scan.id)
    scan.celery_task_id = task.id
    await db.commit()

    logger.info("scan.created", scan_id=scan.id, target=scan.target, org=org.id)
    return scan


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    status: ScanStatus | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    q = select(Scan).where(Scan.org_id == org.id).order_by(desc(Scan.created_at))
    if status:
        q = q.where(Scan.status == status)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
    org: Organisation = Depends(get_current_org),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        raise HTTPException(status_code=400, detail="Cannot cancel a finished scan")

    if scan.celery_task_id:
        from app.workers.celery_app import celery_app
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    await db.commit()


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Severity | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    q = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    if status:
        q = q.where(Finding.status == status)
    q = q.limit(limit).offset(offset)

    result = await db.execute(q)
    findings = result.scalars().all()
    return [
        {
            "id": f.id, "title": f.title, "cve_id": f.cve_id,
            "severity": f.severity, "cvss_score": f.cvss_score,
            "epss_score": f.epss_score, "is_in_kev": f.is_in_kev,
            "owasp_category": f.owasp_category, "killchain_phase": f.killchain_phase,
            "mitre_technique_id": f.mitre_technique_id, "source": f.source,
            "description": f.description, "remediation": f.remediation,
            "status": f.status, "first_seen": f.first_seen,
        }
        for f in findings
    ]


@router.get("/{scan_id}/stats")
async def get_scan_stats(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organisation = Depends(get_current_org),
):
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org.id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    counts = {}
    for sev in Severity:
        r = await db.execute(
            select(func.count(Finding.id))
            .where(Finding.scan_id == scan_id, Finding.severity == sev)
        )
        counts[sev.value] = r.scalar()

    return {
        "scan_id": scan_id,
        "risk_score": scan.risk_score,
        "finding_counts": counts,
        "status": scan.status,
        "duration_seconds": (
            (scan.completed_at - scan.started_at).total_seconds()
            if scan.completed_at and scan.started_at else None
        ),
    }


@router.websocket("/{scan_id}/ws")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
    token: str | None = None,
):
    """WebSocket — streams real-time scan progress from Redis pub/sub.

    Requires a valid Clerk token (passed as ?token=... query param) and
    verifies the scan belongs to the authenticated user's org before
    streaming, so scan IDs can't be enumerated by unauthenticated clients.
    """
    # ── Authenticate the socket before accepting ─────────────────
    if not token:
        await websocket.close(code=4401)  # unauthorized
        return

    try:
        from app.core.auth import _verify_clerk_token
        from app.database import AsyncSessionLocal
        from app.models import User, Scan

        payload = await _verify_clerk_token(token)
        clerk_user_id = payload.get("sub")
        if not clerk_user_id:
            await websocket.close(code=4401)
            return

        async with AsyncSessionLocal() as db:
            user_res = await db.execute(
                select(User).where(User.clerk_user_id == clerk_user_id)
            )
            user = user_res.scalar_one_or_none()
            if not user:
                await websocket.close(code=4401)
                return

            # Verify the scan belongs to this user's org
            scan_res = await db.execute(
                select(Scan).where(Scan.id == scan_id, Scan.org_id == user.org_id)
            )
            if not scan_res.scalar_one_or_none():
                await websocket.close(code=4403)  # forbidden / not found
                return
    except Exception:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    r = aioredis.from_url(settings.redis_url)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}:progress")

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            payload = message["data"].decode()
            await websocket.send_text(payload)

            # Close once the scan reaches a terminal state. listen() otherwise
            # blocks forever, holding a Redis connection open for every socket
            # a client ever opened.
            try:
                progress = json.loads(payload).get("progress")
            except (ValueError, AttributeError):
                progress = None
            if progress is not None and (progress >= 100 or progress < 0):
                break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        # A client vanishing mid-send raises transport errors that are not
        # WebSocketDisconnect; without this the pubsub cleanup below is skipped.
        logger.debug("scan_ws.closed", scan_id=scan_id, error=str(exc))
    finally:
        try:
            await pubsub.unsubscribe()
            await pubsub.aclose()
        except Exception:
            pass
        await r.aclose()
