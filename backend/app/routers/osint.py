import asyncio
from fastapi import APIRouter, Depends

from app.core.auth import get_current_user
from app.models import User
from app.services.osint.scanners import (
    CRTScanner,
    HIBPScanner,
    VirusTotalScanner,
    WaybackScanner,
    WhoisScanner,
)

router = APIRouter()


@router.get("/health")
async def health():
    return {"module": "osint", "status": "ok"}


@router.get("/{target}/full")
async def osint_full(
    target: str,
    user: User = Depends(get_current_user),
):
    """Run all passive OSINT sources against a target in parallel."""
    results = await asyncio.gather(
        WhoisScanner().scan(target),
        CRTScanner().scan(target),
        HIBPScanner().scan(target),
        VirusTotalScanner().scan(target),
        WaybackScanner().scan(target),
        return_exceptions=True,
    )

    def safe(r):
        return r if not isinstance(r, BaseException) else {"error": str(r)}

    return {
        "target": target,
        "whois":      safe(results[0]),
        "crt":        safe(results[1]),
        "hibp":       safe(results[2]),
        "virustotal": safe(results[3]),
        "wayback":    safe(results[4]),
    }
