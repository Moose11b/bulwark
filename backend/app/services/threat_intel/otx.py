"""
AlienVault OTX (Open Threat Exchange) integration.
Pulls subscribed pulses and matches scan targets against known IOCs.
Also stores fresh IOCs in the local database for cross-referencing.
"""
from datetime import datetime, timedelta
import re
import httpx
import structlog
from sqlalchemy import select, update
from app.database import AsyncSessionLocal
from app.models import IOC, ThreatFeedSync
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _headers() -> dict:
    return {"X-OTX-API-KEY": settings.alienvault_api_key}


async def sync_otx_pulses(modified_since_days: int = 7) -> dict:
    """
    Pull recently modified subscribed pulses from OTX and store their
    indicators as IOCs. Runs on a schedule via Celery Beat.
    """
    if not settings.alienvault_api_key:
        logger.warning("otx.no_api_key")
        return {"status": "skipped", "reason": "no API key configured"}

    async with AsyncSessionLocal() as db:
        sync = ThreatFeedSync(feed_name="otx", status="running")
        db.add(sync)
        await db.commit()
        await db.refresh(sync)
        sync_id = sync.id

    count = 0
    try:
        since = (datetime.utcnow() - timedelta(days=modified_since_days)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        async with httpx.AsyncClient(timeout=60, headers=_headers()) as client:
            next_url = f"{OTX_BASE}/pulses/subscribed?modified_since={since}&limit=50"
            page = 0

            while next_url and page < 10:  # cap at 10 pages per run
                resp = await client.get(next_url)
                if resp.status_code != 200:
                    logger.warning("otx.bad_response", status=resp.status_code)
                    break
                data = resp.json()

                batch = [
                    (ind, pulse.get("name", ""), pulse.get("tags", []),
                     pulse.get("references", []))
                    for pulse in data.get("results", [])
                    for ind in pulse.get("indicators", [])
                ]
                count += await _store_iocs(batch)

                next_url = data.get("next")
                page += 1

        async with AsyncSessionLocal() as db:
            await db.execute(
                update(ThreatFeedSync)
                .where(ThreatFeedSync.id == sync_id)
                .values(status="success", records_synced=count,
                        completed_at=datetime.utcnow())
            )
            await db.commit()

        logger.info("otx.sync_complete", iocs=count)
        return {"status": "success", "iocs": count}

    except Exception as e:
        logger.error("otx.sync_failed", error=str(e))
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(ThreatFeedSync)
                .where(ThreatFeedSync.id == sync_id)
                .values(status="failed", error_message=str(e)[:1000],
                        completed_at=datetime.utcnow())
            )
            await db.commit()
        raise


OTX_TYPE_MAP = {
    "domain": "domain", "hostname": "domain",
    "IPv4": "ip", "IPv6": "ip",
    "URL": "url", "URI": "url",
    "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
    "CVE": "cve",
}


# Cap on indicators per session, so the IN clause stays a sane size.
_IOC_CHUNK = 500


async def _store_iocs(batch: list[tuple]) -> int:
    """Upsert a batch of indicators, one session and one commit per chunk.

    The previous per-indicator version opened a session — and with NullPool
    that is a fresh Postgres connect/auth handshake — plus a commit for every
    single IOC, so one sync could open thousands of connections in sequence.
    Keying by indicator value also collapses duplicates within a batch, which
    previously each cost their own round trip.
    """
    parsed: dict[str, dict] = {}
    for indicator, pulse_name, tags, refs in batch:
        value = indicator.get("indicator", "")
        if not value:
            continue
        raw_type = indicator.get("type", "")
        parsed[value] = {
            "raw_type": raw_type,
            "ioc_type": OTX_TYPE_MAP.get(raw_type, "other"),
            "pulse_name": (pulse_name or "")[:255],
            "description": indicator.get("description", ""),
            "tags": (tags or [])[:20],
            "refs": (refs or [])[:10],
        }

    if not parsed:
        return 0

    values = list(parsed)
    now = datetime.utcnow()

    for i in range(0, len(values), _IOC_CHUNK):
        chunk = values[i:i + _IOC_CHUNK]
        async with AsyncSessionLocal() as db:
            existing = await db.execute(
                select(IOC).where(IOC.indicator.in_(chunk), IOC.source == "otx")
            )
            seen = set()
            for row in existing.scalars().all():
                row.last_seen = now
                row.is_active = True
                seen.add(row.indicator)

            for value in chunk:
                if value in seen:
                    continue
                data = parsed[value]
                db.add(IOC(
                    indicator=value,
                    ioc_type=data["ioc_type"],
                    source="otx",
                    threat_type=data["raw_type"],
                    pulse_name=data["pulse_name"],
                    description=data["description"],
                    confidence=60,
                    tags=data["tags"],
                    references=data["refs"],
                    expires_at=now + timedelta(days=90),
                ))
            await db.commit()

    return len(parsed)


async def match_target_against_iocs(target: str) -> list[dict]:
    """
    Check whether a scan target (or its resolved IP) appears in our
    local IOC database. Returns any matches as finding-shaped dicts.
    """
    hostname = re.sub(r"^https?://", "", target).split("/")[0]
    candidates = {hostname}

    # Also resolve to IP. gethostbyname is blocking with no timeout option;
    # run on the loop's resolver thread with a bound so a slow or blackholed
    # nameserver cannot stall the scan indefinitely at this step.
    try:
        import asyncio
        import socket
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=10,
        )
        candidates.update(info[4][0] for info in infos)
    except Exception:
        pass

    matches = []
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IOC).where(IOC.indicator.in_(list(candidates)), IOC.is_active == True)
        )
        for ioc in result.scalars().all():
            matches.append({
                "title": f"Target matches known IOC: {ioc.indicator}",
                "source": "threat_intel",
                "severity": "HIGH" if ioc.confidence >= 70 else "MEDIUM",
                "cwe_id": None,
                "owasp_category": "A06",
                "killchain_phase": "command_control",
                "mitre_technique_id": "T1071",
                "description": (
                    f"The target {ioc.indicator} appears in threat intelligence feed "
                    f"'{ioc.pulse_name}' (source: {ioc.source}). "
                    f"Threat type: {ioc.threat_type}. {ioc.description or ''}"
                ),
                "evidence": f"IOC match — indicator {ioc.indicator}, confidence {ioc.confidence}%",
                "remediation": (
                    "This target matches a known indicator of compromise. Investigate "
                    "immediately for signs of compromise. Review the linked threat intel references."
                ),
                "references": ioc.references or [],
            })

    if matches:
        logger.info("ioc.matches_found", target=hostname, count=len(matches))
    return matches


async def lookup_ioc(indicator: str) -> dict | None:
    """Live OTX lookup for a single indicator (on-demand)."""
    if not settings.alienvault_api_key:
        return None
    # Determine section by indicator shape
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        section = "IPv4"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
        section = "file"
    else:
        section = "domain"

    try:
        async with httpx.AsyncClient(timeout=20, headers=_headers()) as client:
            resp = await client.get(f"{OTX_BASE}/indicators/{section}/{indicator}/general")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "indicator": indicator,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [
                        p.get("name") for p in
                        data.get("pulse_info", {}).get("pulses", [])[:10]
                    ],
                    "reputation": data.get("reputation", 0),
                }
    except Exception as e:
        logger.debug("otx.lookup_failed", indicator=indicator, error=str(e))
    return None
