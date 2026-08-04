import asyncio
import httpx
import structlog
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: set[str] = set()
_kev_loaded = False

# NVD's published limits are 5 requests per rolling 30s window without an API
# key and 50 with one. The previous flat 0.15s delay exceeded both, so lookups
# were being answered with 429s and silently discarded — fast, but useless.
_NVD_DELAY_NO_KEY = 6.0
_NVD_DELAY_WITH_KEY = 0.6

# Ceiling on NVD calls per run. At the keyless rate a scan with hundreds of
# distinct CVEs would otherwise take hours; anything skipped is logged rather
# than dropped silently.
MAX_NVD_LOOKUPS = 50
CLI_MAX_NVD_LOOKUPS = 10

# EPSS takes a comma-separated list; chunk it so the URL stays reasonable.
_EPSS_CHUNK = 100


def _nvd_delay() -> float:
    return _NVD_DELAY_WITH_KEY if settings.nvd_api_key else _NVD_DELAY_NO_KEY


async def _load_kev() -> set[str]:
    global _kev_cache, _kev_loaded
    if _kev_loaded:
        return _kev_cache
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            data = resp.json()
            _kev_cache = {v["cveID"] for v in data.get("vulnerabilities", [])}
            _kev_loaded = True
            logger.info("kev.loaded", count=len(_kev_cache))
    except Exception as e:
        logger.warning("kev.load_failed", error=str(e))
    return _kev_cache


async def _nvd_lookup(cve_id: str) -> dict | None:
    try:
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            resp = await client.get(NVD_URL, params={"cveId": cve_id})
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            vuln = vulns[0]["cve"]
            metrics = vuln.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            cvss_score = None
            if cvss_v3:
                cvss_score = cvss_v3[0]["cvssData"]["baseScore"]
            return {"cvss_score": cvss_score}
    except Exception as e:
        logger.debug("nvd.lookup_failed", cve_id=cve_id, error=str(e))
        return None


async def _epss_lookup(cve_ids: list[str]) -> dict[str, float]:
    """Batch EPSS lookup — returns {cve_id: epss_score}."""
    unique = sorted({c for c in cve_ids if c})
    if not unique:
        return {}

    scores: dict[str, float] = {}
    for i in range(0, len(unique), _EPSS_CHUNK):
        chunk = unique[i:i + _EPSS_CHUNK]
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                data = resp.json()
                scores.update({
                    item["cve"]: float(item["epss"])
                    for item in data.get("data", [])
                })
        except Exception as e:
            logger.debug("epss.lookup_failed", error=str(e))
    return scores


async def _nvd_lookup_many(cve_ids: list[str], max_lookups: int) -> dict[str, float]:
    """Resolve CVSS scores for a set of CVEs, deduplicated and rate-limited.

    Sleeps only *between* real requests. The old code slept once per finding
    whether or not it called NVD, and re-queried the same CVE for every
    finding that referenced it.
    """
    todo = sorted({c for c in cve_ids if c})
    if not todo:
        return {}

    if len(todo) > max_lookups:
        logger.warning(
            "nvd.lookup_capped",
            unique_cves=len(todo), performed=max_lookups,
            skipped=len(todo) - max_lookups,
            hint="set NVD_API_KEY to raise the usable rate",
        )
        todo = todo[:max_lookups]

    delay = _nvd_delay()
    scores: dict[str, float] = {}
    for i, cve_id in enumerate(todo):
        if i:
            await asyncio.sleep(delay)
        nvd = await _nvd_lookup(cve_id)
        if nvd and nvd.get("cvss_score"):
            scores[cve_id] = nvd["cvss_score"]
    return scores


async def enrich_scan_findings(scan_id: str):
    """Enrich all CVE-tagged findings for a scan with NVD/EPSS/KEV data.

    Deliberately three phases — read, network, write — so that no database
    connection is held across the slow rate-limited NVD calls. The engine runs
    with NullPool, so an open session is a real Postgres connection, and the
    previous single-session version could hold one for the entire loop.
    """
    from sqlalchemy import select, update
    from app.database import AsyncSessionLocal
    from app.models import Finding

    # ── Read: snapshot what needs enriching, then release the connection ──
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.cve_id.isnot(None))
        )
        rows = [
            {"id": f.id, "cve_id": f.cve_id, "cvss_score": f.cvss_score}
            for f in result.scalars().all()
        ]

    if not rows:
        logger.info("enrichment.no_cve_findings", scan_id=scan_id)
        return

    # ── Network: no DB connection held here ──────────────────────────────
    kev = await _load_kev()
    epss_map = await _epss_lookup([r["cve_id"] for r in rows])
    cvss_map = await _nvd_lookup_many(
        [r["cve_id"] for r in rows if not r["cvss_score"]],
        MAX_NVD_LOOKUPS,
    )

    # ── Write: reopen briefly and commit once ────────────────────────────
    async with AsyncSessionLocal() as db:
        for r in rows:
            cve_id = r["cve_id"]
            updates: dict = {"is_in_kev": cve_id in kev}
            if cve_id in epss_map:
                updates["epss_score"] = epss_map[cve_id]
            if not r["cvss_score"] and cve_id in cvss_map:
                updates["cvss_score"] = cvss_map[cve_id]

            await db.execute(
                update(Finding).where(Finding.id == r["id"]).values(**updates)
            )
        await db.commit()

    logger.info(
        "enrichment.complete", scan_id=scan_id,
        findings=len(rows), cvss_resolved=len(cvss_map), epss_resolved=len(epss_map),
    )


async def enrich_findings_list(findings: list[dict]) -> list[dict]:
    """
    Standalone enrichment for the CLI/CI path — operates on plain dicts,
    no database. Adds is_in_kev, epss_score, and cvss_score (if missing)
    to any finding that has a cve_id. Network errors are swallowed so a
    scan never fails just because NVD/EPSS were unreachable.
    """
    cve_findings = [f for f in findings if f.get("cve_id")]
    if not cve_findings:
        return findings

    try:
        kev = await _load_kev()
    except Exception:
        kev = set()

    epss_map = await _epss_lookup([f["cve_id"] for f in cve_findings])

    # Tighter cap than the worker path: this runs in a CI gate, where a long
    # rate-limited stall is worse than a missing CVSS score.
    cvss_map = await _nvd_lookup_many(
        [f["cve_id"] for f in cve_findings if not f.get("cvss_score")],
        CLI_MAX_NVD_LOOKUPS,
    )

    for f in cve_findings:
        cve_id = f["cve_id"]
        f["is_in_kev"] = cve_id in kev
        if cve_id in epss_map:
            f["epss_score"] = epss_map[cve_id]
        if not f.get("cvss_score") and cve_id in cvss_map:
            f["cvss_score"] = cvss_map[cve_id]

    return findings
