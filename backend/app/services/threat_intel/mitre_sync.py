"""
MITRE ATT&CK live sync service.
Pulls the Enterprise ATT&CK STIX 2.1 bundle from the official MITRE CTI
GitHub repo and stores techniques + tactics in Postgres. Runs daily via
Celery Beat so kill-chain and technique mappings stay current rather than
relying on hardcoded tables.
"""
from datetime import datetime, timedelta
import httpx
import structlog
from sqlalchemy import select, update
from app.database import AsyncSessionLocal
from app.models import MitreTechnique, ThreatFeedSync

logger = structlog.get_logger()

# Official MITRE CTI STIX 2.1 bundle (Enterprise ATT&CK)
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Map ATT&CK tactic shortnames → Lockheed kill chain phases
TACTIC_TO_KILLCHAIN = {
    "reconnaissance":         "reconnaissance",
    "resource-development":   "weaponization",
    "initial-access":         "delivery",
    "execution":              "exploitation",
    "persistence":            "installation",
    "privilege-escalation":   "exploitation",
    "defense-evasion":        "exploitation",
    "credential-access":      "exploitation",
    "discovery":              "reconnaissance",
    "lateral-movement":       "actions",
    "collection":             "actions",
    "command-and-control":    "command_control",
    "exfiltration":           "actions",
    "impact":                 "actions",
}


async def sync_mitre_attack() -> dict:
    """Fetch and store the latest MITRE ATT&CK techniques."""
    async with AsyncSessionLocal() as db:
        sync = ThreatFeedSync(feed_name="mitre_attack", status="running")
        db.add(sync)
        await db.commit()
        await db.refresh(sync)
        sync_id = sync.id

    count = 0
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            logger.info("mitre.fetch_start", url=ATTACK_STIX_URL)
            resp = await client.get(ATTACK_STIX_URL)
            resp.raise_for_status()
            bundle = resp.json()

        objects = bundle.get("objects", [])
        stix_version = bundle.get("spec_version", "2.1")

        # Build tactic shortname → name lookup from x-mitre-tactic objects
        tactic_names = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname", "")
                tactic_names[shortname] = obj.get("name", shortname)

        techniques = [
            o for o in objects
            if o.get("type") == "attack-pattern"
            and not o.get("revoked", False)
        ]

        async with AsyncSessionLocal() as db:
            # Preload existing rows in one query. The upsert below used to
            # issue a SELECT per technique — roughly 700 sequential round
            # trips on every sync.
            preload = await db.execute(select(MitreTechnique))
            existing_by_id = {t.technique_id: t for t in preload.scalars().all()}

            for obj in techniques:
                # Extract the Txxxx external ID
                ext_id = None
                url = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id")
                        url = ref.get("url")
                        break
                if not ext_id:
                    continue

                # Tactics come from kill_chain_phases
                tactic_shortnames = [
                    p.get("phase_name")
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ]
                primary_tactic = (
                    tactic_names.get(tactic_shortnames[0], tactic_shortnames[0])
                    if tactic_shortnames else None
                )

                platforms = obj.get("x_mitre_platforms", [])
                is_deprecated = obj.get("x_mitre_deprecated", False)
                description = obj.get("description", "")
                detection = obj.get("x_mitre_detection", "")

                # Upsert
                row = existing_by_id.get(ext_id)

                if row:
                    row.name = obj.get("name", row.name)
                    row.tactic = primary_tactic
                    row.tactic_ids = tactic_shortnames
                    row.description = description
                    row.platforms = platforms
                    row.detection = detection
                    row.url = url
                    row.is_deprecated = is_deprecated
                    row.stix_version = stix_version
                    row.synced_at = datetime.utcnow()
                else:
                    new_row = MitreTechnique(
                        technique_id=ext_id,
                        name=obj.get("name", ext_id),
                        tactic=primary_tactic,
                        tactic_ids=tactic_shortnames,
                        description=description,
                        platforms=platforms,
                        detection=detection,
                        url=url,
                        is_deprecated=is_deprecated,
                        stix_version=stix_version,
                    )
                    db.add(new_row)
                    # Guard against the same ID appearing twice in one bundle,
                    # which would otherwise insert a duplicate.
                    existing_by_id[ext_id] = new_row
                count += 1

                if count % 100 == 0:
                    await db.commit()

            await db.commit()

        async with AsyncSessionLocal() as db:
            await db.execute(
                update(ThreatFeedSync)
                .where(ThreatFeedSync.id == sync_id)
                .values(
                    status="success",
                    records_synced=count,
                    completed_at=datetime.utcnow(),
                )
            )
            await db.commit()

        logger.info("mitre.sync_complete", techniques=count)
        return {"status": "success", "techniques": count}

    except Exception as e:
        logger.error("mitre.sync_failed", error=str(e))
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(ThreatFeedSync)
                .where(ThreatFeedSync.id == sync_id)
                .values(
                    status="failed",
                    error_message=str(e)[:1000],
                    completed_at=datetime.utcnow(),
                )
            )
            await db.commit()
        raise


def _technique_to_dict(t: MitreTechnique) -> dict:
    return {
        "technique_id": t.technique_id,
        "name": t.name,
        "tactic": t.tactic,
        "killchain_phase": TACTIC_TO_KILLCHAIN.get(
            t.tactic_ids[0] if t.tactic_ids else "", "reconnaissance"
        ),
        "description": t.description,
        "detection": t.detection,
        "url": t.url,
    }


async def get_technique(technique_id: str) -> dict | None:
    """Look up a technique by its Txxxx ID from the synced data."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
        )
        t = result.scalar_one_or_none()
        return _technique_to_dict(t) if t else None


async def get_techniques(technique_ids) -> dict[str, dict]:
    """Look up many techniques in one session and one query.

    Callers that enrich a whole scan must use this rather than looping over
    get_technique(): the engine runs with NullPool, so every session is a full
    Postgres connect/auth handshake. A 100-finding scan previously opened 100
    connections in sequence, which dominated scan time and could exhaust
    max_connections.
    """
    ids = {t for t in technique_ids if t}
    if not ids:
        return {}
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id.in_(ids))
        )
        return {t.technique_id: _technique_to_dict(t) for t in result.scalars().all()}


async def enrich_finding_with_attack(finding: dict) -> dict:
    """Attach live ATT&CK metadata to a finding that has a technique ID."""
    tech_id = finding.get("mitre_technique_id")
    if not tech_id:
        return finding
    technique = await get_technique(tech_id)
    if technique:
        finding["mitre_tactic"] = technique["tactic"]
        finding["mitre_detection"] = technique.get("detection")
        finding["mitre_url"] = technique.get("url")
        # Override killchain phase with live ATT&CK mapping
        if technique.get("killchain_phase"):
            finding["killchain_phase"] = technique["killchain_phase"]
    return finding
