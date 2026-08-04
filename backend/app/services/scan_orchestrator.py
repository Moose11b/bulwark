"""
Central scan orchestrator.
Runs scanner modules in sequence, persists findings,
publishes real-time progress via Redis pub/sub,
and triggers post-scan enrichment + alerting.
"""
from datetime import datetime
import asyncio
import json
import structlog
import redis.asyncio as aioredis

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models import Scan, Finding, Asset, ScanStatus, ScanType, Severity

logger = structlog.get_logger()
settings = get_settings()

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
    Severity.PASS: 0,
}


async def _publish(redis_client, scan_id: str, progress: int, message: str):
    payload = json.dumps({"progress": progress, "message": message})
    await redis_client.publish(f"scan:{scan_id}:progress", payload)


async def _update_scan(db, scan, **kwargs):
    for k, v in kwargs.items():
        setattr(scan, k, v)
    await db.commit()


def _coerce_severity(value) -> Severity:
    """Map arbitrary scanner output to a Severity, defaulting to INFO.

    Scanner dicts are untrusted input as far as this module is concerned;
    constructing Severity() directly raises ValueError on anything unexpected
    and would fail a scan that had already finished all of its real work.
    """
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).strip().upper())
    except (ValueError, AttributeError):
        return Severity.INFO


async def _run_stage(redis_client, scan_id: str, name: str,
                     start: int, done: int, timeout: int, factory):
    """Run one scanner stage in isolation and return its findings.

    Returns [] instead of propagating when the scanner raises or overruns, so
    one broken tool degrades a scan rather than destroying it. `timeout` is a
    backstop above each scanner's own internal limit; note that a scanner
    running in a thread executor cannot truly be interrupted, so this frees
    the orchestrator rather than the worker thread.
    """
    await _publish(redis_client, scan_id, start, f"{name}...")
    try:
        findings = await asyncio.wait_for(factory(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("scan.stage_timeout", scan_id=scan_id, stage=name, timeout=timeout)
        await _publish(redis_client, scan_id, done, f"{name} timed out — continuing")
        return []
    except Exception as exc:
        logger.warning("scan.stage_failed", scan_id=scan_id, stage=name, error=str(exc))
        await _publish(redis_client, scan_id, done, f"{name} unavailable — continuing")
        return []

    findings = findings or []
    await _publish(redis_client, scan_id, done, f"{name} complete — {len(findings)} findings")
    return findings


def _make_progress_cb(loop, redis_client, scan_id: str, base: int, span: float):
    """Build a progress callback that is safe to call from a worker thread.

    Nikto and Nuclei run under `run_in_executor`, so their callbacks fire on a
    ThreadPoolExecutor thread where there is no running loop — `create_task`
    there raises RuntimeError and kills the scan. `run_coroutine_threadsafe`
    hands the publish back to the orchestrator's loop and returns a future we
    briefly wait on, so events arrive in order instead of being dropped.

    Progress reporting is cosmetic: it must never fail a scan, so every error
    here is swallowed.
    """
    def _cb(pct, message):
        try:
            pct = max(0, min(100, int(pct)))
            scaled = base + int(pct * span)
            future = asyncio.run_coroutine_threadsafe(
                _publish(redis_client, scan_id, scaled, str(message)), loop
            )
            # Bounded wait: guarantees delivery without letting a stalled loop
            # block the scanner thread indefinitely.
            future.result(timeout=5)
        except Exception as exc:
            logger.debug("progress.publish_failed", scan_id=scan_id, error=str(exc))

    return _cb


async def orchestrate_scan(scan_id: str, celery_task=None):
    """Main entry point called by the Celery worker.

    Owns the Redis client so it is released on every exit path, including the
    failure path that re-raises for Celery's retry handling.
    """
    r = aioredis.from_url(settings.redis_url)
    try:
        return await _orchestrate_scan(r, scan_id, celery_task)
    finally:
        await r.aclose()


async def _orchestrate_scan(r, scan_id: str, celery_task=None):
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error("scan.not_found", scan_id=scan_id)
            return

        await _update_scan(
            db, scan,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
            progress=2,
            progress_message="Initialising scan...",
        )
        await _publish(r, scan_id, 2, "Initialising scan...")

        target = scan.target
        scan_type = scan.scan_type
        all_findings = []

        # ── Re-validate + pin the target IP ──────────────────────
        # The scan may have sat in the queue for a while since the API
        # validated it, so re-validate here and pin the resolved IP. The
        # pinnable scanners connect to this exact IP (closing the DNS-rebind
        # window); subprocess scanners re-check just before launch.
        from app.core.target_validation import validate_target_pinned, TargetValidationError
        try:
            validated = validate_target_pinned(target)
            target, port, pinned_ip = validated.host, validated.port, validated.pinned_ip
        except TargetValidationError as exc:
            logger.warning("orchestrator.target_blocked", scan_id=scan_id, error=str(exc))
            await _update_scan(
                db, scan,
                status=ScanStatus.FAILED,
                completed_at=datetime.utcnow(),
                progress=100,
                progress_message=f"Target rejected: {exc}",
            )
            await _publish(r, scan_id, 100, f"Target rejected: {exc}")
            return

        try:
            # ── Scanner dispatch ─────────────────────────────────
            # Every stage is isolated: a scanner that raises or hangs is
            # logged and skipped rather than discarding the whole scan. The
            # CLI engine has always behaved this way (standalone_engine wraps
            # each scanner); the orchestrator did not, so a single missing
            # binary — nmap in particular — failed the entire GUI scan.
            loop = asyncio.get_running_loop()

            if scan_type in (ScanType.FULL, ScanType.NMAP):
                from app.services.scanners.nmap_scanner import NmapScanner
                all_findings += await _run_stage(
                    r, scan_id, "Port scan", 10, 22, 420,
                    lambda: NmapScanner().scan(target, lambda p, m: None),
                )

            if scan_type in (ScanType.FULL, ScanType.SSL):
                from app.services.scanners.ssl_scanner import SSLScanner
                all_findings += await _run_stage(
                    r, scan_id, "SSL/TLS analysis", 25, 35, 120,
                    lambda: SSLScanner().scan(target, pinned_ip=pinned_ip, port=port),
                )

            if scan_type in (ScanType.FULL, ScanType.HEADERS):
                from app.services.scanners.header_scanner import HeaderScanner
                all_findings += await _run_stage(
                    r, scan_id, "HTTP header audit", 38, 46, 90,
                    lambda: HeaderScanner().scan(target, pinned_ip=pinned_ip, port=port),
                )

            if scan_type in (ScanType.FULL, ScanType.DNS):
                from app.services.scanners.dns_scanner import DNSScanner
                all_findings += await _run_stage(
                    r, scan_id, "DNS reconnaissance", 48, 56, 300,
                    lambda: DNSScanner().scan(target),
                )

            if scan_type in (ScanType.FULL, ScanType.NIKTO):
                from app.services.scanners.nikto_scanner import NiktoScanner
                all_findings += await _run_stage(
                    r, scan_id, "Nikto web scan", 58, 68, 480,
                    lambda: NiktoScanner().scan(
                        target,
                        _make_progress_cb(loop, r, scan_id, 58, 0.10),
                        pinned_ip=pinned_ip,
                        port=port,
                    ),
                )

            if scan_type in (ScanType.FULL, ScanType.NUCLEI):
                from app.services.scanners.nuclei_scanner import NucleiScanner
                all_findings += await _run_stage(
                    r, scan_id, "Nuclei templates", 70, 82, 780,
                    lambda: NucleiScanner().scan(
                        target,
                        _make_progress_cb(loop, r, scan_id, 70, 0.12),
                        pinned_ip=pinned_ip,
                        port=port,
                    ),
                )

            if scan_type in (ScanType.FULL, ScanType.EXPOSURE):
                from app.services.scanners.exposure_scanner import ExposureScanner
                all_findings += await _run_stage(
                    r, scan_id, "Sensitive file exposure", 82, 86, 180,
                    lambda: ExposureScanner().scan(target, pinned_ip=pinned_ip, port=port),
                )

            # ── Shodan passive exposure intel ────────────────────
            if scan_type in (ScanType.FULL, ScanType.SHODAN):
                from app.services.threat_intel.shodan_scanner import ShodanScanner
                all_findings += await _run_stage(
                    r, scan_id, "Shodan exposure data", 87, 88, 90,
                    lambda: ShodanScanner().scan(target),
                )

            # ── Passive OSINT ────────────────────────────────────
            # Produces reference data rather than findings, so it is stored on
            # the scan row instead of the findings table. Not part of FULL —
            # it is a separate profile so FULL's runtime stays bounded.
            if scan_type == ScanType.OSINT:
                await _publish(r, scan_id, 88, "Collecting passive OSINT...")
                osint_data = await _collect_osint(target)
                scan.raw_results = {**(scan.raw_results or {}), "osint": osint_data}
                await db.commit()
                await _publish(r, scan_id, 89, "OSINT collection complete")

            # ── Threat intel IOC matching ────────────────────────
            await _publish(r, scan_id, 89, "Cross-referencing threat intelligence...")
            try:
                from app.services.threat_intel.otx import match_target_against_iocs
                ioc_matches = await match_target_against_iocs(target)
                all_findings.extend(ioc_matches)
                if ioc_matches:
                    await _publish(r, scan_id, 90, f"⚠ {len(ioc_matches)} IOC match(es) found")
            except Exception as exc:
                logger.warning("ioc_match.failed", error=str(exc))

            # ── Enrich + classify findings ───────────────────────
            await _publish(r, scan_id, 91, "Classifying and enriching findings...")
            enriched = await _enrich_and_classify(all_findings)

            # ── Persist findings ─────────────────────────────────
            await _publish(r, scan_id, 93, "Saving findings...")
            persisted = await _persist_findings(db, scan, enriched)

            # ── Calculate risk score ─────────────────────────────
            # Severity is coerced rather than constructed directly: an
            # unrecognised value from a scanner must not fail a scan that has
            # already completed all of its actual work.
            risk_score = min(100.0, sum(
                SEVERITY_WEIGHT.get(_coerce_severity(f.get("severity")), 0)
                for f in enriched
            ))
            counts = {}
            for sev in Severity:
                counts[sev.value] = sum(
                    1 for f in enriched
                    if _coerce_severity(f.get("severity")) is sev
                )

            await _update_scan(
                db, scan,
                status=ScanStatus.COMPLETED,
                progress=100,
                progress_message="Scan complete",
                risk_score=risk_score,
                finding_counts=counts,
                completed_at=datetime.utcnow(),
            )

            # Update asset last_scan_at
            if scan.asset_id:
                from sqlalchemy import update
                await db.execute(
                    update(Asset)
                    .where(Asset.id == scan.asset_id)
                    .values(last_scan_at=datetime.utcnow(), risk_score=risk_score)
                )
                await db.commit()

            await _publish(r, scan_id, 100, "Scan complete")
            logger.info(
                "scan.completed", scan_id=scan_id,
                findings=len(enriched), risk=risk_score
            )

            # ── Trigger post-scan tasks ──────────────────────────
            # Guarded separately: the scan is already COMPLETED and committed
            # above, so a broker hiccup here must not roll it back to FAILED
            # and re-run the whole thing on Celery's retry.
            try:
                from app.workers.tasks import enrich_findings, send_alert
                enrich_findings.delay(scan_id)

                # IDs come from the persisted rows — the enriched dicts have no
                # primary key, so the old lookup always produced an empty list
                # and alerts silently never fired.
                critical_ids = [
                    f.id for f in persisted
                    if f.severity in (Severity.CRITICAL, Severity.HIGH)
                ]
                if critical_ids:
                    send_alert.delay(scan.org_id, scan_id, critical_ids)
            except Exception as exc:
                logger.error(
                    "scan.post_tasks_failed", scan_id=scan_id, error=str(exc)
                )

        except Exception as exc:
            logger.exception("scan.error", scan_id=scan_id, error=str(exc))
            await _update_scan(
                db, scan,
                status=ScanStatus.FAILED,
                progress=0,
                progress_message=f"Error: {str(exc)[:200]}",
                error_message=str(exc),
                completed_at=datetime.utcnow(),
            )
            await _publish(r, scan_id, -1, f"Scan failed: {str(exc)[:200]}")
            raise


async def _enrich_and_classify(raw_findings: list[dict]) -> list[dict]:
    """Run OWASP and kill chain classifiers over raw scanner output,
    then overlay live MITRE ATT&CK metadata where a technique ID exists."""
    from app.services.analysis import (
        classify_vulnerability, classify_to_phase, map_compliance,
    )
    from app.services.threat_intel.mitre_sync import get_techniques

    # One batched lookup for the whole scan. Enriching per finding opened a
    # fresh Postgres connection each time, which on a large scan took longer
    # than the scanning itself and looked like a hang at 91%.
    try:
        techniques = await get_techniques(
            f.get("mitre_technique_id") for f in raw_findings
        )
    except Exception as exc:
        logger.warning("mitre.batch_lookup_failed", error=str(exc))
        techniques = {}

    enriched = []
    for f in raw_findings:
        owasp_cat, _ = classify_vulnerability(f)
        phase_id, _ = classify_to_phase(f)
        compliance = map_compliance(f)

        item = {
            **f,
            "owasp_category": f.get("owasp_category") or owasp_cat,
            "killchain_phase": f.get("killchain_phase") or phase_id,
            "pci_dss": compliance.get("pci_dss", []),
            "iso_27001": compliance.get("iso_27001", []),
            "nist_csf": compliance.get("nist_csf", []),
            "cis_v8": compliance.get("cis_v8", []),
        }

        # Overlay live ATT&CK data (updates tactic + killchain phase from synced feed)
        technique = techniques.get(item.get("mitre_technique_id"))
        if technique:
            item["mitre_tactic"] = technique["tactic"]
            item["mitre_detection"] = technique.get("detection")
            item["mitre_url"] = technique.get("url")
            if technique.get("killchain_phase"):
                item["killchain_phase"] = technique["killchain_phase"]

        enriched.append(item)

    return enriched


async def _persist_findings(db, scan: Scan, findings: list[dict]) -> list[Finding]:
    """Bulk-insert Finding rows, sanitising untrusted scanner output first.

    Returns the persisted rows so callers can reference real primary keys
    (alert dispatch needs them; the raw finding dicts have none).
    """
    from app.core.audit import sanitize_finding
    rows: list[Finding] = []
    for f in findings:
        # Strip control chars / HTML from scanner-derived text fields
        f = sanitize_finding(f)
        severity = _coerce_severity(f.get("severity"))

        finding = Finding(
            scan_id=scan.id,
            org_id=scan.org_id,
            title=f.get("title") or f.get("check") or f.get("cve_id") or "Unknown",
            cve_id=f.get("cve_id"),
            cwe_id=f.get("cwe_id"),
            source=f.get("source", "unknown"),
            severity=severity,
            cvss_score=float(f.get("cvss_score") or 0),
            owasp_category=f.get("owasp_category"),
            killchain_phase=f.get("killchain_phase"),
            mitre_technique_id=f.get("mitre_technique_id"),
            mitre_tactic=f.get("mitre_tactic"),
            pci_dss=f.get("pci_dss", []),
            iso_27001=f.get("iso_27001", []),
            nist_csf=f.get("nist_csf", []),
            cis_v8=f.get("cis_v8", []),
            description=f.get("description") or f.get("detail"),
            evidence=f.get("evidence"),
            remediation=f.get("remediation"),
            references=f.get("references", []),
            raw_output=str(f.get("raw_output") or "")[:4000],
        )
        db.add(finding)
        rows.append(finding)

    await db.commit()
    return rows


async def _collect_osint(target: str) -> dict:
    """Run the passive OSINT collectors, tolerating individual failures.

    All three live in app.services.osint.scanners — the previous per-scanner
    module paths never existed, so this whole phase raised ImportError.
    """
    from app.services.osint.scanners import (
        CRTScanner, WhoisScanner, HIBPScanner,
    )

    collectors = {
        "crt": CRTScanner(),
        "whois": WhoisScanner(),
        "hibp": HIBPScanner(),
    }

    osint_data: dict = {}
    for name, collector in collectors.items():
        try:
            osint_data[name] = await asyncio.wait_for(
                collector.scan(target), timeout=60
            )
        except Exception as exc:
            logger.warning("osint.collector_failed", collector=name, error=str(exc))
            osint_data[name] = {"error": "collector unavailable"}
    return osint_data


async def run_osint_phase(scan_id: str):
    """OSINT enrichment — runs after main scan completes."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        osint_data = await _collect_osint(scan.target)

        from sqlalchemy import update
        results = dict(scan.raw_results or {})
        results["osint"] = osint_data
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(raw_results=results)
        )
        await db.commit()


async def launch_scheduled(asset_id: str, scan_type: str):
    """Create and queue a scan for a scheduled asset."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return

        # Use org's first admin as the creator
        from app.models import User
        user_result = await db.execute(
            select(User)
            .where(User.org_id == asset.org_id, User.role == "admin")
            .limit(1)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return

        scan = Scan(
            org_id=asset.org_id,
            asset_id=asset.id,
            created_by_id=user.id,
            target=asset.target,
            scan_type=ScanType(scan_type),
            status=ScanStatus.QUEUED,
            scan_options={"scheduled": True},
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        from app.workers.tasks import run_scan
        task = run_scan.delay(scan.id)
        scan.celery_task_id = task.id
        await db.commit()

        logger.info("scheduled_scan.launched", asset_id=asset_id, scan_id=scan.id)
