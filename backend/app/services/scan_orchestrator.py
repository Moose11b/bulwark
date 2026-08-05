"""
Central scan orchestrator.
Runs scanner modules concurrently (bounded), persists findings,
publishes real-time progress via Redis pub/sub,
and triggers post-scan enrichment + alerting.
"""
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
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


@dataclass(frozen=True)
class _Stage:
    """One scanner run: a display name, a hard timeout, and a thunk.

    factory receives the progress callback and is deferred, so a stage that is
    never scheduled never constructs its scanner. Scanners with no sub-progress
    reporting simply ignore the argument.
    """
    name: str
    timeout: int
    factory: Callable[[Callable], Awaitable[list[dict]]]


class _ScanProgress:
    """Progress accounting shared by concurrently running stages.

    Stages used to own fixed percentage bands, which only worked because they
    ran one at a time. Running in parallel, a scanner's own 0-100 sub-progress
    cannot drive the overall bar — interleaved scanners would send it jumping
    backwards. So the percentage advances only as whole stages finish, and a
    scanner's own progress updates the message text at the current percentage.
    """

    def __init__(self, redis_client, scan_id: str, start: int, end: int, total: int):
        self._redis = redis_client
        self._scan_id = scan_id
        self._start = start
        self._end = end
        self._total = max(1, total)
        self._completed = 0
        self._lock = asyncio.Lock()

    @property
    def pct(self) -> int:
        span = self._end - self._start
        return self._start + int(self._completed / self._total * span)

    async def publish(self, message: str) -> None:
        await _publish(self._redis, self._scan_id, self.pct, message)

    async def stage_finished(self, message: str) -> None:
        async with self._lock:
            self._completed += 1
            await _publish(
                self._redis, self._scan_id, self.pct,
                f"{message} ({self._completed}/{self._total})",
            )


def _make_progress_cb(loop, progress: _ScanProgress):
    """Build a progress callback safe to call from a scanner's worker thread.

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
            future = asyncio.run_coroutine_threadsafe(
                progress.publish(str(message)), loop
            )
            # Bounded wait: guarantees delivery without letting a stalled loop
            # block the scanner thread indefinitely.
            future.result(timeout=5)
        except Exception as exc:
            logger.debug("progress.publish_failed", error=str(exc))

    return _cb


async def _run_stages(redis_client, scan_id: str, stages: list[_Stage],
                      start: int, end: int) -> list[dict]:
    """Run scanner stages concurrently and return their combined findings.

    Stages are independent — different protocols, no shared state — and used to
    run one after another. Sequentially the worst-case FULL scan totalled about
    41 minutes against Celery's 30 minute soft limit, so slow scans were killed
    before they could finish.

    Concurrency is bounded rather than unlimited. Every active scanner points
    at the same host, and firing Nikto, Nuclei, the 35 parallel exposure
    probes, and the header check simultaneously is a lot of load to put on
    someone's server. The cap keeps the wall-clock win (bounded by the single
    slowest scanner) without turning a scan into a stress test.

    A stage that raises or overruns yields [] and is logged; one broken tool
    degrades a scan rather than destroying it. Note that a scanner running in a
    thread executor cannot truly be interrupted, so the timeout frees the
    orchestrator, not the worker thread.
    """
    if not stages:
        return []

    progress = _ScanProgress(redis_client, scan_id, start, end, len(stages))
    progress_cb = _make_progress_cb(asyncio.get_running_loop(), progress)
    semaphore = asyncio.Semaphore(max(1, settings.scan_stage_concurrency))

    await _publish(
        redis_client, scan_id, start,
        f"Running {len(stages)} scanner(s): {', '.join(s.name for s in stages)}",
    )

    async def _run(stage: _Stage) -> list[dict]:
        async with semaphore:
            try:
                findings = await asyncio.wait_for(
                    stage.factory(progress_cb), timeout=stage.timeout
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "scan.stage_timeout", scan_id=scan_id,
                    stage=stage.name, timeout=stage.timeout,
                )
                await progress.stage_finished(f"{stage.name} timed out — continuing")
                return []
            except Exception as exc:
                logger.warning(
                    "scan.stage_failed", scan_id=scan_id,
                    stage=stage.name, error=str(exc),
                )
                await progress.stage_finished(f"{stage.name} unavailable — continuing")
                return []

        findings = findings or []
        await progress.stage_finished(f"{stage.name} complete — {len(findings)} findings")
        return findings

    results = await asyncio.gather(*(_run(s) for s in stages))
    return [f for group in results for f in group]


async def _load_credential(db, scan: Scan):
    """Decrypt the asset's scan credential, if one is configured.

    Held in memory for the duration of the scan only. A decryption failure is
    surfaced rather than swallowed: scanning unauthenticated while believing
    otherwise would report a clean result for a surface never reached.

    Only applies to asset-linked scans; an ad-hoc target scan has no place to
    have stored a credential.
    """
    if not scan.asset_id:
        return None

    from sqlalchemy import select
    from app.core.pinned_connection import ScanCredential
    from app.core.secrets import decrypt_secret
    from app.models import AssetCredential, AuthType

    record = (await db.execute(
        select(AssetCredential).where(AssetCredential.asset_id == scan.asset_id)
    )).scalar_one_or_none()
    if not record:
        return None

    secret = decrypt_secret(record.secret_encrypted)

    if record.auth_type == AuthType.COOKIE:
        return ScanCredential("Cookie", secret)
    if record.auth_type == AuthType.BEARER:
        return ScanCredential("Authorization", f"Bearer {secret}")
    return ScanCredential(record.header_name or "Authorization", secret)


def _build_stages(scan_type, target, pinned_ip, port, credential=None) -> list[_Stage]:
    """Select the scanners this scan type runs.

    Timeouts are backstops sitting above each tool's own internal limit, not
    expected durations.
    """
    from app.services.scanners.dns_scanner import DNSScanner
    from app.services.scanners.exposure_scanner import ExposureScanner
    from app.services.scanners.header_scanner import HeaderScanner
    from app.services.scanners.nikto_scanner import NiktoScanner
    from app.services.scanners.nmap_scanner import NmapScanner
    from app.services.scanners.nuclei_scanner import NucleiScanner
    from app.services.scanners.ssl_scanner import SSLScanner
    from app.services.threat_intel.shodan_scanner import ShodanScanner

    full = scan_type == ScanType.FULL
    candidates = [
        (ScanType.NMAP, _Stage(
            "Port scan", 420,
            lambda cb: NmapScanner().scan(target, cb),
        )),
        (ScanType.SSL, _Stage(
            "SSL/TLS analysis", 120,
            lambda cb: SSLScanner().scan(target, cb, pinned_ip=pinned_ip, port=port,
                                        credential=credential),
        )),
        (ScanType.HEADERS, _Stage(
            "HTTP header audit", 90,
            lambda cb: HeaderScanner().scan(target, cb, pinned_ip=pinned_ip, port=port,
                                           credential=credential),
        )),
        (ScanType.DNS, _Stage(
            "DNS reconnaissance", 300,
            lambda cb: DNSScanner().scan(target, cb),
        )),
        (ScanType.NIKTO, _Stage(
            "Nikto web scan", 480,
            lambda cb: NiktoScanner().scan(target, cb, pinned_ip=pinned_ip, port=port),
        )),
        (ScanType.NUCLEI, _Stage(
            "Nuclei templates", 780,
            lambda cb: NucleiScanner().scan(target, cb, pinned_ip=pinned_ip, port=port),
        )),
        (ScanType.EXPOSURE, _Stage(
            "Sensitive file exposure", 180,
            lambda cb: ExposureScanner().scan(target, cb, pinned_ip=pinned_ip, port=port,
                                             credential=credential),
        )),
        (ScanType.SHODAN, _Stage(
            "Shodan exposure data", 90,
            lambda cb: ShodanScanner().scan(target, cb),
        )),
    ]

    return [stage for kind, stage in candidates if full or scan_type == kind]


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
            # Credentials reach only the scanners whose HTTP client we fully
            # control. Nikto and Nuclei are subprocesses, and passing a secret
            # on their command line would expose it through /proc to every
            # local process — so they stay unauthenticated for now rather than
            # leaking. See docs; this is a deliberate gap, not an oversight.
            credential = await _load_credential(db, scan)
            if credential:
                logger.info("scan.authenticated", scan_id=scan_id)
            stages = _build_stages(scan_type, target, pinned_ip, port, credential)
            all_findings += await _run_stages(r, scan_id, stages, start=10, end=88)

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
                #
                # Restricted to newly-appeared findings: re-sending the same
                # criticals after every scheduled scan is how alerting gets
                # muted and then ignored. On a first scan everything is new, so
                # nothing is lost. The full set stays available via the API.
                critical_ids = [
                    f.id for f in persisted
                    if f.is_new and f.severity in (Severity.CRITICAL, Severity.HIGH)
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


async def _previous_finding_index(db, scan: Scan) -> dict[str, datetime]:
    """Map fingerprint -> first_seen from the most recent prior scan.

    Scoped to the same asset where there is one, falling back to the same
    target within the org so ad-hoc scans still gain history. Only completed
    scans count: comparing against a failed or half-finished run would report
    everything it missed as newly resolved.
    """
    from sqlalchemy import select

    prior = select(Scan.id).where(
        Scan.org_id == scan.org_id,
        Scan.id != scan.id,
        Scan.status == ScanStatus.COMPLETED,
    )
    prior = prior.where(
        Scan.asset_id == scan.asset_id if scan.asset_id else Scan.target == scan.target
    )
    prior = prior.order_by(Scan.created_at.desc()).limit(1)

    previous_scan_id = (await db.execute(prior)).scalar_one_or_none()
    if not previous_scan_id:
        return {}

    rows = await db.execute(
        select(Finding.fingerprint, Finding.first_seen)
        .where(Finding.scan_id == previous_scan_id, Finding.fingerprint.isnot(None))
    )
    # Keep the earliest first_seen if a fingerprint somehow appears twice.
    index: dict[str, datetime] = {}
    for fingerprint, first_seen in rows:
        existing = index.get(fingerprint)
        if existing is None or (first_seen and first_seen < existing):
            index[fingerprint] = first_seen
    return index


async def _persist_findings(db, scan: Scan, findings: list[dict]) -> list[Finding]:
    """Bulk-insert Finding rows, sanitising untrusted scanner output first.

    Each row is reconciled against the previous scan so the platform can say
    what is new rather than re-reporting the same issues every run.

    Returns the persisted rows so callers can reference real primary keys
    (alert dispatch needs them; the raw finding dicts have none).
    """
    from app.core.audit import sanitize_finding
    from app.services.fingerprint import finding_fingerprint

    previous = await _previous_finding_index(db, scan)
    seen_at = datetime.utcnow()

    rows: list[Finding] = []
    for f in findings:
        # Strip control chars / HTML from scanner-derived text fields
        f = sanitize_finding(f)
        severity = _coerce_severity(f.get("severity"))

        fingerprint = finding_fingerprint(f)
        previously_seen_at = previous.get(fingerprint)

        finding = Finding(
            scan_id=scan.id,
            org_id=scan.org_id,
            fingerprint=fingerprint,
            # Absent from the previous scan of this target means genuinely new,
            # which is the signal worth alerting on.
            is_new=previously_seen_at is None,
            # Carried forward so the age of an issue survives re-scanning.
            first_seen=previously_seen_at or seen_at,
            last_seen=seen_at,
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
