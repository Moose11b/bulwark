import asyncio
from datetime import datetime
from celery import shared_task
from celery.utils.log import get_task_logger
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


def _run_async(coro):
    """Run async code from within a Celery sync task.

    Each task gets its own loop (the DB engine uses NullPool precisely so
    connections never outlive it). Teardown has to be thorough: scanners run
    work in the loop's default thread-pool executor, and closing the loop
    without draining it leaves those threads alive for the life of the worker
    process — one leaked pool per task.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            # Cancel any lingering tasks and let them settle before closing,
            # so async cleanup (httpx/asyncpg) doesn't run against a closed loop.
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            # Bounded: a scanner thread blocked in a C call cannot be
            # interrupted, so give the pool a grace period and move on rather
            # than wedging the worker.
            loop.run_until_complete(
                asyncio.wait_for(loop.shutdown_default_executor(), timeout=30)
            )
        except Exception as exc:
            logger.warning("event_loop.teardown_incomplete: %s", exc)
        finally:
            asyncio.set_event_loop(None)
            loop.close()


@celery_app.task(bind=True, name="app.workers.tasks.run_scan", max_retries=2)
def run_scan(self, scan_id: str):
    """Main scan orchestration task."""
    from app.services.scan_orchestrator import orchestrate_scan
    logger.info("Starting scan %s", scan_id)
    try:
        result = _run_async(orchestrate_scan(scan_id, self))
        logger.info("Scan %s completed", scan_id)
        return result
    except Exception as exc:
        logger.error("Scan %s failed: %s", scan_id, exc)
        _run_async(_mark_failed(scan_id, str(exc)))
        raise self.retry(exc=exc, countdown=30)


@celery_app.task(bind=True, name="app.workers.tasks.run_osint", max_retries=1)
def run_osint(self, scan_id: str):
    """Passive OSINT enrichment task."""
    from app.services.scan_orchestrator import run_osint_phase
    logger.info("Starting OSINT for scan %s", scan_id)
    return _run_async(run_osint_phase(scan_id))


@celery_app.task(bind=True, name="app.workers.tasks.enrich_findings")
def enrich_findings(self, scan_id: str):
    """Enrich CVEs with NVD/EPSS/KEV data after scan completes."""
    from app.services.enrichment import enrich_scan_findings
    logger.info("Enriching findings for scan %s", scan_id)
    return _run_async(enrich_scan_findings(scan_id))


@celery_app.task(bind=True, name="app.workers.tasks.generate_report")
def generate_report(self, scan_id: str, report_type: str = "full", user_id: str = ""):
    """Generate PDF or structured report for a scan."""
    from app.services.report_generator import generate
    logger.info("Generating %s report for scan %s", report_type, scan_id)
    return _run_async(generate(scan_id, report_type, user_id))


@celery_app.task(bind=True, name="app.workers.tasks.run_scheduled_scan")
def run_scheduled_scan(self, asset_id: str, scan_type: str):
    """Triggered by Celery Beat for scheduled scans."""
    from app.services.scan_orchestrator import launch_scheduled
    logger.info("Scheduled scan for asset %s (%s)", asset_id, scan_type)
    return _run_async(launch_scheduled(asset_id, scan_type))


@celery_app.task(name="app.workers.tasks.send_alert")
def send_alert(org_id: str, scan_id: str, finding_ids: list[str]):
    """Send alerts for high/critical findings."""
    from app.services.alerting import dispatch_alerts
    return _run_async(dispatch_alerts(org_id, scan_id, finding_ids))


async def _mark_failed(scan_id: str, error: str):
    from sqlalchemy import update
    from app.database import AsyncSessionLocal
    from app.models import Scan, ScanStatus

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                status=ScanStatus.FAILED,
                error_message=error[:1000],
                completed_at=datetime.utcnow(),
            )
        )
        await db.commit()


@celery_app.task(bind=True, name="app.workers.tasks.sync_mitre_attack", max_retries=2)
def sync_mitre_attack(self):
    """Daily MITRE ATT&CK STIX sync."""
    from app.services.threat_intel.mitre_sync import sync_mitre_attack as _sync
    logger.info("Starting MITRE ATT&CK sync")
    try:
        return _run_async(_sync())
    except Exception as exc:
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(bind=True, name="app.workers.tasks.sync_otx", max_retries=2)
def sync_otx(self):
    """Daily AlienVault OTX pulse sync."""
    from app.services.threat_intel.otx import sync_otx_pulses
    logger.info("Starting OTX sync")
    try:
        return _run_async(sync_otx_pulses())
    except Exception as exc:
        raise self.retry(exc=exc, countdown=300)
