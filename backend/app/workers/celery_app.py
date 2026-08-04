import asyncio
from celery import Celery
from celery.utils.log import get_task_logger
from app.config import get_settings

settings = get_settings()
logger = get_task_logger(__name__)

celery_app = Celery(
    "bulwark",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.tasks.run_scan": {"queue": "scans"},
        "app.workers.tasks.run_osint": {"queue": "osint"},
        "app.workers.tasks.generate_report": {"queue": "reports"},
        "app.workers.tasks.run_scheduled_scan": {"queue": "scans"},
        "app.workers.tasks.enrich_findings": {"queue": "osint"},
        "app.workers.tasks.send_alert": {"queue": "reports"},
    },
    task_soft_time_limit=1800,
    task_time_limit=3600,
    redbeat_redis_url=settings.redis_url,
)


# ── Scheduled threat-intel syncs (Celery Beat) ──────────────────
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    "sync-mitre-attack-daily": {
        "task": "app.workers.tasks.sync_mitre_attack",
        "schedule": crontab(hour=3, minute=0),   # 03:00 UTC daily
    },
    "sync-otx-pulses-daily": {
        "task": "app.workers.tasks.sync_otx",
        "schedule": crontab(hour=4, minute=0),   # 04:00 UTC daily
    },
}
