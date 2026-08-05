"""
Schema migration runner.

Replaces the previous `Base.metadata.create_all` startup path. create_all only
ever CREATES missing tables — it never ALTERs an existing one — so any change
to a table that already existed silently never reached installs that had
already run once. Alembic makes schema changes real and ordered.

Three situations have to work, because Bulwark is self-hosted and operators
upgrade on their own schedule:

  fresh database          apply every migration
  pre-Alembic v1.0.x      tables exist but there is no alembic_version table.
                          Stamp the baseline (which describes exactly the
                          schema create_all produced) and then apply anything
                          newer. Without the stamp, the baseline would try to
                          re-create tables that already exist and fail.
  already managed         apply whatever is new

Migrations are serialised behind a Postgres advisory lock so that an API
container and a worker container starting at the same moment cannot race each
other into a half-applied schema.
"""
import asyncio
from pathlib import Path

import structlog
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from app.database import engine

logger = structlog.get_logger()

# Revision of the baseline that matches the v1.0.x create_all schema.
BASELINE_REVISION = "c4a0c2c0e09a"

# Arbitrary but fixed application lock id ("blwk"), so every replica contends
# on the same key.
_MIGRATION_LOCK_ID = 0x626C776B

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    # Absolute path so this works regardless of the process's working dir.
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    return cfg


def _is_pre_alembic_schema(sync_conn) -> bool:
    """True when tables exist but Alembic has never run here."""
    tables = set(inspect(sync_conn).get_table_names())
    return "alembic_version" not in tables and "organisations" in tables


def _stamp_baseline() -> None:
    command.stamp(_alembic_config(), BASELINE_REVISION)


def _upgrade_head() -> None:
    command.upgrade(_alembic_config(), "head")


async def run_migrations() -> None:
    """Bring the database schema up to date. Safe to call on every startup."""
    loop = asyncio.get_running_loop()

    async with engine.connect() as conn:
        # Session-scoped lock; released explicitly below and implicitly if the
        # connection dies, so a crashed migration cannot wedge later starts.
        await conn.exec_driver_sql(f"SELECT pg_advisory_lock({_MIGRATION_LOCK_ID})")
        try:
            if await conn.run_sync(_is_pre_alembic_schema):
                logger.info(
                    "db.stamping_pre_alembic_schema", revision=BASELINE_REVISION
                )
                # Alembic's command API is synchronous and env.py drives its own
                # event loop, so it must not run on this one.
                await loop.run_in_executor(None, _stamp_baseline)

            await loop.run_in_executor(None, _upgrade_head)
            logger.info("db.migrations_applied")
        finally:
            await conn.exec_driver_sql(
                f"SELECT pg_advisory_unlock({_MIGRATION_LOCK_ID})"
            )
