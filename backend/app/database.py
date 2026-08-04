from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool
from app.config import get_settings

settings = get_settings()

# NullPool: each session opens a fresh connection bound to the current event
# loop. Necessary because Celery tasks create a new asyncio loop per task —
# pooled connections from a previous (closed) loop poison the next task with
# "Future attached to a different loop". For a low-QPS scanning SaaS the
# per-request connection cost is negligible.
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    poolclass=NullPool,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Create any missing tables.

    Importing app.models here is load-bearing, not decorative: create_all only
    emits DDL for tables registered on Base.metadata, and that registration is
    a side effect of importing the model classes. Called without that import,
    this silently creates nothing and returns successfully — the app happens to
    work only because main.py imports routers (and therefore models) first.
    """
    import app.models  # noqa: F401  — registers tables on Base.metadata

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
