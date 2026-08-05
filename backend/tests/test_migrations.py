"""
Migration safety.

The schema is the one thing a self-hosted install cannot roll back easily, so
these assert the properties that matter on upgrade rather than just that
Alembic runs.
"""
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from app.core.migrations import BASELINE_REVISION, _is_pre_alembic_schema
from app.database import Base, engine

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _script_dir() -> ScriptDirectory:
    cfg = Config(str(BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    return ScriptDirectory.from_config(cfg)


def test_single_head_no_forked_history():
    """Two heads means someone branched; upgrades become ambiguous."""
    heads = _script_dir().get_heads()
    assert len(heads) == 1, f"expected exactly one head, found {heads}"


def test_baseline_is_the_root_revision():
    """The stamp target for pre-Alembic installs must be the root.

    If the baseline ever stops being the root, stamping a v1.0.x database at
    it would skip every migration in between.
    """
    script = _script_dir()
    bases = script.get_bases()
    assert bases == [BASELINE_REVISION], (
        f"baseline {BASELINE_REVISION} is not the root revision; roots={bases}"
    )


async def test_migrated_schema_matches_the_models():
    """Every table the ORM declares must exist after migrating.

    This is the check that would have caught create_all silently creating
    nothing, and catches a model added without a matching migration.
    """
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))

    declared = set(Base.metadata.tables)
    missing = declared - tables
    assert not missing, f"models declare tables with no migration: {sorted(missing)}"


async def test_pre_alembic_detection_is_false_once_managed():
    """A managed database must not be re-stamped on every startup."""
    async with engine.connect() as conn:
        assert await conn.run_sync(_is_pre_alembic_schema) is False
