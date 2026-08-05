"""finding fingerprint and cross-scan tracking

Adds the stable identity that lets a finding be followed between scans.

Two things autogenerate got wrong and are corrected here:

  * `is_new` was emitted as NOT NULL with no default, which fails outright on
    any table that already has rows. It is added with a server default, then
    the default is dropped so the schema still matches the model (the app
    supplies the value on insert, and `alembic check` compares defaults).

  * Existing findings had no fingerprint, so the first scan after upgrading
    would have found no history and reported every finding as new. They are
    backfilled here instead.

The fingerprint algorithm is inlined rather than imported from
app.services.fingerprint on purpose: a migration must keep producing the same
result forever, and importing live code would silently change this migration's
behaviour the next time that algorithm is tuned.

Revision ID: 3683d07c2f17
Revises: c4a0c2c0e09a
Create Date: 2026-08-05 16:57:53.939418
"""
import hashlib
import re
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '3683d07c2f17'
down_revision: Union[str, None] = 'c4a0c2c0e09a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_VOLATILE_PHRASES = [
    (re.compile(r"\bin\s+\d+\s+days?\b", re.IGNORECASE), "in N days"),
    (re.compile(r"\b\d+\s+days?\s+ago\b", re.IGNORECASE), "N days ago"),
    (re.compile(r"\bexpires?\s+on\s+\d{4}-\d{2}-\d{2}\b", re.IGNORECASE), "expires on DATE"),
]
_WHITESPACE = re.compile(r"\s+")


def _fingerprint(source, cve_id, title) -> str:
    """Frozen copy of the v2.0 fingerprint algorithm."""
    text = (title or "").strip().lower()
    for pattern, replacement in _VOLATILE_PHRASES:
        text = pattern.sub(replacement, text)
    text = _WHITESPACE.sub(" ", text).strip()

    identity = (cve_id or "").strip().upper() or text or "unidentified"
    src = (source or "unknown").strip().lower()
    return hashlib.sha256(f"{src}|{identity}".encode("utf-8")).hexdigest()[:32]


def upgrade() -> None:
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=32), nullable=True))
    op.add_column(
        "findings",
        # Historical rows predate tracking, so we cannot know whether they were
        # new at the time. false is the conservative value — it cannot produce
        # a spurious "newly discovered" alarm when querying past scans.
        sa.Column("is_new", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("findings", "is_new", server_default=None)
    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=False)

    # Backfill so the first scan after upgrading can recognise recurrences.
    conn = op.get_bind()
    findings = conn.execute(
        sa.text("SELECT id, source, cve_id, title FROM findings")
    ).fetchall()

    for chunk_start in range(0, len(findings), 500):
        for row in findings[chunk_start:chunk_start + 500]:
            conn.execute(
                sa.text("UPDATE findings SET fingerprint = :fp WHERE id = :id"),
                {"fp": _fingerprint(row.source, row.cve_id, row.title), "id": row.id},
            )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_fingerprint"), table_name="findings")
    op.drop_column("findings", "is_new")
    op.drop_column("findings", "fingerprint")
