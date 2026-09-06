"""siege tower engagement logs

Revision ID: c3a7e1f2b9d4
Revises: b2f4a9c7d1e0
Create Date: 2026-09-06 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = 'c3a7e1f2b9d4'
down_revision: Union[str, None] = 'b2f4a9c7d1e0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    outcome = sa.Enum(
        'NOT_STARTED', 'ATTEMPTED', 'SUCCEEDED', 'FAILED',
        'FELL_BACK', 'BLOCKED', 'SKIPPED',
        name='logoutcome',
    )
    op.create_table(
        'engagement_logs',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('engagement_id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('operator_id', sa.String(), nullable=True),
        sa.Column('plan_key', sa.String(length=32), nullable=True),
        sa.Column('step_index', sa.Integer(), nullable=True),
        sa.Column('technique_id', sa.String(length=16), nullable=True),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('outcome', outcome, nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('evidence_refs', JSONB(), nullable=False),
        sa.Column('targets', JSONB(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['organisations.id'], ),
        sa.ForeignKeyConstraint(['operator_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_engagement_logs_engagement_id'), 'engagement_logs', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_engagement_logs_org_id'), 'engagement_logs', ['org_id'], unique=False)
    op.create_index(op.f('ix_engagement_logs_technique_id'), 'engagement_logs', ['technique_id'], unique=False)
    op.create_index(op.f('ix_engagement_logs_outcome'), 'engagement_logs', ['outcome'], unique=False)
    op.create_index(op.f('ix_engagement_logs_created_at'), 'engagement_logs', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_engagement_logs_created_at'), table_name='engagement_logs')
    op.drop_index(op.f('ix_engagement_logs_outcome'), table_name='engagement_logs')
    op.drop_index(op.f('ix_engagement_logs_technique_id'), table_name='engagement_logs')
    op.drop_index(op.f('ix_engagement_logs_org_id'), table_name='engagement_logs')
    op.drop_index(op.f('ix_engagement_logs_engagement_id'), table_name='engagement_logs')
    op.drop_table('engagement_logs')
    sa.Enum(name='logoutcome').drop(op.get_bind(), checkfirst=True)
