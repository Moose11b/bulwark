"""siege tower engagements and plans

Revision ID: b2f4a9c7d1e0
Revises: a7a1dba56c1b
Create Date: 2026-09-05 20:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision: str = 'b2f4a9c7d1e0'
down_revision: Union[str, None] = 'a7a1dba56c1b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    engagement_status = sa.Enum(
        'DRAFT', 'PLANNING', 'ACTIVE', 'COMPLETE', 'ARCHIVED',
        name='engagementstatus',
    )

    op.create_table(
        'engagements',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('created_by_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('client_name', sa.String(length=255), nullable=True),
        sa.Column('authorization_ref', sa.String(length=512), nullable=True),
        sa.Column('objective', sa.String(length=64), nullable=False),
        sa.Column('box_type', sa.String(length=16), nullable=False),
        sa.Column('scope_platforms', JSONB(), nullable=False),
        sa.Column('in_scope_targets', JSONB(), nullable=False),
        sa.Column('out_of_scope', JSONB(), nullable=False),
        sa.Column('provided_access', JSONB(), nullable=False),
        sa.Column('restrictions', JSONB(), nullable=False),
        sa.Column('forbidden_technique_ids', JSONB(), nullable=False),
        sa.Column('forbidden_tactics', JSONB(), nullable=False),
        sa.Column('time_budget_hours', sa.Float(), nullable=True),
        sa.Column('allow_evidence_removal', sa.Boolean(), nullable=False),
        sa.Column('emulate_adversary', sa.String(length=64), nullable=True),
        sa.Column('roe_notes', sa.Text(), nullable=True),
        sa.Column('objective_note', sa.Text(), nullable=True),
        sa.Column('status', engagement_status, nullable=False),
        sa.Column('last_plan_meta', JSONB(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organisations.id'], ),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_engagements_org_id'), 'engagements', ['org_id'], unique=False)
    op.create_index(op.f('ix_engagements_status'), 'engagements', ['status'], unique=False)

    op.create_table(
        'engagement_plans',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('engagement_id', sa.String(), nullable=False),
        sa.Column('org_id', sa.String(), nullable=False),
        sa.Column('plan_key', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=512), nullable=False),
        sa.Column('fit_score', sa.Float(), nullable=False),
        sa.Column('rationale', JSONB(), nullable=False),
        sa.Column('steps', JSONB(), nullable=False),
        sa.Column('est_total_minutes', sa.Integer(), nullable=False),
        sa.Column('within_time_budget', sa.Boolean(), nullable=True),
        sa.Column('aggregate_noise', sa.Float(), nullable=False),
        sa.Column('max_difficulty', sa.Integer(), nullable=False),
        sa.Column('covered_tactics', JSONB(), nullable=False),
        sa.Column('warnings', JSONB(), nullable=False),
        sa.Column('is_selected', sa.Boolean(), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['org_id'], ['organisations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_engagement_plans_engagement_id'), 'engagement_plans', ['engagement_id'], unique=False)
    op.create_index(op.f('ix_engagement_plans_org_id'), 'engagement_plans', ['org_id'], unique=False)
    op.create_index(op.f('ix_engagement_plans_is_selected'), 'engagement_plans', ['is_selected'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_engagement_plans_is_selected'), table_name='engagement_plans')
    op.drop_index(op.f('ix_engagement_plans_org_id'), table_name='engagement_plans')
    op.drop_index(op.f('ix_engagement_plans_engagement_id'), table_name='engagement_plans')
    op.drop_table('engagement_plans')
    op.drop_index(op.f('ix_engagements_status'), table_name='engagements')
    op.drop_index(op.f('ix_engagements_org_id'), table_name='engagements')
    op.drop_table('engagements')
    sa.Enum(name='engagementstatus').drop(op.get_bind(), checkfirst=True)
