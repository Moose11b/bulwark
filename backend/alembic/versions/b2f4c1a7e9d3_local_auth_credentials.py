"""local auth credentials

Adds the columns that back built-in email/password login:

  * password_hash — nullable; only local users have one (Clerk/OIDC users
    authenticate against their external provider).
  * must_change_password — added NOT NULL with a server default of false so it
    backfills cleanly on tables that already have rows; the default is then
    dropped so the schema matches the model (the app sets the value on insert).

Revision ID: b2f4c1a7e9d3
Revises: a7a1dba56c1b
Create Date: 2026-08-30 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b2f4c1a7e9d3"
down_revision: Union[str, None] = "a7a1dba56c1b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.String(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    # Drop the server default so the column matches the model, which supplies
    # the value from the application on insert.
    op.alter_column("users", "must_change_password", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
    op.drop_column("users", "password_hash")
