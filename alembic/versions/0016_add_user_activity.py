"""add user_activity table

v0.7 auth plan step 2: the activity log behind OWASP A09 — every
authenticated user action plus every failed access attempt (bad login,
lockout, authorisation denial). NULL actor columns mean an anonymous
request. Rows are purged past PEST_ACTIVITY_RETENTION_DAYS by the
scheduler (step 3), so growth is bounded.

Revision ID: 0016
Revises: 0015
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: str | Sequence[str] | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "user_activity",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor_name", sa.String(length=64), nullable=True),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=True),
        sa.Column("route", sa.String(length=256), nullable=True),
        sa.Column("target", sa.String(length=256), nullable=True),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_useract_ts", "user_activity", ["ts"])
    op.create_index("ix_useract_actor", "user_activity", ["actor_id", "ts"])
    op.create_index("ix_useract_kind", "user_activity", ["kind", "ts"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_useract_kind", table_name="user_activity")
    op.drop_index("ix_useract_actor", table_name="user_activity")
    op.drop_index("ix_useract_ts", table_name="user_activity")
    op.drop_table("user_activity")
