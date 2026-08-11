"""add admin_audit table

v0.7 auth plan step 2: every settings/user mutation writes a row, same
discipline as ai_enrichment_audit. `actor_name` is a snapshot so rows
survive deletion of the actor (the FK then goes NULL, attribution stays).

Revision ID: 0015
Revises: 0014
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "admin_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor_name", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=128), nullable=True),
        sa.Column("detail", sa.String(length=2048), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_admaud_ts", "admin_audit", ["ts"])
    op.create_index("ix_admaud_action", "admin_audit", ["action", "ts"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_admaud_action", table_name="admin_audit")
    op.drop_index("ix_admaud_ts", table_name="admin_audit")
    op.drop_table("admin_audit")
