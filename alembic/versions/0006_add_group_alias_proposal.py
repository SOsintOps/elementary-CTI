"""add group_alias_proposals table

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-10 13:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "group_alias_proposals",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=True),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("proposed_alias", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("notes", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["article_id"],
            ["articles.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["groups.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_aliasprop_group", "group_alias_proposals", ["group_id"])
    op.create_index("ix_aliasprop_status", "group_alias_proposals", ["status", "created_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_aliasprop_status", table_name="group_alias_proposals")
    op.drop_index("ix_aliasprop_group", table_name="group_alias_proposals")
    op.drop_table("group_alias_proposals")
