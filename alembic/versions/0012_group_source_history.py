"""Evidence history: archive superseded group_source_data versions.

Adversary self-descriptions evolve; when a source's payload for a group
changes, the previous version moves here instead of being lost.

Revision ID: 0012
Revises: 0011
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "group_source_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_name", sa.String(length=100), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id"), nullable=False),
        sa.Column("raw_data", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_gsh_group_source", "group_source_history", ["group_name", "source_id"])


def downgrade() -> None:
    op.drop_index("ix_gsh_group_source", table_name="group_source_history")
    op.drop_table("group_source_history")
