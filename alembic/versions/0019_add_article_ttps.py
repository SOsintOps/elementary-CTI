"""add article_ttps table

Phase 4 step 9: the ATT&CK techniques an article evidences, validated against
the catalogue and anchored to a span of the body (roadmap criterion 4). The
unique key is `(article_id, technique_id)` on the *resolved* id, so two ids
that revocation maps onto one technique are one row.

`tactic_name` sits beside `tactic_id` because there is no tactics table to join
to — the same denormalisation `group_ttps` already carries. Both default to an
empty string: a live technique the bundle gives no kill-chain phase is still a
mapping, and refusing it would be punishing the article for MITRE's metadata.

Revision ID: 0019
Revises: 0018
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0019"
down_revision: str | Sequence[str] | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "article_ttps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("technique_id", sa.String(length=20), nullable=False),
        sa.Column("technique_name", sa.String(length=200), nullable=False),
        sa.Column("tactic_id", sa.String(length=20), nullable=False, server_default=""),
        sa.Column("tactic_name", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("evidence_span_start", sa.Integer(), nullable=False),
        sa.Column("evidence_span_end", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["article_id"], ["articles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["article_analysis_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("article_id", "technique_id", name="uq_article_ttp"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("article_ttps")
