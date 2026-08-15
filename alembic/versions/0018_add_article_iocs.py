"""add article_iocs table

Phase 4 step 9: the indicators an article was found to contain, one row per
indicator with the span that proves the article contains it (roadmap
criterion 3 — "the offset is persisted"). `confidence` is nullable and stays
null for now: the model does not report one for indicators and Phase 5
computes a composite.

Revision ID: 0018
Revises: 0017
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: str | Sequence[str] | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "article_iocs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("ioc_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.Column("value_defanged", sa.String(length=500), nullable=False),
        sa.Column("span_start", sa.Integer(), nullable=False),
        sa.Column("span_end", sa.Integer(), nullable=False),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["article_id"], ["articles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["article_analysis_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("article_id", "ioc_type", "value", name="uq_article_ioc"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("article_iocs")
