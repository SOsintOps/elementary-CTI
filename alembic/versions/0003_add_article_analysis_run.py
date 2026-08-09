"""add article_analysis_runs table

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-10 13:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "article_analysis_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("model_id", sa.String(length=100), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=True),
        sa.Column("tokens_out", sa.Integer(), nullable=True),
        sa.Column("usd_cost", sa.Numeric(10, 6), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("raw_output_json", sa.JSON(), nullable=True),
        sa.Column("prompt_version", sa.String(length=50), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["article_id"],
            ["articles.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("article_id", "state", name="uq_run_article_state"),
    )
    op.create_index("ix_run_article_status", "article_analysis_runs", ["article_id", "status"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_run_article_status", table_name="article_analysis_runs")
    op.drop_table("article_analysis_runs")
