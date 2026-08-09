"""add llm_call_logs table

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-10 13:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "llm_call_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=True),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("provider_name", sa.String(length=50), nullable=False),
        sa.Column("model_id", sa.String(length=100), nullable=False),
        sa.Column("year_month", sa.String(length=7), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("usd_cost", sa.Numeric(10, 6), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["article_id"],
            ["articles.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["article_analysis_runs.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_llmlog_provider_month", "llm_call_logs", ["provider_name", "year_month"])
    op.create_index("ix_llmlog_article", "llm_call_logs", ["article_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_llmlog_article", table_name="llm_call_logs")
    op.drop_index("ix_llmlog_provider_month", table_name="llm_call_logs")
    op.drop_table("llm_call_logs")
