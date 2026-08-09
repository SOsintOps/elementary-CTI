"""add ai_enrichment_audit table

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-10 13:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "ai_enrichment_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("table_name", sa.String(length=64), nullable=False),
        sa.Column("row_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("before_json", sa.JSON(), nullable=True),
        sa.Column("after_json", sa.JSON(), nullable=True),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("decided_by", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.String(length=2048), nullable=True),
        sa.ForeignKeyConstraint(
            ["article_id"],
            ["articles.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["article_analysis_runs.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_aieaud_target", "ai_enrichment_audit", ["table_name", "row_id", "created_at"]
    )
    op.create_index("ix_aieaud_decision", "ai_enrichment_audit", ["decision", "created_at"])
    op.create_index("ix_aieaud_article", "ai_enrichment_audit", ["article_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_aieaud_article", table_name="ai_enrichment_audit")
    op.drop_index("ix_aieaud_decision", table_name="ai_enrichment_audit")
    op.drop_index("ix_aieaud_target", table_name="ai_enrichment_audit")
    op.drop_table("ai_enrichment_audit")
