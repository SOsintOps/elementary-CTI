"""add articles table

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-10 13:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "articles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("url", sa.String(length=1000), nullable=False),
        sa.Column("url_canonical_hash", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("body_simhash", sa.String(length=32), nullable=True),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("summary_md", sa.Text(), nullable=True),
        sa.Column("recommendations_md", sa.Text(), nullable=True),
        sa.Column("article_type", sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["article_sources.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url_canonical_hash", name="uq_article_url_hash"),
    )
    op.create_index("ix_article_source_id", "articles", ["source_id"])
    op.create_index("ix_article_published_at", "articles", ["published_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_article_published_at", table_name="articles")
    op.drop_index("ix_article_source_id", table_name="articles")
    op.drop_table("articles")
