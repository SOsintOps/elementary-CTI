"""Add Group.is_hacktivist, backfilled from descriptions (ME-11/NI-04).

The hacktivist/non-ransomware classification moves from a per-render keyword
scan in the web layer to a column populated at ingest time
(pestilentia.classify). Keywords mirrored here for the one-time backfill.

Revision ID: 0011
Revises: 0010
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Keep in sync with pestilentia.classify.HACKTIVIST_KEYWORDS
KEYWORDS = ("not a ransomware", "hacktivist", "data broker", "not ransomware")


def upgrade() -> None:
    op.add_column(
        "groups",
        sa.Column("is_hacktivist", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    bind = op.get_bind()
    for kw in KEYWORDS:
        bind.execute(
            sa.text(
                "UPDATE groups SET is_hacktivist = :flag "
                "WHERE lower(coalesce(description, '')) LIKE :pattern"
            ),
            {"flag": True, "pattern": f"%{kw}%"},
        )


def downgrade() -> None:
    with op.batch_alter_table("groups") as batch:
        batch.drop_column("is_hacktivist")
