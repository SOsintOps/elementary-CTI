"""Conditional GET for article feeds, and a decision-impact flag on alerts.

W12: `article_sources` gains `etag` / `last_modified` so the poller can send
If-None-Match / If-Modified-Since and take a 304 instead of re-downloading a
feed that has not changed. With twelve feeds on a four-hour cycle that is
roughly seventy unconditional GETs a day today.

W16: `alerts` gains `actioned_at`. The 2026 SANS survey's central finding is
that 91% of CISOs call CTI valuable while only 26% say it changes a decision;
nothing in this system recorded whether an alert ever led to one. "Seen" is
not "acted on".

All three columns are nullable with no default, so the migration is additive
and the downgrade is a clean drop.

Revision ID: 0013
Revises: 0012
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | Sequence[str] | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("article_sources", recreate="auto") as batch:
        batch.add_column(sa.Column("etag", sa.String(length=256), nullable=True))
        batch.add_column(sa.Column("last_modified", sa.String(length=128), nullable=True))
    with op.batch_alter_table("alerts", recreate="auto") as batch:
        batch.add_column(sa.Column("actioned_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("alerts", recreate="auto") as batch:
        batch.drop_column("actioned_at")
    with op.batch_alter_table("article_sources", recreate="auto") as batch:
        batch.drop_column("last_modified")
        batch.drop_column("etag")
