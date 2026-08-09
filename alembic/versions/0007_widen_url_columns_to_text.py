"""widen feed-supplied URL/link columns from String(300) to Text

Onion URLs with long paths routinely exceed 300 chars. SQLite never enforced
the length, but PostgreSQL does — so these columns must be Text to ingest live
feed data without StringDataRightTruncation (review finding ME-04).

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-11 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column) pairs widened to Text
_COLUMNS = [
    ("groups", "url"),
    ("group_locations", "fqdn"),
    ("group_locations", "slug"),
    ("victims", "claim_url"),
    ("victims", "screenshot"),
    ("victims", "url"),
    ("victim_duplicates", "dup_link"),
    ("victim_press", "press_link"),
    ("victim_updates", "update_link"),
]


def upgrade() -> None:
    """Upgrade schema. Batch mode keeps this portable to SQLite (no ALTER COLUMN TYPE)."""
    for table, column in _COLUMNS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, type_=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    for table, column in _COLUMNS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, type_=sa.String(length=300), existing_nullable=True)
