"""an ungraded source defaults to F, not D

0020 gave `article_sources.reliability_grade` a server default of D. That was
wrong, and the error is the kind worth a migration of its own rather than a
quiet edit: D is "not usually reliable" on the UNODC 6x6 source scale, which is
a judgement, and asserting one about a feed nobody has assessed is precisely
the guess roadmap criterion 1c forbids. F means the question was never
answered, and the gate stages what it cannot judge instead of scoring it.

No row is rewritten. The twelve seeded feeds were given real grades by 0020 and
keep them; this changes only what a feed inserted from now on starts as.

Development SQLite only, like 0020. Production stays at 0013 by decision.

Revision ID: 0021
Revises: 0020
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0021"
down_revision: str | Sequence[str] | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("article_sources") as batch:
        batch.alter_column(
            "reliability_grade",
            existing_type=sa.String(length=1),
            existing_nullable=False,
            server_default="F",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("article_sources") as batch:
        batch.alter_column(
            "reliability_grade",
            existing_type=sa.String(length=1),
            existing_nullable=False,
            server_default="D",
        )
