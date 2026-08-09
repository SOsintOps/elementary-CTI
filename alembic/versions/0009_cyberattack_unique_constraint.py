"""Dedup cyberattacks, then enforce UNIQUE(victim_name, attack_date) (BL-07).

The application-level NULL-safe dedup has kept the table clean (verified: 0
duplicates live), so the DELETE is an idempotent safety net. Rows where either
key is NULL are left alone — both PostgreSQL and SQLite treat NULLs as
distinct in unique constraints.

Revision ID: 0009
Revises: 0008
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM cyberattacks
        WHERE victim_name IS NOT NULL
          AND attack_date IS NOT NULL
          AND id NOT IN (
              SELECT MIN(id) FROM cyberattacks
              WHERE victim_name IS NOT NULL AND attack_date IS NOT NULL
              GROUP BY victim_name, attack_date
          )
        """
    )
    with op.batch_alter_table("cyberattacks") as batch:
        batch.create_unique_constraint("uq_cyberattack_victim_date", ["victim_name", "attack_date"])


def downgrade() -> None:
    with op.batch_alter_table("cyberattacks") as batch:
        batch.drop_constraint("uq_cyberattack_victim_date", type_="unique")
