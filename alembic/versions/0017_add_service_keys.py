"""add service_keys table

v0.7 auth plan step 9: API keys for keyed services, manageable from the
admin settings. Environment variables always win over these rows (operator
override); the UI never returns a stored value to any client. The
updated_by_name snapshot survives deletion of the admin who set the key.

Revision ID: 0017
Revises: 0016
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | Sequence[str] | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "service_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("service", sa.String(length=32), nullable=False),
        sa.Column("key_value", sa.String(length=512), nullable=False),
        sa.Column("updated_by_id", sa.Integer(), nullable=True),
        sa.Column("updated_by_name", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("service_keys")
