"""Alert FKs gain ON DELETE CASCADE (ME-01 follow-up).

Deleting a watchlist target or a victim now removes its alerts at the DB
level instead of leaving orphans the dispatcher must skip.

PostgreSQL: drop the existing (auto-named) FKs by introspection, recreate
with CASCADE. SQLite: table recreate via batch copy_from (unnamed inline FKs
cannot be dropped in place).

Revision ID: 0010
Revises: 0009
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _alerts_table(ondelete: str | None) -> sa.Table:
    return sa.Table(
        "alerts",
        sa.MetaData(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "watchlist_id",
            sa.Integer,
            sa.ForeignKey("watchlist.id", ondelete=ondelete),
            nullable=False,
        ),
        sa.Column(
            "victim_id", sa.Integer, sa.ForeignKey("victims.id", ondelete=ondelete), nullable=False
        ),
        sa.Column("match_field", sa.String(50), nullable=False),
        sa.Column("seen", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def _set_cascade(ondelete: str | None) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for fk in sa.inspect(bind).get_foreign_keys("alerts"):
            op.drop_constraint(fk["name"], "alerts", type_="foreignkey")
        op.create_foreign_key(
            "fk_alerts_watchlist",
            "alerts",
            "watchlist",
            ["watchlist_id"],
            ["id"],
            ondelete=ondelete,
        )
        op.create_foreign_key(
            "fk_alerts_victim", "alerts", "victims", ["victim_id"], ["id"], ondelete=ondelete
        )
    else:
        # batch with no ops is a no-op — force the table recreate that
        # rewrites the inline FKs with the new ON DELETE behavior
        with op.batch_alter_table("alerts", copy_from=_alerts_table(ondelete), recreate="always"):
            pass


def upgrade() -> None:
    _set_cascade("CASCADE")


def downgrade() -> None:
    _set_cascade(None)
