"""Convert every DateTime column to timezone-aware (BL-04 closure).

PostgreSQL: TIMESTAMP -> TIMESTAMPTZ, interpreting stored naive values as UTC
(which they are — all writers use datetime.now(UTC) / UTC-parsed feed dates).
SQLite: no-op — SQLite has no timezone-aware storage; SQLAlchemy keeps
returning naive values there and the code already coerces where needed.

Revision ID: 0008
Revises: 0007
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DATETIME_COLUMNS: list[tuple[str, str]] = [
    ("article_sources", "created_at"),
    ("article_sources", "updated_at"),
    ("data_sources", "created_at"),
    ("info_updates", "last_update_rss"),
    ("info_updates", "last_update_json"),
    ("info_updates", "last_update_csv"),
    ("manual_overrides", "override_date"),
    ("notification_subscriptions", "created_at"),
    ("source_health", "last_check"),
    ("source_health", "last_ok"),
    ("watchlist", "created_at"),
    ("articles", "published_at"),
    ("articles", "fetched_at"),
    ("cyberattacks", "attack_date"),
    ("cyberattacks", "added"),
    ("cyberattacks", "discovered"),
    ("group_source_data", "fetched_at"),
    ("organizations", "created_at"),
    ("organizations", "updated_at"),
    ("article_analysis_runs", "started_at"),
    ("article_analysis_runs", "finished_at"),
    ("group_alias_proposals", "reviewed_at"),
    ("group_alias_proposals", "created_at"),
    ("group_btc_transactions", "tx_date"),
    ("group_locations", "lastscrape"),
    ("group_locations", "updated"),
    ("organization_identifiers", "created_at"),
    ("victims", "attackdate"),
    ("victims", "discovered"),
    ("ai_enrichment_audit", "created_at"),
    ("ai_enrichment_audit", "decided_at"),
    ("alerts", "created_at"),
    ("enrichment_review", "reviewed_at"),
    ("enrichment_review", "created_at"),
    ("llm_call_logs", "created_at"),
    ("victim_duplicates", "dup_attackdate"),
    ("victim_duplicates", "dup_date"),
    ("victim_infostealer", "last_update"),
    ("victim_organizations", "matched_at"),
    ("victim_updates", "update_date"),
]


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, col in DATETIME_COLUMNS:
        op.alter_column(
            table,
            col,
            type_=sa.DateTime(timezone=True),
            postgresql_using=f"\"{col}\" AT TIME ZONE 'UTC'",
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, col in DATETIME_COLUMNS:
        op.alter_column(
            table,
            col,
            type_=sa.DateTime(timezone=False),
            postgresql_using=f"\"{col}\" AT TIME ZONE 'UTC'",
        )
