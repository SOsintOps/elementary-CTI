# "Data, data, data! I cannot make bricks without clay." — Sherlock, Elementary
"""Per-source evidence storage for groups (evidence vs synthesis separation).

Every source's raw payload for a group is kept in `group_source_data`
(latest version) and archived to `group_source_history` when it changes.
Unchanged payloads are skipped entirely — no churn, and `fetched_at` reads
as "when this content was last new".
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from pestilentia.models import DataSource
from pestilentia.models.tables import GroupSourceData, GroupSourceHistory


def upsert_source_evidence(
    session: Session, group_name: str, source_id: int, raw_json: str
) -> bool:
    """Store a source payload for a group; archive the previous version on change.

    Returns True when the content was new or changed, False when identical
    (in which case nothing is written).
    """
    existing = (
        session.query(GroupSourceData).filter_by(group_name=group_name, source_id=source_id).first()
    )
    if existing is None:
        session.add(GroupSourceData(group_name=group_name, source_id=source_id, raw_data=raw_json))
        return True
    if existing.raw_data == raw_json:
        return False
    session.add(
        GroupSourceHistory(
            group_name=group_name,
            source_id=source_id,
            raw_data=existing.raw_data,
            fetched_at=existing.fetched_at,
        )
    )
    existing.raw_data = raw_json
    existing.fetched_at = datetime.now(UTC)
    return True


def get_or_create_source(session: Session, source_name: str, base_url: str = "") -> DataSource:
    """Fetch (or lazily create) the DataSource row used to attribute evidence."""
    ds = session.query(DataSource).filter_by(source_name=source_name).first()
    if ds is None:
        ds = DataSource(source_name=source_name, base_url=base_url or None, enabled=True)
        session.add(ds)
        session.flush()
    return ds
