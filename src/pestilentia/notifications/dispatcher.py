# "There is nothing more stimulating than a case where everything goes against you." — Sherlock
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from pestilentia.models import Alert, NotificationSubscription, Victim, Watchlist
from pestilentia.notifications.base import AlertEvent
from pestilentia.notifications.registry import CHANNELS

logger = logging.getLogger(__name__)


def _build_event(alert: Alert, session: Session) -> AlertEvent | None:
    watchlist = session.get(Watchlist, alert.watchlist_id)
    victim = session.get(Victim, alert.victim_id)
    if watchlist is None or victim is None:
        # Don't emit "unknown"/"unknown" events for orphaned alerts —
        # downstream can't tell them from real names (ME-01)
        logger.warning(
            "Skipping alert %d: %s no longer exists (watchlist_id=%d, victim_id=%d)",
            alert.id,
            "watchlist" if watchlist is None else "victim",
            alert.watchlist_id,
            alert.victim_id,
        )
        return None
    group_name = victim.group.group_name if victim.group else None
    country = victim.country.iso_code if victim.country else None

    return AlertEvent(
        alert_id=alert.id,
        watchlist_name=watchlist.name,
        victim_name=victim.victim_name,
        victim_domain=victim.domain,
        group_name=group_name,
        country=country,
        match_field=alert.match_field,
        attack_date=victim.attackdate,
        created_at=alert.created_at,
    )


def _load_channel_config(session: Session, channel_name: str) -> dict[str, str]:
    rows = (
        session.query(NotificationSubscription)
        .filter(
            NotificationSubscription.channel == channel_name,
            NotificationSubscription.active.is_(True),
        )
        .all()
    )
    return {row.config_key: row.config_value for row in rows if row.config_value}


async def dispatch_alerts(
    session: Session,
    new_alert_ids: list[int],
    channel_names: list[str] | None = None,
) -> int:
    if not new_alert_ids:
        return 0

    alerts = session.query(Alert).filter(Alert.id.in_(new_alert_ids)).all()
    events = [e for a in alerts if (e := _build_event(a, session)) is not None]
    if not events:
        return 0

    targets = channel_names or list(CHANNELS.keys())
    sent = 0

    for name in targets:
        channel_cls = CHANNELS.get(name)
        if not channel_cls:
            logger.warning("Unknown notification channel: %s", name)
            continue

        config = _load_channel_config(session, name)
        channel = channel_cls(config=config)
        try:
            await channel.send_batch(events)
            sent += len(events)
            logger.debug(
                "Dispatched %d alerts via %s",
                len(events),
                name,
            )
        except Exception:
            logger.exception("Failed to dispatch via %s", name)
        finally:
            await channel.close()

    return sent
