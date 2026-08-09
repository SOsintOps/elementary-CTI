# "I see everything; that is my curse." — Sherlock Holmes, Elementary
from __future__ import annotations

import logging

from pestilentia.notifications.base import AlertEvent, NotificationChannel
from pestilentia.notifications.registry import register_channel

logger = logging.getLogger(__name__)


@register_channel
class LogChannel(NotificationChannel):
    channel_name = "log"

    def __init__(self, config: dict[str, str] | None = None) -> None:
        super().__init__(config)

    async def send(self, event: AlertEvent) -> None:
        logger.info(
            "ALERT: %s matched victim %s (%s) via %s",
            event.watchlist_name,
            event.victim_name,
            event.group_name or "unknown group",
            event.match_field,
            extra={
                "alert_id": event.alert_id,
                "watchlist": event.watchlist_name,
                "victim": event.victim_name,
                "group": event.group_name,
                "match_field": event.match_field,
            },
        )

    async def send_batch(self, events: list[AlertEvent]) -> None:
        for event in events:
            await self.send(event)
