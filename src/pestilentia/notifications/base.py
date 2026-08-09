# "The lowest and vilest alleys in London do not present a more dreadful record of sin." — Sherlock
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AlertEvent:
    alert_id: int
    watchlist_name: str
    victim_name: str
    victim_domain: str | None
    group_name: str | None
    country: str | None
    match_field: str
    attack_date: datetime | None
    created_at: datetime


class NotificationChannel(ABC):
    channel_name: str

    def __init__(self, config: dict[str, str] | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    async def send(self, event: AlertEvent) -> None: ...

    @abstractmethod
    async def send_batch(self, events: list[AlertEvent]) -> None: ...

    async def close(self) -> None:  # noqa: B027
        pass
