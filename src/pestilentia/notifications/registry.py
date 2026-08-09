# "The game is afoot." — Sherlock Holmes, Elementary
from pestilentia.notifications.base import NotificationChannel

CHANNELS: dict[str, type[NotificationChannel]] = {}


def register_channel(cls: type[NotificationChannel]) -> type[NotificationChannel]:
    CHANNELS[cls.channel_name] = cls
    return cls
