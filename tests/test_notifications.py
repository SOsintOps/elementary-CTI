from datetime import UTC, datetime

import pytest

from pestilentia.notifications.base import AlertEvent, NotificationChannel
from pestilentia.notifications.registry import CHANNELS, register_channel


def _make_event(**kwargs):
    defaults = {
        "alert_id": 1,
        "watchlist_name": "test",
        "victim_name": "Acme Corp",
        "victim_domain": "acme.com",
        "group_name": "lockbit",
        "country": "US",
        "match_field": "name",
        "attack_date": datetime(2024, 1, 1, tzinfo=UTC),
        "created_at": datetime(2024, 1, 2, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return AlertEvent(**defaults)


def test_alert_event_frozen():
    event = _make_event()
    with pytest.raises(AttributeError):
        event.alert_id = 99


def test_register_channel():
    @register_channel
    class TestChannel(NotificationChannel):
        channel_name = "test_chan"

        async def send(self, event):
            pass

        async def send_batch(self, events):
            pass

    assert "test_chan" in CHANNELS
    assert CHANNELS["test_chan"] is TestChannel
    del CHANNELS["test_chan"]


def test_log_channel_registered():
    import pestilentia.notifications.log_channel  # noqa: F401

    assert "log" in CHANNELS


@pytest.mark.anyio
async def test_log_channel_send():
    from pestilentia.notifications.log_channel import LogChannel

    channel = LogChannel()
    event = _make_event()
    await channel.send(event)
    await channel.close()


@pytest.mark.anyio
async def test_log_channel_send_batch():
    from pestilentia.notifications.log_channel import LogChannel

    channel = LogChannel()
    events = [_make_event(alert_id=i) for i in range(3)]
    await channel.send_batch(events)
    await channel.close()
