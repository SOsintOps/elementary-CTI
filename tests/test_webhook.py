from datetime import UTC, datetime

import httpx
import pytest

from pestilentia.notifications.base import AlertEvent
from pestilentia.notifications.registry import CHANNELS


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


def test_webhook_channel_registered():
    import pestilentia.notifications.webhook_channel  # noqa: F401

    assert "webhook" in CHANNELS


def test_webhook_channel_serialize():
    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook"})
    event = _make_event()
    data = ch._serialize_event(event)

    assert data["alert_id"] == 1
    assert data["victim_name"] == "Acme Corp"
    assert data["attack_date"] == "2024-01-01T00:00:00+00:00"
    assert data["created_at"] == "2024-01-02T00:00:00+00:00"


@pytest.mark.anyio
async def test_webhook_send_no_url_skips():
    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={})
    event = _make_event()
    await ch.send(event)
    await ch.close()


@pytest.mark.anyio
async def test_webhook_send_success(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=200)

    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook"})
    event = _make_event()
    await ch.send(event)

    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    body = requests[0].content
    import json

    payload = json.loads(body)
    assert len(payload["events"]) == 1
    assert payload["events"][0]["victim_name"] == "Acme Corp"

    await ch.close()


@pytest.mark.anyio
async def test_webhook_send_batch(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=200)

    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook"})
    events = [_make_event(alert_id=i) for i in range(3)]
    await ch.send_batch(events)

    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    import json

    payload = json.loads(requests[0].content)
    assert len(payload["events"]) == 3

    await ch.close()


@pytest.mark.anyio
async def test_webhook_secret_header(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=200)

    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook", "secret": "s3cret"})
    await ch.send(_make_event())

    req = httpx_mock.get_requests()[0]
    assert req.headers["X-Webhook-Secret"] == "s3cret"

    await ch.close()


@pytest.mark.anyio
async def test_webhook_retry_on_failure(httpx_mock):
    httpx_mock.add_response(url="https://example.com/hook", status_code=500)
    httpx_mock.add_response(url="https://example.com/hook", status_code=500)
    httpx_mock.add_response(url="https://example.com/hook", status_code=200)

    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook"})
    await ch.send(_make_event())

    assert len(httpx_mock.get_requests()) == 3

    await ch.close()


@pytest.mark.anyio
async def test_webhook_retry_exhausted(httpx_mock):
    for _ in range(3):
        httpx_mock.add_response(url="https://example.com/hook", status_code=500)

    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "https://example.com/hook"})
    with pytest.raises(httpx.HTTPStatusError):
        await ch.send(_make_event())

    await ch.close()


def test_webhook_url_validation():
    from pestilentia.notifications.webhook_channel import _is_safe_webhook_url

    assert _is_safe_webhook_url("https://hooks.example.com/x")
    assert _is_safe_webhook_url("http://hooks.example.com/x")
    assert not _is_safe_webhook_url("javascript:alert(1)")
    assert not _is_safe_webhook_url("file:///etc/passwd")
    assert not _is_safe_webhook_url("ftp://example.com/x")
    assert not _is_safe_webhook_url("https://localhost/hook")
    assert not _is_safe_webhook_url("https://127.0.0.1/hook")
    assert not _is_safe_webhook_url("http://192.168.1.10/hook")
    assert not _is_safe_webhook_url("http://10.0.0.5:8080/hook")
    assert not _is_safe_webhook_url("http://169.254.169.254/latest/meta-data")
    assert not _is_safe_webhook_url("http://[::1]/hook")
    assert not _is_safe_webhook_url("")


@pytest.mark.anyio
async def test_webhook_send_unsafe_url_skips(httpx_mock):
    from pestilentia.notifications.webhook_channel import WebhookChannel

    ch = WebhookChannel(config={"url": "http://127.0.0.1:9999/internal"})
    await ch.send(_make_event())

    assert len(httpx_mock.get_requests()) == 0
    await ch.close()
