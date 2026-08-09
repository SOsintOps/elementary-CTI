"""Tests for the shared sync HTTP retry helper."""

import httpx
import pytest

import pestilentia.clients.http as http_helper
from pestilentia.clients.http import get_with_retry


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(http_helper, "BACKOFF_BASE", 0.0)


def test_retries_on_transport_error(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("boom"))
    httpx_mock.add_response(status_code=200, json={"ok": True})
    r = get_with_retry("https://example.com/data", timeout=1)
    assert r.status_code == 200


def test_retries_on_5xx(httpx_mock):
    httpx_mock.add_response(status_code=502)
    httpx_mock.add_response(status_code=200)
    r = get_with_retry("https://example.com/data", timeout=1)
    assert r.status_code == 200


def test_returns_last_5xx_after_exhausting_retries(httpx_mock):
    for _ in range(3):
        httpx_mock.add_response(status_code=503)
    r = get_with_retry("https://example.com/data", timeout=1)
    assert r.status_code == 503


def test_raises_after_exhausting_transport_errors(httpx_mock):
    for _ in range(3):
        httpx_mock.add_exception(httpx.ConnectError("boom"))
    with pytest.raises(httpx.ConnectError):
        get_with_retry("https://example.com/data", timeout=1)


def test_4xx_not_retried(httpx_mock):
    httpx_mock.add_response(status_code=404)
    r = get_with_retry("https://example.com/data", timeout=1)
    assert r.status_code == 404


def test_sends_user_agent(httpx_mock):
    httpx_mock.add_response(status_code=200)
    get_with_retry("https://example.com/data", timeout=1)
    assert httpx_mock.get_request().headers["User-Agent"] == http_helper.USER_AGENT
