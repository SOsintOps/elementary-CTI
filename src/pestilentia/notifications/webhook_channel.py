# "One must be careful not to pull the thread too hard, lest the whole tapestry unravel." — Sherlock
from __future__ import annotations

import ipaddress
import logging
from dataclasses import asdict
from urllib.parse import urlparse

import anyio
import httpx

from pestilentia.notifications.base import AlertEvent, NotificationChannel
from pestilentia.notifications.registry import register_channel

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BACKOFF_BASE = 2.0
TIMEOUT = 10.0


def _is_safe_webhook_url(url: str) -> bool:
    """Reject non-http(s) schemes and loopback/private/link-local hosts (SSRF defense)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.hostname == "localhost":
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return True  # hostname, not an IP literal
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )


@register_channel
class WebhookChannel(NotificationChannel):
    channel_name = "webhook"

    def __init__(self, config: dict[str, str] | None = None) -> None:
        config = config or {}
        self.url = config.get("url", "")
        self.secret = config.get("secret", "")
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.secret:
                headers["X-Webhook-Secret"] = self.secret
            self._client = httpx.AsyncClient(
                timeout=TIMEOUT,
                headers=headers,
            )
        return self._client

    async def _post_with_retry(self, payload: dict) -> None:
        client = self._get_client()
        last_exc: Exception | None = None

        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.post(self.url, json=payload)
                resp.raise_for_status()
                return
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < MAX_RETRIES - 1:
                    delay = BACKOFF_BASE**attempt
                    logger.warning(
                        "Webhook POST to %s failed (attempt %d/%d): %s — retrying in %.1fs",
                        self.url,
                        attempt + 1,
                        MAX_RETRIES,
                        exc,
                        delay,
                    )
                    await anyio.sleep(delay)

        logger.error("Webhook POST to %s failed after %d retries", self.url, MAX_RETRIES)
        if last_exc is None:
            raise RuntimeError(
                f"Webhook POST to {self.url} exhausted without an exception "
                f"(MAX_RETRIES={MAX_RETRIES})"
            )
        raise last_exc

    def _serialize_event(self, event: AlertEvent) -> dict:
        data = asdict(event)
        for key in ("attack_date", "created_at"):
            val = data.get(key)
            if val is not None:
                data[key] = val.isoformat()
        return data

    def _deliverable(self) -> bool:
        if not self.url:
            logger.warning("Webhook channel has no URL configured, skipping")
            return False
        if not _is_safe_webhook_url(self.url):
            logger.error(
                "Webhook URL %r rejected: only http(s) URLs to non-private hosts are allowed",
                self.url,
            )
            return False
        return True

    async def send(self, event: AlertEvent) -> None:
        await self.send_batch([event])

    async def send_batch(self, events: list[AlertEvent]) -> None:
        if not self._deliverable():
            return
        payload = {"events": [self._serialize_event(e) for e in events]}
        await self._post_with_retry(payload)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
