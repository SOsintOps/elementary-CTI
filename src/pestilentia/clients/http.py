# "Education never ends, Watson. It is a series of lessons." — Sherlock Holmes, Elementary
"""Shared synchronous HTTP helpers with retry/backoff for enrichment clients."""

from __future__ import annotations

import logging
import time

import httpx

from pestilentia import __version__

logger = logging.getLogger(__name__)

# A bare token gets a crawler blocked. Version + contact URL is the polite
# convention and gives an upstream operator someone to reach if we misbehave.
# (Tested against CISA's WAF: this is not what caused the 403 seen on
# 2026-08-07 — that was transient rate limiting — but it is correct practice
# for a client polling a dozen vendor feeds on a schedule.)
USER_AGENT = f"elementary-cti/{__version__} (+https://github.com/SOsintOps/elementary-CTI)"
MAX_RETRIES = 3
BACKOFF_BASE = 2.0


def request_with_retry(
    method: str,
    url: str,
    *,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Issue an HTTP request, retrying on transport errors and 5xx responses.

    Returns the final response (callers keep their own status-code handling);
    raises the last transport error only when every attempt failed to connect.
    """
    last_exc: httpx.HTTPError | None = None
    for attempt in range(MAX_RETRIES):
        try:
            r = httpx.request(
                method,
                url,
                timeout=timeout,
                follow_redirects=follow_redirects,
                headers={"User-Agent": USER_AGENT, **(headers or {})},
            )
        except httpx.HTTPError as exc:
            last_exc = exc
            if attempt < MAX_RETRIES - 1:
                delay = BACKOFF_BASE**attempt
                logger.warning(
                    "HTTP %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method,
                    url,
                    attempt + 1,
                    MAX_RETRIES,
                    exc,
                    delay,
                )
                time.sleep(delay)
            continue
        if r.status_code >= 500 and attempt < MAX_RETRIES - 1:
            delay = BACKOFF_BASE**attempt
            logger.warning(
                "HTTP %s %s returned %d (attempt %d/%d) — retrying in %.1fs",
                method,
                url,
                r.status_code,
                attempt + 1,
                MAX_RETRIES,
                delay,
            )
            time.sleep(delay)
            continue
        return r
    assert last_exc is not None  # loop can only exhaust via the except branch
    raise last_exc


def get_with_retry(
    url: str,
    *,
    timeout: float = 30.0,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return request_with_retry(
        "GET", url, timeout=timeout, follow_redirects=follow_redirects, headers=headers
    )


def head_with_retry(
    url: str, *, timeout: float = 15.0, follow_redirects: bool = True
) -> httpx.Response:
    return request_with_retry("HEAD", url, timeout=timeout, follow_redirects=follow_redirects)
