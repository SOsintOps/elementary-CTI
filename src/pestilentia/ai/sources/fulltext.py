# "You see, but you do not observe." — Sherlock Holmes, Elementary
"""Full-text extraction for ingested articles (Phase 2, iteration 2).

Feeds mostly carry summaries; the LLM pipeline wants the full text.
trafilatura does the readability-style extraction; raw text replaces the
summary in Article.body and truncated flips to False.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urljoin, urlparse

import httpx
import trafilatura
from sqlalchemy.orm import Session

from pestilentia.ai.sources.dedup import simhash64
from pestilentia.clients.http import USER_AGENT
from pestilentia.models.tables import Article

log = logging.getLogger(__name__)

MAX_BODY_CHARS = 200_000


def _is_publicly_routable(url: str) -> bool:
    """True only for http(s) URLs whose host resolves exclusively to global
    addresses. Article links arrive from third-party feeds — adversary-
    influenced data — and this fetch runs inside the deployment's network,
    so a link pointing at loopback/RFC1918/link-local must never be dialed
    (OWASP audit A10)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
        addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(ip.is_global for ip in addresses)


MAX_REDIRECTS = 5


def _peer_is_global(response: httpx.Response) -> bool:
    """True when the address actually connected to is globally routable.

    `_is_publicly_routable` resolves the name; this checks the socket. The
    gap between the two is DNS rebinding: an attacker-controlled name that
    answers with a public address for the check and a private one for the
    connect. Fails closed — an unverifiable peer is treated as hostile,
    which costs an occasional article body and never an internal one.
    """
    stream = response.extensions.get("network_stream")
    address = stream.get_extra_info("server_addr") if stream is not None else None
    if not address:
        return False
    try:
        return ipaddress.ip_address(address[0]).is_global
    except (ValueError, IndexError):
        return False


def fetch_full_text(url: str) -> str | None:
    """Fetch and extract an article body, refusing any hop that leaves the
    public internet.

    Redirects are walked by hand: letting httpx follow them would validate
    only the first URL, and a public host answering `302 -> 127.0.0.1` would
    put the guard right back where it started. The response body is read
    only after the peer address is confirmed public, so a rebinding attack
    cannot land internal content in Article.body.

    No retries here (unlike the rest of the client layer): a failed fetch
    leaves `truncated` set, so the next scheduler cycle picks the article
    up again anyway.
    """
    target = url
    for _ in range(MAX_REDIRECTS + 1):
        if not _is_publicly_routable(target):
            log.warning("Refusing full-text fetch of non-public URL: %s", target)
            return None
        with httpx.stream(
            "GET",
            target,
            timeout=30,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as response:
            if not _peer_is_global(response):
                log.warning("Refusing response from non-public peer for %s", target)
                return None
            if not response.is_redirect:
                response.read()
                response.raise_for_status()
                return trafilatura.extract(
                    response.text, include_comments=False, include_tables=True
                )
            location = response.headers.get("location")
            if not location:
                return None
            # Relative Locations are legal and resolve against the current hop.
            target = urljoin(target, location)
    log.warning("Full-text fetch exceeded %d redirects: %s", MAX_REDIRECTS, url)
    return None


def enrich_articles_fulltext(session: Session, limit: int = 50) -> dict:
    """Fetch full text for up to `limit` truncated articles (oldest first)."""
    stats = {"processed": 0, "ok": 0, "failed": 0}
    rows = (
        session.query(Article)
        .filter(Article.truncated.is_(True))
        .order_by(Article.id)
        .limit(limit)
        .all()
    )
    for art in rows:
        stats["processed"] += 1
        try:
            text = fetch_full_text(art.url)
        except Exception as exc:
            log.warning("Full-text fetch failed for %s: %s", art.url, exc)
            stats["failed"] += 1
            continue
        if not text:
            stats["failed"] += 1
            continue
        art.body = text[:MAX_BODY_CHARS]
        art.truncated = False
        art.body_simhash = f"{simhash64(text):016x}"
        stats["ok"] += 1
    return stats
