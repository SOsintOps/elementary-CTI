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
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
import trafilatura
from sqlalchemy.orm import Session

from pestilentia.ai.sources.dedup import simhash64
from pestilentia.clients.http import USER_AGENT
from pestilentia.models.tables import Article, ArticleSource

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


class EmptyDocumentError(RuntimeError):
    """A success status with nothing behind it.

    Measured on Check Point Research, 2026-08-14: CloudFront answers `202` with
    `x-amzn-waf-action: challenge` and a zero-byte body — a bot challenge that
    wants JavaScript we do not run. `raise_for_status` says nothing about a
    202, so without this the call returns None and the caller reads it as "this
    page holds no article", which is a claim about the URL and is false. It is
    a claim about the client, and about this minute: six of the fifteen Check
    Point articles came through the same challenge on the same run.

    Raised rather than returned so that a caller which distinguishes the two
    kinds of failure can retry it. `enrich_articles_fulltext` catches it with
    everything else and behaves exactly as before.
    """


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

    Returns None when the page holds no article. Raises `EmptyDocumentError` when
    there was no page at all behind a success status — a bot challenge, most
    often — because that is a statement about the client and the minute, not
    about the URL, and a caller that retries deserves to be able to tell them
    apart.
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
                if not response.text.strip():
                    raise EmptyDocumentError(f"{response.status_code} with an empty body: {target}")
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


def _store_body(article: Article, text: str) -> int:
    """Write a recovered body onto the article. Returns the length kept."""
    article.body = text[:MAX_BODY_CHARS]
    article.truncated = False
    article.body_simhash = f"{simhash64(text):016x}"
    return len(article.body)


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
        _store_body(art, text)
        stats["ok"] += 1
    return stats


# --- Phase 5 step 1: the calibration corpus --------------------------------
#
# `enrich_articles_fulltext` is the scheduler's shape and stays that shape: no
# retries, oldest first, whatever fails is picked up four hours later. Sweeping
# a backlog in one sitting is a different job with different failure modes, so
# it gets a different function rather than a flag on that one.

BACKFILL_PASSES = 3
BACKFILL_HOST_INTERVAL = 5.0
BACKFILL_PASS_BACKOFF = 30.0


@dataclass
class SourceTally:
    """One feed's line in the backfill report."""

    ok: int = 0
    refused: int = 0
    deferred: int = 0
    chars: int = 0

    @property
    def attempted(self) -> int:
        return self.ok + self.refused + self.deferred

    @property
    def mean_chars(self) -> float:
        return self.chars / self.ok if self.ok else 0.0


@dataclass
class BackfillReport:
    """What the sweep did, per feed, because the yield is a per-feed property.

    `deferred` and `refused` are kept apart on purpose. A refusal is a verdict
    about the URL — it left the public internet, or the extractor found no
    article in the page — and repeating it would only repeat the answer. A
    deferral is a verdict about the moment: a status or transport error that
    outlived this run's retries, most often an IP-reputation block, which the
    scheduler may well win later from a different exit node.
    """

    passes: int = 0
    per_source: dict[str, SourceTally] = field(default_factory=dict)

    def tally(self, source: str) -> SourceTally:
        return self.per_source.setdefault(source, SourceTally())

    @property
    def ok(self) -> int:
        return sum(t.ok for t in self.per_source.values())

    @property
    def refused(self) -> int:
        return sum(t.refused for t in self.per_source.values())

    @property
    def deferred(self) -> int:
        return sum(t.deferred for t in self.per_source.values())


class _HostPacer:
    """Keeps `interval` seconds between requests to the same host.

    Per host, not global: twelve feeds crawled back to back are twelve
    conversations, and making Talos wait for Trend Micro's turn would stretch
    the sweep for nothing. What must not happen is hammering one host, which
    would add a rate problem on top of the reputation problem the sweep already
    has to live with.
    """

    def __init__(
        self,
        interval: float,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ):
        self._interval = interval
        self._sleep = sleep
        self._now = now
        self._last: dict[str, float] = {}

    def wait(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        moment = self._now()
        previous = self._last.get(host)
        if previous is not None:
            gap = self._interval - (moment - previous)
            if gap > 0:
                self._sleep(gap)
                moment = self._now()
        self._last[host] = moment


def backfill_fulltext(
    session: Session,
    *,
    limit: int | None = None,
    passes: int = BACKFILL_PASSES,
    host_interval: float = BACKFILL_HOST_INTERVAL,
    pass_backoff: float = BACKFILL_PASS_BACKOFF,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> BackfillReport:
    """Sweep the truncated backlog in one sitting, and report yield per feed.

    Three departures from the scheduler's function, each forced by the job:

    The queue is read once and walked, instead of being re-queried per batch.
    `enrich_articles_fulltext` orders by id and leaves failures truncated, so
    calling it repeatedly re-fetches the same head of the queue and never
    reaches the tail. Here every article gets its turn in the first pass.

    Failures are retried in a later pass rather than on the spot. The block we
    actually met in the field was a 403 keyed on the exit IP, which does not
    clear in the two seconds an inline retry would wait, and which does clear
    for a whole feed at once. Retrying the round gives the condition time to
    change and keeps the pacing per host honest.

    Bodies are committed as they land. A sweep of three hundred articles that
    loses everything to one exception at article two hundred is a sweep that
    gets run twice.
    """
    rows = (
        session.query(Article, ArticleSource.name)
        .join(ArticleSource, Article.source_id == ArticleSource.id)
        .filter(Article.truncated.is_(True))
        .order_by(Article.id)
    )
    if limit is not None:
        rows = rows.limit(limit)

    queue = [(article, name) for article, name in rows.all()]
    report = BackfillReport()
    pacer = _HostPacer(host_interval, sleep=sleep, now=now)

    for attempt in range(1, passes + 1):
        if not queue:
            break
        if attempt > 1:
            sleep(pass_backoff * (attempt - 1))
        report.passes = attempt
        log.info("full-text sweep pass %s/%s: %s articles queued", attempt, passes, len(queue))

        retry: list[tuple[Article, str]] = []
        for article, source in queue:
            pacer.wait(article.url)
            try:
                text = fetch_full_text(article.url)
            except Exception as exc:
                log.warning("full-text sweep will retry %s: %s", article.url, exc)
                retry.append((article, source))
                continue
            if not text:
                # A verdict on the URL, not on the moment: retrying re-reads it.
                report.tally(source).refused += 1
                continue
            report.tally(source).ok += 1
            report.tally(source).chars += _store_body(article, text)
            session.commit()

        queue = retry

    for _, source in queue:
        report.tally(source).deferred += 1

    log.info(
        "full-text sweep done in %s passes: %s recovered, %s refused, %s deferred",
        report.passes,
        report.ok,
        report.refused,
        report.deferred,
    )
    return report
