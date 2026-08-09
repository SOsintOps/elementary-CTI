# "It is my business to know what other people don't know." — Sherlock, Elementary
"""RSS/Atom article ingestion (Phase 2).

v1 semantics: unconditional GET of the feed XML, exact dedup via canonical
URL hash (uq_article_url_hash). Feed XML is a few KB on a multi-hour cadence,
so etag caching is deferred (needs an article_sources.etag column — L2).
Full-text fetch of linked pages is the next Phase 2 iteration; until then
Article.body holds the feed summary and truncated=True.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from time import struct_time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
from sqlalchemy.orm import Session

from pestilentia.ai.sources.dedup import find_near_duplicate, simhash64
from pestilentia.clients.http import get_with_retry
from pestilentia.models.tables import Article, ArticleSource

log = logging.getLogger(__name__)

_TRACKING_PARAMS = ("utm_", "fbclid", "gclid", "mc_cid", "mc_eid", "ref")


def canonicalize_url(url: str) -> str:
    """Normalize a URL for dedup: lowercase scheme/host, drop fragments,
    tracking params and trailing slash."""
    parts = urlsplit(url.strip())
    query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING_PARAMS)
    ]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, urlencode(query), ""))


def canonical_hash(url: str) -> str:
    return hashlib.sha256(canonicalize_url(url).encode()).hexdigest()


def _entry_published(entry) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        ts = getattr(entry, attr, None)
        if isinstance(ts, struct_time):
            return datetime(*ts[:6], tzinfo=UTC)
    return None


def ingest_feed(session: Session, source: ArticleSource) -> dict:
    """Fetch one feed and insert new articles. Returns stats dict."""
    stats = {
        "source": source.name,
        "entries": 0,
        "added": 0,
        "skipped": 0,
        "near_dup": 0,
        "errors": 0,
        "not_modified": False,
    }
    # Conditional GET: echo back whatever the upstream last gave us. A 304
    # means the feed has not changed, which is the common case on a four-hour
    # cycle — twelve feeds were otherwise re-downloading in full every time.
    headers = {}
    if source.etag:
        headers["If-None-Match"] = source.etag
    if source.last_modified:
        headers["If-Modified-Since"] = source.last_modified

    r = get_with_retry(source.url, timeout=30, headers=headers or None)
    if r.status_code == 304:
        stats["not_modified"] = True
        log.info("Feed %s: 304 Not Modified", source.name)
        return stats
    r.raise_for_status()

    # Store the new validators only after a successful parse, so a malformed
    # body cannot poison the cache into skipping a feed forever.
    new_etag = r.headers.get("ETag")
    new_last_modified = r.headers.get("Last-Modified")
    parsed = feedparser.parse(r.content)
    if parsed.bozo and not parsed.entries:
        raise ValueError(f"Unparseable feed for {source.name}: {parsed.bozo_exception}")

    for entry in parsed.entries:
        stats["entries"] += 1
        link = getattr(entry, "link", "") or ""
        title = (getattr(entry, "title", "") or "").strip()
        if not link or not title:
            stats["errors"] += 1
            continue
        h = canonical_hash(link)
        if session.query(Article.id).filter_by(url_canonical_hash=h).first():
            stats["skipped"] += 1
            continue
        summary = (getattr(entry, "summary", "") or "").strip() or None
        sh = simhash64(f"{title} {summary or ''}")
        if find_near_duplicate(session, sh) is not None:
            stats["near_dup"] += 1
            continue
        session.add(
            Article(
                source_id=source.id,
                url=link[:1000],
                url_canonical_hash=h,
                title=title[:500],
                body=summary,
                published_at=_entry_published(entry),
                tlp=source.default_tlp,
                body_simhash=f"{sh:016x}",
                truncated=True,  # summary only — full text comes in iteration 2
            )
        )
        stats["added"] += 1

    source.etag = new_etag
    source.last_modified = new_last_modified

    log.info(
        "Feed %s: %d entries, +%d new, %d known",
        source.name,
        stats["entries"],
        stats["added"],
        stats["skipped"],
    )
    return stats


def ingest_all(session: Session) -> list[dict]:
    """Ingest every enabled RSS source; per-source failures don't stop the run."""
    results = []
    for source in session.query(ArticleSource).filter_by(enabled=True, source_type="rss"):
        try:
            results.append(ingest_feed(session, source))
        except Exception:
            log.exception("Feed ingestion failed for %s", source.name)
            results.append({"source": source.name, "error": True})
    return results
