# "You see, but you do not observe." — Sherlock Holmes, Elementary
"""Full-text extraction for ingested articles (Phase 2, iteration 2).

Feeds mostly carry summaries; the LLM pipeline wants the full text.
trafilatura does the readability-style extraction; raw text replaces the
summary in Article.body and truncated flips to False.
"""

from __future__ import annotations

import logging

import trafilatura
from sqlalchemy.orm import Session

from pestilentia.ai.sources.dedup import simhash64
from pestilentia.clients.http import get_with_retry
from pestilentia.models.tables import Article

log = logging.getLogger(__name__)

MAX_BODY_CHARS = 200_000


def fetch_full_text(url: str) -> str | None:
    r = get_with_retry(url, timeout=30, follow_redirects=True)
    r.raise_for_status()
    return trafilatura.extract(r.text, include_comments=False, include_tables=True)


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
