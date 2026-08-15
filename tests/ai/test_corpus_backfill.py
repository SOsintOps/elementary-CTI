# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes
"""Phase 5 step 1: the full-text sweep that builds the calibration corpus.

The scheduler's `enrich_articles_fulltext` is deliberately retry-free, and
these tests pin the three ways the sweep has to behave differently: it reaches
the tail of the queue, it retries a transport failure in a later pass, and it
does not retry a refusal. Every one of them is a bug that would only show up
after an hour of real crawling, which is exactly the kind the suite should
catch first.
"""

from typing import ClassVar

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.ai.sources import fulltext as ft
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleSource

BODY = "Full body text " * 50


def _setup() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _seed(session: Session, urls: dict[str, list[str]]) -> None:
    """One source per feed name, one truncated article per URL."""
    for index, (name, article_urls) in enumerate(urls.items()):
        source = ArticleSource(name=name, url=f"https://{name}.example/feed")
        session.add(source)
        session.flush()
        for position, url in enumerate(article_urls):
            session.add(
                Article(
                    source_id=source.id,
                    url=url,
                    url_canonical_hash=f"{index}-{position}",
                    title=f"{name} {position}",
                    body="RSS summary",
                    truncated=True,
                )
            )
    session.commit()


class _Nap:
    """Swallows the sleeps and records them, so the tests run at full speed."""

    def __init__(self):
        self.slept: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.slept.append(seconds)


@pytest.fixture
def nap():
    return _Nap()


def test_the_sweep_reaches_the_tail_instead_of_re_fetching_the_head(monkeypatch, nap):
    """The bug this function exists to avoid.

    `enrich_articles_fulltext` orders by id and leaves failures truncated, so
    calling it seven times re-fetches the same head seven times. The sweep must
    give every article in the backlog its turn in the first pass.
    """
    factory = _setup()
    with factory() as session:
        _seed(session, {"talos": [f"https://talos.example/{n}" for n in range(5)]})
        seen: list[str] = []

        def _fetch(url):
            seen.append(url)
            # The head of the queue never yields, the way a blocked feed behaves.
            return None if url.endswith("/0") else BODY

        monkeypatch.setattr(ft, "fetch_full_text", _fetch)
        report = ft.backfill_fulltext(session, sleep=nap, now=lambda: 0.0)

        assert len(seen) == 5
        assert report.ok == 4
        assert report.refused == 1
        assert session.query(Article).filter(Article.truncated.is_(False)).count() == 4


def test_a_transport_failure_is_retried_in_a_later_pass(monkeypatch, nap):
    """The 403 keyed on the exit IP, which cleared for a whole feed at once."""
    factory = _setup()
    with factory() as session:
        _seed(session, {"bleeping": ["https://bleeping.example/1"]})
        calls = {"n": 0}

        def _fetch(url):
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.HTTPStatusError("403", request=None, response=None)
            return BODY

        monkeypatch.setattr(ft, "fetch_full_text", _fetch)
        report = ft.backfill_fulltext(session, sleep=nap, now=lambda: 0.0)

        assert calls["n"] == 2
        assert report.passes == 2
        assert report.ok == 1
        assert report.deferred == 0
        # The second pass waits before retrying, or it learns nothing new.
        assert ft.BACKFILL_PASS_BACKOFF in nap.slept


def test_a_refusal_is_never_retried(monkeypatch, nap):
    """A None is a verdict on the URL: the SSRF guard, or no article in the page.

    Retrying it burns a request to be told the same thing, and on a backlog of
    three hundred that is three hundred wasted requests against feeds already
    watching our exit IP.
    """
    factory = _setup()
    with factory() as session:
        _seed(session, {"talos": ["https://talos.example/1"]})
        calls = {"n": 0}

        def _fetch(url):
            calls["n"] += 1
            return None

        monkeypatch.setattr(ft, "fetch_full_text", _fetch)
        report = ft.backfill_fulltext(session, sleep=nap, now=lambda: 0.0)

        assert calls["n"] == 1
        assert report.passes == 1
        assert report.refused == 1
        assert report.deferred == 0


def test_what_outlives_the_retries_is_deferred_not_refused(monkeypatch, nap):
    """Left truncated and named as deferred, so the scheduler still owns it."""
    factory = _setup()
    with factory() as session:
        _seed(session, {"bleeping": ["https://bleeping.example/1"]})
        monkeypatch.setattr(
            ft, "fetch_full_text", lambda url: (_ for _ in ()).throw(httpx.ConnectError("down"))
        )
        report = ft.backfill_fulltext(session, passes=2, sleep=nap, now=lambda: 0.0)

        assert report.passes == 2
        assert report.deferred == 1
        assert report.refused == 0
        assert session.query(Article).filter(Article.truncated.is_(True)).count() == 1


def test_the_report_is_per_feed_because_the_yield_is(monkeypatch, nap):
    """Yield is a property of the feed and the exit IP, never of the corpus.

    A single total would hide the case the field actually produced: eleven
    feeds untouched and one feed blocked outright.
    """
    factory = _setup()
    with factory() as session:
        _seed(
            session,
            {
                "talos": ["https://talos.example/1", "https://talos.example/2"],
                "bleeping": ["https://bleeping.example/1"],
            },
        )
        monkeypatch.setattr(
            ft,
            "fetch_full_text",
            lambda url: None if "bleeping" in url else BODY,
        )
        report = ft.backfill_fulltext(session, sleep=nap, now=lambda: 0.0)

        assert report.per_source["talos"].ok == 2
        assert report.per_source["talos"].mean_chars == len(BODY)
        assert report.per_source["bleeping"].ok == 0
        assert report.per_source["bleeping"].refused == 1
        assert report.per_source["bleeping"].attempted == 1


def test_the_pacer_spaces_one_host_and_does_not_stall_the_others(nap):
    """Twelve feeds are twelve conversations, not one queue."""
    clock = {"t": 0.0}
    pacer = ft._HostPacer(5.0, sleep=nap, now=lambda: clock["t"])

    pacer.wait("https://talos.example/1")
    assert nap.slept == []

    # A different host owes nothing to the first.
    pacer.wait("https://bleeping.example/1")
    assert nap.slept == []

    # The same host, immediately after, waits out the interval.
    pacer.wait("https://talos.example/2")
    assert nap.slept == [5.0]

    # And once the interval has genuinely passed, it does not wait again.
    clock["t"] = 100.0
    pacer.wait("https://talos.example/3")
    assert nap.slept == [5.0]


def test_limit_bounds_the_sweep_for_a_dry_run(monkeypatch, nap):
    """Because the first thing anyone does with a three-hundred-article crawl
    is try it on three."""
    factory = _setup()
    with factory() as session:
        _seed(session, {"talos": [f"https://talos.example/{n}" for n in range(5)]})
        monkeypatch.setattr(ft, "fetch_full_text", lambda url: BODY)
        report = ft.backfill_fulltext(session, limit=3, sleep=nap, now=lambda: 0.0)

        assert report.ok == 3
        assert session.query(Article).filter(Article.truncated.is_(True)).count() == 2


# --- the bot challenge that looked like an empty article ---------------------


def test_a_success_status_with_no_body_is_not_a_verdict_on_the_url(monkeypatch):
    """Measured on Check Point, 2026-08-14: CloudFront answers 202 with
    `x-amzn-waf-action: challenge` and zero bytes.

    `raise_for_status` says nothing about a 202, so this used to return None and
    be filed as "no article on this page" — a claim about the URL, and a false
    one. Six of the same feed's fifteen articles came through the same challenge
    on the same run, which is what makes it a claim about the minute instead.
    """

    class _Challenge:
        status_code = 202
        is_redirect = False
        text = ""
        headers: ClassVar[dict] = {"x-amzn-waf-action": "challenge"}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b""

        def raise_for_status(self):
            pass

        @property
        def extensions(self):
            class _Stream:
                def get_extra_info(self, name):
                    return ("93.184.216.34", 443) if name == "server_addr" else None

            return {"network_stream": _Stream()}

    monkeypatch.setattr(ft.httpx, "stream", lambda *a, **k: _Challenge())
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)

    with pytest.raises(ft.EmptyDocumentError):
        ft.fetch_full_text("https://research.example/post")


def test_a_challenged_article_is_retried_and_ends_deferred_not_refused(monkeypatch, nap):
    """Which is the whole point of raising rather than returning None: the
    sweep gets another go at it, and if it never wins, the row says the
    scheduler may still succeed where this run did not."""
    factory = _setup()
    with factory() as session:
        _seed(session, {"checkpoint": ["https://checkpoint.example/1"]})
        monkeypatch.setattr(
            ft,
            "fetch_full_text",
            lambda url: (_ for _ in ()).throw(ft.EmptyDocumentError("202, empty")),
        )
        report = ft.backfill_fulltext(session, passes=2, sleep=nap, now=lambda: 0.0)

        assert report.deferred == 1
        assert report.refused == 0


def test_an_intermittent_challenge_is_won_on_the_second_pass(monkeypatch, nap):
    """Six of fifteen got through on the first run, so the retry is not a
    formality — it is the difference between nine lost articles and none."""
    factory = _setup()
    with factory() as session:
        _seed(session, {"checkpoint": ["https://checkpoint.example/1"]})
        calls = {"n": 0}

        def _fetch(url):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ft.EmptyDocumentError("202, empty")
            return BODY

        monkeypatch.setattr(ft, "fetch_full_text", _fetch)
        report = ft.backfill_fulltext(session, sleep=nap, now=lambda: 0.0)

        assert report.ok == 1
        assert report.deferred == 0
