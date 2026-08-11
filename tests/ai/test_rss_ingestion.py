"""Phase 2: RSS ingestion — canonicalization, dedup, seeding."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.ai.sources import rss
from pestilentia.ai.sources.seeds import SEED_SOURCES, seed_article_sources
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleSource

FEED = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>LockBit hits hospital</title><link>https://example.com/post/1?utm_source=rss</link>
<description>Summary one</description><pubDate>Wed, 10 Jun 2026 10:00:00 GMT</pubDate></item>
<item><title>Akira retools</title><link>https://Example.com/post/2/</link>
<description>Summary two</description></item>
</channel></rss>"""


def _setup() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


class _Resp:
    """Minimal httpx.Response stand-in.

    Carries status_code and headers because ingest_feed now speaks conditional
    GET: it checks for 304 and stores the ETag / Last-Modified validators.
    """

    def __init__(self, content: bytes, status_code: int = 200, headers: dict | None = None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self):
        pass


def test_canonicalize_strips_tracking_and_normalizes():
    assert rss.canonicalize_url("https://Example.com/post/1/?utm_source=rss&x=1#frag") == (
        "https://example.com/post/1?x=1"
    )
    # same canonical form -> same hash
    assert rss.canonical_hash("https://example.com/post/1?utm_source=a") == rss.canonical_hash(
        "https://EXAMPLE.com/post/1/"
    )


def test_ingest_feed_inserts_and_dedups(monkeypatch):
    factory = _setup()
    monkeypatch.setattr(rss, "get_with_retry", lambda url, timeout=30, headers=None: _Resp(FEED))
    with factory() as session:
        src = ArticleSource(name="t", url="https://example.com/feed", default_tlp="clear")
        session.add(src)
        session.flush()

        stats = rss.ingest_feed(session, src)
        session.commit()
        assert stats["added"] == 2 and stats["skipped"] == 0

        arts = session.query(Article).order_by(Article.id).all()
        assert arts[0].title == "LockBit hits hospital"
        assert arts[0].published_at is not None
        assert arts[0].tlp == "clear" and arts[0].truncated is True

        # second run: everything deduped via canonical hash
        stats2 = rss.ingest_feed(session, src)
        assert stats2["added"] == 0 and stats2["skipped"] == 2


def test_ingest_feed_unparseable_raises(monkeypatch):
    factory = _setup()
    monkeypatch.setattr(
        rss, "get_with_retry", lambda url, timeout=30, headers=None: _Resp(b"<html>nope")
    )
    with factory() as session:
        src = ArticleSource(name="bad", url="https://example.com/feed")
        session.add(src)
        session.flush()
        with pytest.raises(ValueError, match="Unparseable"):
            rss.ingest_feed(session, src)


def test_seed_is_idempotent():
    factory = _setup()
    with factory() as session:
        assert seed_article_sources(session) == len(SEED_SOURCES)
        session.commit()
        assert seed_article_sources(session) == 0
        assert session.query(ArticleSource).count() == len(SEED_SOURCES)


# --- iteration 2: simhash near-dup + fulltext ---

from pestilentia.ai.sources import fulltext as ft  # noqa: E402
from pestilentia.ai.sources.dedup import hamming, simhash64  # noqa: E402


def test_simhash_similar_texts_close_distinct_far():
    a = simhash64("LockBit ransomware attacks hospital in Milan with new encryptor variant")
    b = simhash64("LockBit ransomware attacks hospital in Milan with a new encryptor variant!")
    c = simhash64("Quarterly earnings report shows growth in cloud revenue for vendor")
    assert hamming(a, b) <= 6
    assert hamming(a, c) > 10


LONG_SUMMARY = (
    b"The LockBit ransomware group claimed responsibility for an attack against a major "
    b"hospital network in Milan, encrypting clinical systems and exfiltrating patient "
    b"records before deploying its latest encryptor variant across the Windows domain. "
    b"Researchers observed initial access through a compromised VPN appliance followed "
    b"by credential dumping and lateral movement over SMB during a three day intrusion."
)


def _feed_with(summary: bytes, link: bytes, title: bytes) -> bytes:
    return (
        b'<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>'
        b"<item><title>" + title + b"</title><link>" + link + b"</link>"
        b"<description>" + summary + b"</description></item></channel></rss>"
    )


def test_ingest_skips_near_duplicate_entry(monkeypatch):
    factory = _setup()
    first = _feed_with(LONG_SUMMARY, b"https://example.com/post/1", b"LockBit hits hospital")
    near = _feed_with(
        LONG_SUMMARY.replace(b"three day intrusion", b"four day intrusion"),
        b"https://other.com/story/9",
        b"LockBit hits a hospital",
    )
    with factory() as session:
        src = ArticleSource(name="t1", url="https://example.com/feed")
        session.add(src)
        session.flush()
        monkeypatch.setattr(
            rss, "get_with_retry", lambda url, timeout=30, headers=None: _Resp(first)
        )
        rss.ingest_feed(session, src)
        session.commit()
        monkeypatch.setattr(
            rss, "get_with_retry", lambda url, timeout=30, headers=None: _Resp(near)
        )
        stats = rss.ingest_feed(session, src)
        assert stats["near_dup"] == 1


def test_enrich_articles_fulltext(monkeypatch):
    factory = _setup()
    with factory() as session:
        src = ArticleSource(name="t2", url="https://example.com/feed")
        session.add(src)
        session.flush()
        monkeypatch.setattr(
            rss, "get_with_retry", lambda url, timeout=30, headers=None: _Resp(FEED)
        )
        rss.ingest_feed(session, src)
        session.commit()

        monkeypatch.setattr(ft, "fetch_full_text", lambda url: "Full body text " * 50)
        stats = ft.enrich_articles_fulltext(session, limit=10)
        session.commit()
        assert (
            stats["ok"] == session.query(Article).filter(Article.truncated.is_(False)).count() > 0
        )
        art = session.query(Article).filter(Article.truncated.is_(False)).first()
        assert art.body.startswith("Full body text") and len(art.body_simhash) == 16


# --- W12: conditional GET ---


def test_304_short_circuits_without_touching_the_database():
    """A feed that has not changed must not be re-parsed or re-inserted."""
    factory = _setup()
    with factory() as session:
        src = ArticleSource(name="cached", url="https://example.com/feed", etag='W/"abc"')
        session.add(src)
        session.flush()

        sent = {}

        def _fake_get(url, timeout=30, headers=None, **kw):
            sent["headers"] = headers or {}
            return _Resp(b"", status_code=304)

        rss.get_with_retry = _fake_get
        stats = rss.ingest_feed(session, src)

    assert stats["not_modified"] is True
    assert stats["added"] == 0
    assert sent["headers"].get("If-None-Match") == 'W/"abc"'


def test_validators_are_stored_only_after_a_successful_parse():
    """A malformed body must not poison the cache into skipping forever."""
    factory = _setup()
    with factory() as session:
        src = ArticleSource(name="v", url="https://example.com/feed")
        session.add(src)
        session.flush()

        def _fake_get(url, timeout=30, headers=None, **kw):
            return _Resp(
                FEED,
                headers={"ETag": 'W/"new"', "Last-Modified": "Wed, 01 Jul 2026 00:00:00 GMT"},
            )

        rss.get_with_retry = _fake_get
        rss.ingest_feed(session, src)
        assert src.etag == 'W/"new"'
        assert src.last_modified == "Wed, 01 Jul 2026 00:00:00 GMT"

        def _bad_get(url, timeout=30, headers=None, **kw):
            return _Resp(b"<<<not a feed", headers={"ETag": 'W/"poison"'})

        rss.get_with_retry = _bad_get
        src.etag = 'W/"new"'
        with pytest.raises(ValueError):
            rss.ingest_feed(session, src)
        assert src.etag == 'W/"new"', "validators must not update on a parse failure"


# --- OWASP audit A10 (2026-08): SSRF guard on the fulltext fetch ------------
# Article URLs come from third-party feeds; the fetch runs inside the
# deployment's network. Non-public destinations must never be dialed.


def _fake_resolver(mapping):
    def resolver(host, *a, **k):
        if host not in mapping:
            raise OSError(f"unresolvable: {host}")
        return [(2, 1, 6, "", (mapping[host], 0))]

    return resolver


def test_ssrf_guard_refuses_non_public_destinations(monkeypatch):
    monkeypatch.setattr(
        ft.socket,
        "getaddrinfo",
        _fake_resolver(
            {
                "public.example": "93.184.216.34",
                "internal.example": "192.168.178.1",
                "metadata.example": "169.254.169.254",
                "localhost": "127.0.0.1",
            }
        ),
    )
    assert ft._is_publicly_routable("https://public.example/post") is True
    assert ft._is_publicly_routable("http://internal.example/admin") is False
    assert ft._is_publicly_routable("http://metadata.example/latest") is False
    assert ft._is_publicly_routable("http://localhost:8000/healthz") is False
    assert ft._is_publicly_routable("http://10.0.0.7/x") is False  # literal, no DNS
    assert ft._is_publicly_routable("ftp://public.example/x") is False
    assert ft._is_publicly_routable("http://nxdomain.example/x") is False


def test_fetch_full_text_never_dials_refused_urls(monkeypatch):
    def explode(*a, **k):
        raise AssertionError("guard must reject before any HTTP request")

    monkeypatch.setattr(ft.httpx, "stream", explode)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: False)
    assert ft.fetch_full_text("http://192.168.178.88/secret") is None


class _FakeStream:
    """httpx.stream() stand-in: a context manager yielding a canned response."""

    def __init__(self, status_code, headers=None, text="", peer="93.184.216.34"):
        self.status_code = status_code
        self.headers = headers or {}
        self._text = text
        self._peer = peer
        self.read_called = False

    # -- context manager --------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    # -- httpx.Response surface used by fetch_full_text -------------------
    @property
    def extensions(self):
        peer = self._peer

        class _Stream:
            def get_extra_info(self, name):
                return (peer, 443) if name == "server_addr" and peer else None

        return {"network_stream": _Stream() if peer else None}

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308)

    def read(self):
        self.read_called = True
        return self._text.encode()

    @property
    def text(self):
        return self._text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected status {self.status_code}")


_ARTICLE_HTML = "<html><body><article>" + "Real body text. " * 40 + "</article></body></html>"


def test_redirect_to_internal_host_is_refused(monkeypatch):
    """A public host answering 302 -> loopback must not be followed: the
    guard would otherwise validate only the first URL (OWASP audit A10)."""
    dialed = []

    def fake_stream(method, url, **kwargs):
        assert kwargs.get("follow_redirects") is False, "redirects must be walked by hand"
        dialed.append(url)
        if url == "https://public.example/post":
            return _FakeStream(302, {"location": "http://169.254.169.254/latest/meta-data/"})
        raise AssertionError(f"internal host was dialed: {url}")

    monkeypatch.setattr(ft.httpx, "stream", fake_stream)
    monkeypatch.setattr(
        ft, "_is_publicly_routable", lambda url: url == "https://public.example/post"
    )
    assert ft.fetch_full_text("https://public.example/post") is None
    assert dialed == ["https://public.example/post"]


def test_redirect_to_public_host_is_followed(monkeypatch):
    def fake_stream(method, url, **kwargs):
        if url == "https://public.example/post":
            return _FakeStream(301, {"location": "/final"})  # relative Location
        return _FakeStream(200, text=_ARTICLE_HTML)

    monkeypatch.setattr(ft.httpx, "stream", fake_stream)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)
    assert ft.fetch_full_text("https://public.example/post") is not None


def test_redirect_loop_terminates(monkeypatch):
    calls = []

    def fake_stream(method, url, **kwargs):
        calls.append(url)
        return _FakeStream(302, {"location": "https://public.example/next"})

    monkeypatch.setattr(ft.httpx, "stream", fake_stream)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)
    assert ft.fetch_full_text("https://public.example/post") is None
    assert len(calls) == ft.MAX_REDIRECTS + 1


# --- DNS rebinding: the name passed the check, the socket went elsewhere ----


def test_rebound_peer_is_refused_before_the_body_is_read(monkeypatch):
    """_is_publicly_routable says yes (attacker DNS answered public), but the
    connection landed on the metadata service. The body must never be read."""
    response = _FakeStream(200, text=_ARTICLE_HTML, peer="169.254.169.254")
    monkeypatch.setattr(ft.httpx, "stream", lambda *a, **k: response)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)

    assert ft.fetch_full_text("https://rebind.example/post") is None
    assert not response.read_called, "internal content must not be read into memory"


def test_unverifiable_peer_fails_closed(monkeypatch):
    response = _FakeStream(200, text=_ARTICLE_HTML, peer=None)
    monkeypatch.setattr(ft.httpx, "stream", lambda *a, **k: response)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)

    assert ft.fetch_full_text("https://public.example/post") is None
    assert not response.read_called


def test_public_peer_is_accepted(monkeypatch):
    response = _FakeStream(200, text=_ARTICLE_HTML, peer="93.184.216.34")
    monkeypatch.setattr(ft.httpx, "stream", lambda *a, **k: response)
    monkeypatch.setattr(ft, "_is_publicly_routable", lambda url: True)

    assert ft.fetch_full_text("https://public.example/post") is not None
    assert response.read_called
