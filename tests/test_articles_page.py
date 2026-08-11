"""W9: the read-only article list (Phase 2 success criterion 4).

The page shows what the fetcher stored and nothing else — no extraction, no
model output. These tests pin the filtering, the empty state and the fact that
adversary-controlled article URLs go through the safe_url gate.
"""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleSource
from pestilentia.web.app import app


@pytest.fixture
def seeded(monkeypatch, authenticate):
    # StaticPool + check_same_thread: TestClient serves from another thread,
    # and a fresh connection to ":memory:" would be a fresh, empty database.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        vendor = ArticleSource(name="Cisco Talos", url="https://x/feed", source_type="rss")
        news = ArticleSource(name="BleepingComputer", url="https://y/feed", source_type="rss")
        session.add_all([vendor, news])
        session.flush()
        session.add_all(
            [
                Article(
                    source_id=vendor.id,
                    url="https://talos.example/lockbit",
                    url_canonical_hash="h1",
                    title="LockBit affiliate tooling",
                    published_at=datetime(2026, 8, 1, tzinfo=UTC),
                    tlp="clear",
                    truncated=False,
                ),
                Article(
                    source_id=news.id,
                    url="javascript:alert(1)",
                    url_canonical_hash="h2",
                    title="Akira hits manufacturer",
                    published_at=datetime(2026, 7, 20, tzinfo=UTC),
                    tlp="green",
                    truncated=True,
                ),
            ]
        )
        session.commit()

    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    # get_db() memoises a module-level factory; point it at our in-memory DB.
    monkeypatch.setattr(web, "_session_factory", factory)
    client = TestClient(app)
    authenticate(client, factory)
    client.factory = factory
    yield client
    web._session_factory = None
    config._settings = None


@pytest.fixture
def admin(seeded):
    # Elevate the signed-in test user: the middleware re-reads the role from
    # the DB on every request, so no new session cookie is needed.
    from pestilentia.models.tables import User

    with seeded.factory() as s:
        row = s.query(User).filter(User.username == "tester").one()
        row.role = "admin"
        s.commit()


def test_lists_articles_with_source_and_tlp(seeded):
    body = seeded.get("/ai/articles").text
    assert "LockBit affiliate tooling" in body
    assert "Cisco Talos" in body
    assert "TLP:CLEAR" in body


def test_filter_by_source(seeded):
    body = seeded.get("/ai/articles?source=Cisco+Talos").text
    assert "LockBit affiliate tooling" in body
    assert "Akira hits manufacturer" not in body


def test_filter_by_tlp(seeded):
    body = seeded.get("/ai/articles?tlp=green").text
    assert "Akira hits manufacturer" in body
    assert "LockBit affiliate tooling" not in body


def test_search_matches_title(seeded):
    body = seeded.get("/ai/articles?q=akira").text
    assert "Akira hits manufacturer" in body
    assert "LockBit affiliate tooling" not in body


def test_no_match_shows_empty_state(seeded):
    body = seeded.get("/ai/articles?q=zzzznope").text
    assert "No articles match these filters" in body


def test_article_urls_go_through_the_safe_url_gate(seeded):
    """Feed content is adversary-controlled: javascript: must never reach href."""
    body = seeded.get("/ai/articles").text
    assert "javascript:alert(1)" not in body
    assert 'href="#"' in body


def test_truncated_articles_are_labelled_summary_only(seeded):
    body = seeded.get("/ai/articles").text
    assert "Summary only" in body
    assert "Full text" in body


# --- W8: pipeline page article card + toggle allowlist ---


def test_pipeline_page_shows_article_counters(seeded):
    body = seeded.get("/pipeline").text
    assert "Articles" in body
    assert 'data-enrichment="articles"' in body
    assert "2 articles" in body, "card must show the real count, not just a state word"
    assert "1 full text" in body


def test_articles_toggle_is_allowed(seeded, admin):
    """The toggle allowlist gates the endpoint; omitting 'articles' would 404.
    Toggling is admin-gated since auth plan step 8."""
    token = web._generate_csrf_token()
    r = seeded.post("/api/v1/enrichment/articles/toggle", headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    r2 = seeded.post("/api/v1/enrichment/articles/toggle", headers={"X-CSRF-Token": token})
    assert r2.json()["enabled"] is True


def test_unknown_enrichment_still_rejected(seeded, admin):
    token = web._generate_csrf_token()
    r = seeded.post("/api/v1/enrichment/nonsense/toggle", headers={"X-CSRF-Token": token})
    assert r.status_code == 404


# --- W15: PIRs derived from the watchlist ---


def test_pir_terms_come_from_the_active_watchlist_only():
    """The watchlist already states what this operator cares about; a separate
    PIR table would need a migration without saying anything new."""
    from pestilentia.models.tables import Watchlist
    from pestilentia.web.app import _pir_terms

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        session.add_all(
            [
                Watchlist(name="Acme Corp", domain="acme.example", keywords="widgets, gadgets"),
                Watchlist(name="Retired Ltd", active=False),
            ]
        )
        session.commit()
        terms = _pir_terms(session)

    assert "acme corp" in terms
    assert "acme.example" in terms
    assert "widgets" in terms and "gadgets" in terms
    assert "retired ltd" not in terms, "inactive entries are not requirements"


def test_pir_hits_read_title_and_body_but_never_the_url():
    """A vendor's own domain in a URL would match a watchlisted company by chance."""
    from pestilentia.web.app import _pir_hits

    class _A:
        title = "Breach at Acme Corp"
        body = "Attackers exfiltrated widgets data."
        url = "https://gadgets.example/post"

    hits = _pir_hits(_A(), ["acme corp", "widgets", "gadgets"])
    assert set(hits) == {"acme corp", "widgets"}


def test_short_watchlist_tokens_are_ignored():
    """Two characters match half the corpus by accident."""
    from pestilentia.models.tables import Watchlist
    from pestilentia.web.app import _pir_terms

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        session.add(Watchlist(name="AB", keywords="xy, valid-term"))
        session.commit()
        terms = _pir_terms(session)
    assert "ab" not in terms and "xy" not in terms
    assert "valid-term" in terms


def test_priority_filter_narrows_the_list(seeded):
    body = seeded.get("/ai/articles?pir_only=true").text
    # No watchlist rows in this fixture, so the filter is inert rather than empty.
    assert "LockBit affiliate tooling" in body


# --- W16: decision-impact loop ---


def test_alert_actioned_toggles_and_implies_seen(seeded):
    """ "Seen" is not "acted on"; the gap between them is the thing to measure."""
    from datetime import UTC, datetime

    from pestilentia.models.tables import Alert, Victim, Watchlist

    factory = web._session_factory
    with factory() as session:
        target = Watchlist(name="Acme")
        victim = Victim(victim_name="Acme", attackdate=datetime.now(UTC))
        session.add_all([target, victim])
        session.flush()
        alert = Alert(watchlist_id=target.id, victim_id=victim.id, match_field="name")
        session.add(alert)
        session.commit()
        alert_id = alert.id

    token = web._generate_csrf_token()
    r = seeded.post(f"/api/v1/alerts/{alert_id}/actioned", headers={"X-CSRF-Token": token})
    assert r.status_code == 200 and r.json()["actioned"] is True

    with factory() as session:
        row = session.query(Alert).filter_by(id=alert_id).first()
        assert row.actioned_at is not None
        assert row.seen is True, "acting on something unseen is not a coherent state"

    # Reversible: a mistaken click must not permanently skew the measure.
    r2 = seeded.post(f"/api/v1/alerts/{alert_id}/actioned", headers={"X-CSRF-Token": token})
    assert r2.json()["actioned"] is False


def test_unknown_alert_is_404(seeded):
    token = web._generate_csrf_token()
    r = seeded.post("/api/v1/alerts/999999/actioned", headers={"X-CSRF-Token": token})
    assert r.status_code == 404
