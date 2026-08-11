"""v0.7 auth plan step 5: the anonymous public surface.

The public dashboard must show the last 30 days from public-source
structured data and nothing else: no old victims, no article content of any
TLP level (the route never queries articles), no drill-down links. The
sidebar must offer sign-in to the anonymous visitor and the full nav to the
signed-in one. The FAQ is public and really renders docs/FAQ.md.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleSource, Country, Group, Victim
from pestilentia.web.app import app

NOW = datetime.now(UTC)


@pytest.fixture
def env(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        it = Country(iso_code="IT", country_name="Italy")
        gang = Group(group_name="lockbit")
        s.add_all([it, gang])
        s.flush()
        s.add_all(
            [
                Victim(
                    victim_name="Fresh Corp",
                    group_id=gang.id,
                    country_id=it.id,
                    discovered=NOW - timedelta(days=3),
                    attackdate=NOW - timedelta(days=4),
                ),
                Victim(
                    victim_name="Ancient Industries",
                    group_id=gang.id,
                    country_id=it.id,
                    discovered=NOW - timedelta(days=200),
                    attackdate=NOW - timedelta(days=201),
                ),
            ]
        )
        feed = ArticleSource(name="Talos", url="https://x/feed", source_type="rss")
        s.add(feed)
        s.flush()
        s.add_all(
            [
                Article(
                    source_id=feed.id,
                    url="https://x/clear-article",
                    url_canonical_hash="h1",
                    title="Clear Article Headline",
                    published_at=NOW - timedelta(days=1),
                    tlp="clear",
                    truncated=False,
                ),
                Article(
                    source_id=feed.id,
                    url="https://x/green-article",
                    url_canonical_hash="h2",
                    title="Green Article Headline",
                    published_at=NOW - timedelta(days=1),
                    tlp="green",
                    truncated=False,
                ),
            ]
        )
        s.commit()
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64, cookie_secure=False))
    monkeypatch.setattr(web, "_session_factory", factory)
    yield TestClient(app), factory
    web._session_factory = None
    config._settings = None


# --- anonymous dashboard ---


def test_anonymous_dashboard_is_public_and_shows_recent_names(env):
    client, _factory = env
    r = client.get("/")
    assert r.status_code == 200
    assert "Fresh Corp" in r.text
    assert "lockbit" in r.text
    assert "last 30 days" in r.text


def test_anonymous_dashboard_hides_old_data_and_all_articles(env):
    client, _factory = env
    body = client.get("/").text
    assert "Ancient Industries" not in body  # outside the 30-day window
    # Articles are TLP-marked content: no title of any level may appear.
    assert "Clear Article Headline" not in body
    assert "Green Article Headline" not in body


def test_anonymous_dashboard_has_no_drill_down_links(env):
    client, _factory = env
    body = client.get("/").text
    for protected in ("/victims", "/groups", "/map", "/ai/articles", "/btc"):
        assert f'href="{protected}' not in body


def test_anonymous_dashboard_shows_sidebar_login_box(env):
    client, _factory = env
    body = client.get("/").text
    assert 'action="/login"' in body
    assert 'name="password"' in body


def test_anonymous_view_of_public_dashboard_is_not_activity_logged(env):
    client, factory = env
    client.get("/")
    from sqlalchemy import select

    from pestilentia.models.tables import UserActivity

    with factory() as s:
        assert list(s.execute(select(UserActivity)).scalars()) == []


# --- authenticated dashboard ---


def test_authenticated_user_gets_the_full_dashboard(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    body = client.get("/").text
    assert "Ancient Industries" in body or "Victims per Month" in body  # full-history view
    assert 'href="/victims' in body  # nav + drill-down restored
    assert 'action="/logout"' in body
    assert 'name="password"' not in body  # no login box for signed-in users


# --- FAQ ---


def test_faq_is_public_and_renders_the_markdown_source(env):
    client, _factory = env
    r = client.get("/faq")
    assert r.status_code == 200
    assert "Frequently asked questions" in r.text
    assert "What is Elementary CTI?" in r.text


def test_faq_file_ships_and_dockerfile_copies_it():
    """Three-gate pin (the CHANGELOG lesson): the file exists at the path the
    route reads, the Dockerfile copies it into the image, and .dockerignore
    re-includes it past the blanket docs/ and *.md exclusions."""
    assert web.FAQ_PATH.exists()
    root = web.FAQ_PATH.parent.parent
    assert "docs/FAQ.md" in (root / "Dockerfile").read_text(encoding="utf-8")
    assert "!docs/FAQ.md" in (root / ".dockerignore").read_text(encoding="utf-8")
