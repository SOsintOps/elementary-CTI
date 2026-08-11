"""UI language toggle: English by default, Italian one click away.

Only descriptive strings are translated; data content never is. The cookie
works for anonymous visitors too (the public storefront has the toggle).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.web.app import app
from pestilentia.web.i18n import STRINGS


@pytest.fixture
def env(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64, cookie_secure=False))
    monkeypatch.setattr(web, "_session_factory", factory)
    yield TestClient(app), factory
    web._session_factory = None
    config._settings = None


def test_catalog_is_complete():
    for key, entry in STRINGS.items():
        assert entry.get("en"), f"{key} missing en"
        assert "it" in entry, f"{key} missing it"


def test_default_language_is_english(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    body = client.get("/victims").text
    assert "Complete register of organizations" in body
    assert "Registro completo" not in body


def test_switch_to_italian_and_back(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.get("/lang/it?next=/victims", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/victims"
    assert "Registro completo" in client.get("/victims").text
    client.get("/lang/en", follow_redirects=False)
    assert "Complete register" in client.get("/victims").text


def test_anonymous_public_page_honours_the_toggle(env):
    client, _factory = env
    assert "Public overview built from open" in client.get("/").text
    client.get("/lang/it", follow_redirects=False)
    assert "Panoramica pubblica" in client.get("/").text


def test_unknown_language_is_404(env, authenticate):
    client, factory = env
    # anonymous: an unknown /lang/ code is just a protected unknown path
    assert client.get("/lang/klingon", follow_redirects=False).status_code == 303
    authenticate(client, factory)
    assert client.get("/lang/klingon", follow_redirects=False).status_code == 404


def test_next_param_cannot_open_redirect(env):
    client, _factory = env
    r = client.get("/lang/en?next=https://evil.example", follow_redirects=False)
    assert r.headers["location"] == "/"
    r = client.get("/lang/en?next=//evil.example", follow_redirects=False)
    assert r.headers["location"] == "/"


def test_html_lang_attribute_follows(env):
    client, _factory = env
    assert '<html lang="en">' in client.get("/").text
    client.get("/lang/it", follow_redirects=False)
    assert '<html lang="it">' in client.get("/").text


def test_pipeline_intro_is_bilingual(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    assert "Control panel for the collection" in client.get("/pipeline").text
    client.get("/lang/it", follow_redirects=False)
    assert "Pannello di controllo della pipeline" in client.get("/pipeline").text


def test_changelog_page_follows_language(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    en = client.get("/changelog").text
    assert "Keep a Changelog" in en or "Unreleased" in en  # canonical CHANGELOG.md
    client.get("/lang/it", follow_redirects=False)
    it = client.get("/changelog").text
    assert "pipeline degli articoli" in it or "Dark mode" in it  # curated Italian notes
