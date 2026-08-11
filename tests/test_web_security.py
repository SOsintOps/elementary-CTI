"""Security regression tests: safe_url filter, session enforcement, avatar bounds.

The Basic-Auth tests that used to live here died with Basic Auth itself
(v0.7 auth plan step 4): enforcement is now the session middleware, pinned
end-to-end in test_auth_web.py and test_auth_roles.py. What remains here is
the surface this file always owned — the safe_url filter, the fact that a
representative route obeys the baseline, and the avatar parameter bounds —
now exercised through an authenticated client.
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
from pestilentia.web.app import _safe_url, app


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


# --- safe_url filter ---


def test_safe_url_allows_http_and_https():
    assert _safe_url("https://example.com/x") == "https://example.com/x"
    assert _safe_url("http://example.onion/leak") == "http://example.onion/leak"


def test_safe_url_blocks_dangerous_schemes():
    assert _safe_url("javascript:alert(1)") == "#"
    assert _safe_url("JaVaScRiPt:alert(1)") == "#"
    assert _safe_url("data:text/html,<script>") == "#"
    assert _safe_url("vbscript:msgbox") == "#"
    assert _safe_url("  javascript:alert(1)") == "#"


def test_safe_url_handles_empty_and_relative():
    assert _safe_url(None) == "#"
    assert _safe_url("") == "#"
    assert _safe_url("//evil.com") == "#"
    assert _safe_url("ftp://example.com") == "#"


# --- session enforcement on a representative route ---


def test_avatar_requires_login(env):
    client, _factory = env
    r = client.get("/avatar/test?size=16", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_avatar_serves_when_authenticated(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.get("/avatar/test?size=16")
    assert r.status_code == 200


def test_healthz_is_public(env):
    client, _factory = env
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_auth_config_rejects_partial_pair(monkeypatch):
    # The PEST_AUTH_* pair still seeds the bootstrap admin, so the
    # both-or-neither validation stays. Set PASS empty (not just absent) so a
    # present .env file can't repopulate it.
    monkeypatch.setenv("PEST_AUTH_USER", "holmes")
    monkeypatch.setenv("PEST_AUTH_PASS", "")
    with pytest.raises(SystemExit):
        config._load()


# --- avatar size bounds ---


def test_api_avatar_rejects_zero_size(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.get("/api/v1/groups/test/avatar?size=0")
    assert r.status_code == 422


def test_api_avatar_rejects_oversize(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.get("/api/v1/groups/test/avatar?size=100000")
    assert r.status_code == 422
