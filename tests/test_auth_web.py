"""v0.7 auth plan step 3: session login flow, activity log, retention.

Enforcement (role gating) is step 4 — these tests pin the infrastructure:
signed cookies with rotation and expiry, the login backoff, the CSRF gate on
the auth forms, bootstrap of the first admin, and the user_activity rows that
OWASP A09 expects (every auth event, every denial, every authenticated hit).
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.activity import purge_user_activity
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import User, UserActivity
from pestilentia.security import hash_password
from pestilentia.web import sessions
from pestilentia.web.app import app


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
    monkeypatch.setattr(web, "_login_backoff", sessions.LoginBackoff())
    yield TestClient(app), factory
    web._session_factory = None
    config._settings = None


def _add_user(factory, username="alice", password="pw-secret", role="user", disabled=False):
    with factory() as s:
        s.add(
            User(
                username=username,
                password_hash=hash_password(password),
                role=role,
                disabled=disabled,
            )
        )
        s.commit()


def _login(client, username="alice", password="pw-secret"):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": web._generate_csrf_token(),
        },
        follow_redirects=False,
    )


def _rows(factory, kind=None):
    with factory() as s:
        q = select(UserActivity)
        if kind:
            q = q.where(UserActivity.kind == kind)
        return list(s.execute(q).scalars())


# --- session token unit behaviour ---


def test_session_token_roundtrip_and_tamper():
    tok = sessions.issue_session("s3cret", 42)
    data = sessions.verify_session("s3cret", tok)
    assert data is not None and data.uid == 42
    assert sessions.verify_session("other-secret", tok) is None
    assert sessions.verify_session("s3cret", tok[:-1] + ("0" if tok[-1] != "0" else "1")) is None
    assert sessions.verify_session("s3cret", None) is None
    assert sessions.verify_session("s3cret", "garbage") is None


def test_session_token_absolute_and_idle_expiry():
    now = 1_000_000
    tok = sessions.issue_session("k", 1, now=now)
    assert sessions.verify_session("k", tok, now=now + sessions.SESSION_IDLE_SECONDS - 1)
    assert sessions.verify_session("k", tok, now=now + sessions.SESSION_IDLE_SECONDS + 1) is None
    # sliding refresh moves the idle anchor but never the absolute one
    data = sessions.verify_session("k", tok, now=now + 100)
    tok2 = sessions.refresh_session("k", data, now=now + sessions.SESSION_ABSOLUTE_SECONDS - 10)
    assert (
        sessions.verify_session("k", tok2, now=now + sessions.SESSION_ABSOLUTE_SECONDS + 1) is None
    )


def test_refresh_keeps_sid_and_iat():
    tok = sessions.issue_session("k", 7, now=500)
    d1 = sessions.verify_session("k", tok, now=500)
    tok2 = sessions.refresh_session("k", d1, now=600)
    d2 = sessions.verify_session("k", tok2, now=600)
    assert (d1.sid, d1.iat) == (d2.sid, d2.iat)
    assert d2.ts == 600


# --- login flow ---


def test_login_success_sets_cookie_and_logs(env):
    client, factory = env
    _add_user(factory)
    r = _login(client)
    assert r.status_code == 303
    assert sessions.SESSION_COOKIE in r.cookies
    ok_rows = _rows(factory, "login_ok")
    assert len(ok_rows) == 1
    assert ok_rows[0].actor_name == "alice"
    assert ok_rows[0].client_ip
    with factory() as s:
        assert s.execute(select(User)).scalar_one().last_login_at is not None


def test_login_failure_logs_attempted_username(env):
    client, factory = env
    _add_user(factory)
    r = _login(client, password="wrong")
    assert r.status_code == 401
    rows = _rows(factory, "login_fail")
    assert len(rows) == 1
    assert rows[0].actor_name == "alice"
    assert rows[0].actor_id is None


def test_unknown_user_and_disabled_user_get_same_message(env):
    client, factory = env
    _add_user(factory, username="off", password="pw", disabled=True)
    r1 = _login(client, username="ghost", password="pw")
    r2 = _login(client, username="off", password="pw")
    assert r1.status_code == r2.status_code == 401
    assert "Invalid credentials" in r1.text and "Invalid credentials" in r2.text


def test_lockout_after_repeated_failures(env):
    client, factory = env
    _add_user(factory)
    for _ in range(5):
        assert _login(client, password="wrong").status_code == 401
    r = _login(client, password="pw-secret")  # correct password, but locked
    assert r.status_code == 429
    assert len(_rows(factory, "lockout")) == 1


def test_login_requires_csrf(env):
    client, _factory = env
    r = client.post("/login", data={"username": "a", "password": "b"})
    assert r.status_code == 403


def test_session_rotates_on_every_login(env):
    client, factory = env
    _add_user(factory)
    t1 = _login(client).cookies[sessions.SESSION_COOKIE]
    client.cookies.clear()
    t2 = _login(client).cookies[sessions.SESSION_COOKIE]
    d1 = sessions.verify_session("x" * 64, t1)
    d2 = sessions.verify_session("x" * 64, t2)
    assert d1.sid != d2.sid  # fixation defence


def test_logout_clears_cookie_and_logs(env):
    client, factory = env
    _add_user(factory)
    _login(client)
    r = client.post(
        "/logout", data={"csrf_token": web._generate_csrf_token()}, follow_redirects=False
    )
    assert r.status_code == 303
    assert len(_rows(factory, "logout")) == 1
    # cookie was invalidated client-side
    assert not client.cookies.get(sessions.SESSION_COOKIE)


def test_secure_flag_follows_config(env, monkeypatch):
    client, factory = env
    _add_user(factory)
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64, cookie_secure=True))
    r = _login(client)
    assert "Secure" in r.headers["set-cookie"]


# --- middleware: request.state.user + activity rows ---


def test_authenticated_page_view_is_logged(env):
    client, factory = env
    _add_user(factory)
    _login(client)
    client.get("/watchlist")
    rows = _rows(factory, "page_view")
    assert any(r.route == "/watchlist" and r.actor_name == "alice" for r in rows)


def test_anonymous_page_request_redirects_to_login_and_is_logged_as_denied(env):
    client, factory = env
    r = client.get("/watchlist", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    rows = _rows(factory)
    assert [row.kind for row in rows] == ["access_denied"]
    assert rows[0].actor_id is None and rows[0].route == "/watchlist"


def test_denied_request_is_logged_even_anonymous(env):
    client, factory = env
    r = client.post("/api/v1/refresh")  # no session -> 401 JSON, no redirect
    assert r.status_code == 401
    rows = _rows(factory, "access_denied")
    assert len(rows) == 1
    assert rows[0].actor_id is None and rows[0].route == "/api/v1/refresh"


def test_disabled_user_session_is_revoked_immediately(env):
    client, factory = env
    _add_user(factory)
    _login(client)
    with factory() as s:
        u = s.execute(select(User)).scalar_one()
        u.disabled = True
        s.commit()
    client.get("/watchlist")
    # no authenticated activity row, and the cookie was dropped
    assert _rows(factory, "page_view") == []
    assert not client.cookies.get(sessions.SESSION_COOKIE)


def test_healthz_stays_public_and_unlogged(env):
    client, factory = env
    assert client.get("/healthz").status_code == 200
    assert _rows(factory) == []


# --- bootstrap ---


def test_bootstrap_creates_admin_from_env_pair(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(
        config,
        "_settings",
        Settings(secret_key="x" * 64, cookie_secure=False, auth_user="Boss", auth_pass="pw"),
    )
    monkeypatch.setattr(web, "_session_factory", factory)
    with TestClient(app):  # context manager runs the lifespan
        pass
    with factory() as s:
        u = s.execute(select(User)).scalar_one()
        assert u.username == "boss"
        assert u.role == "admin"
    # second startup: table not empty, no duplicate
    with TestClient(app):
        pass
    with factory() as s:
        assert len(list(s.execute(select(User)).scalars())) == 1
    web._session_factory = None
    config._settings = None


# --- retention ---


def test_purge_user_activity_respects_retention(env):
    _client, factory = env
    with factory() as s:
        s.add(UserActivity(kind="page_view", ts=datetime.now(UTC) - timedelta(days=120)))
        s.add(UserActivity(kind="page_view", ts=datetime.now(UTC) - timedelta(days=5)))
        s.commit()
    with factory() as s:
        assert purge_user_activity(s, 90) == 1
    with factory() as s:
        assert len(list(s.execute(select(UserActivity)).scalars())) == 1
