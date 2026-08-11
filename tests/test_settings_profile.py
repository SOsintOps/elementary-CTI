"""v0.7 auth plan step 6: the Profile tab of /settings.

Password change is self-service: verify the current password, enforce the
minimum length, re-hash with argon2id, log a `password_change` activity row.
Theme is a per-user default the browser toggle can still override locally.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import User, UserActivity
from pestilentia.security import verify_password
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
    yield TestClient(app), factory
    web._session_factory = None
    config._settings = None


def _post_password(client, current, new, confirm=None):
    return client.post(
        "/settings/password",
        data={
            "current_password": current,
            "new_password": new,
            "confirm_password": confirm if confirm is not None else new,
            "csrf_token": web._generate_csrf_token(),
        },
        follow_redirects=False,
    )


def test_settings_requires_login(env):
    client, _factory = env
    r = client.get("/settings", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_profile_tab_renders_for_any_role(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.get("/settings")
    assert r.status_code == 200
    assert "Change password" in r.text
    assert "Theme" in r.text
    # non-admin: no admin tabs
    assert "/settings/users" not in r.text


def test_admin_sees_all_tabs(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    body = client.get("/settings").text
    for tab in ("/settings/users", "/settings/activity", "/settings/sources", "/settings/keys"):
        assert tab in body


def test_password_change_happy_path(env, authenticate):
    client, factory = env
    authenticate(client, factory)  # password is "test-pw" (conftest)
    r = _post_password(client, "test-pw", "a-long-new-password")
    assert r.status_code == 303
    with factory() as s:
        row = s.execute(select(User)).scalar_one()
        assert verify_password(row.password_hash, "a-long-new-password")
        assert not verify_password(row.password_hash, "test-pw")
        kinds = [a.kind for a in s.execute(select(UserActivity)).scalars()]
        assert "password_change" in kinds


def test_password_change_rejects_wrong_current(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = _post_password(client, "wrong-current", "a-long-new-password")
    assert r.status_code == 403
    assert "Current password is incorrect" in r.text
    with factory() as s:
        row = s.execute(select(User)).scalar_one()
        assert verify_password(row.password_hash, "test-pw")  # unchanged


def test_password_change_rejects_short_and_mismatch(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    assert _post_password(client, "test-pw", "short").status_code == 400
    r = _post_password(client, "test-pw", "a-long-new-password", confirm="different-password")
    assert r.status_code == 400
    assert "do not match" in r.text


def test_password_change_requires_csrf(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.post(
        "/settings/password",
        data={
            "current_password": "test-pw",
            "new_password": "a-long-new-password",
            "confirm_password": "a-long-new-password",
        },
    )
    assert r.status_code == 403


def test_theme_persists_and_validates(env, authenticate):
    client, factory = env
    authenticate(client, factory)
    r = client.post(
        "/settings/theme",
        data={"theme": "dark", "csrf_token": web._generate_csrf_token()},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with factory() as s:
        assert s.execute(select(User)).scalar_one().theme == "dark"
    r = client.post(
        "/settings/theme",
        data={"theme": "hotdog", "csrf_token": web._generate_csrf_token()},
    )
    assert r.status_code == 400
