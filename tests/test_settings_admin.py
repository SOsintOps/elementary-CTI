"""v0.7 auth plan step 7: Users and Activity admin tabs.

Every mutation writes an admin_audit row; the last active admin can never be
disabled, deleted or demoted; nobody can disable or delete themselves; the
whole surface is admin-only (server-side, not just hidden links).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.activity import record_activity
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import AdminAudit, User
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


@pytest.fixture
def admin_client(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    return client, factory


def _post(client, path, **data):
    data["csrf_token"] = web._generate_csrf_token()
    return client.post(path, data=data, follow_redirects=False)


def _user_id(factory, username):
    with factory() as s:
        return s.execute(select(User).where(User.username == username)).scalar_one().id


def _audits(factory):
    with factory() as s:
        return [(a.action, a.target) for a in s.execute(select(AdminAudit)).scalars()]


# --- access control ---


@pytest.mark.parametrize("role", ["user", "analyst"])
@pytest.mark.parametrize("path", ["/settings/users", "/settings/activity"])
def test_admin_tabs_are_admin_only(env, authenticate, role, path):
    client, factory = env
    authenticate(client, factory, role=role, username=f"pleb-{role}")
    assert client.get(path).status_code == 403


# --- users tab ---


def test_create_user_and_audit(admin_client):
    client, factory = admin_client
    r = _post(
        client,
        "/settings/users/create",
        username="watson",
        password="a-long-password",
        role="analyst",
    )
    assert r.status_code == 303 and "err" not in r.headers["location"]
    with factory() as s:
        row = s.execute(select(User).where(User.username == "watson")).scalar_one()
        assert row.role == "analyst"
    assert ("user_create", "watson") in _audits(factory)


def test_create_rejects_bad_input(admin_client):
    client, _factory = admin_client
    assert (
        "bad_username"
        in _post(
            client, "/settings/users/create", username="X!", password="a-long-password", role="user"
        ).headers["location"]
    )
    assert (
        "short_password"
        in _post(
            client, "/settings/users/create", username="ok-name", password="short", role="user"
        ).headers["location"]
    )
    assert (
        "bad_role"
        in _post(
            client,
            "/settings/users/create",
            username="ok-name",
            password="a-long-password",
            role="root",
        ).headers["location"]
    )
    _post(
        client, "/settings/users/create", username="dupe", password="a-long-password", role="user"
    )
    assert (
        "exists"
        in _post(
            client,
            "/settings/users/create",
            username="dupe",
            password="a-long-password",
            role="user",
        ).headers["location"]
    )


def test_disable_enable_and_delete(admin_client):
    client, factory = admin_client
    _post(
        client, "/settings/users/create", username="temp", password="a-long-password", role="user"
    )
    uid = _user_id(factory, "temp")
    assert _post(client, f"/settings/users/{uid}/toggle").status_code == 303
    with factory() as s:
        assert s.get(User, uid).disabled is True
    _post(client, f"/settings/users/{uid}/toggle")
    with factory() as s:
        assert s.get(User, uid).disabled is False
    _post(client, f"/settings/users/{uid}/delete")
    with factory() as s:
        assert s.get(User, uid) is None
    actions = [a for a, _t in _audits(factory)]
    assert {"user_disable", "user_enable", "user_delete"} <= set(actions)


def test_role_change_and_password_reset(admin_client):
    client, factory = admin_client
    _post(
        client, "/settings/users/create", username="mover", password="a-long-password", role="user"
    )
    uid = _user_id(factory, "mover")
    _post(client, f"/settings/users/{uid}/role", role="analyst")
    with factory() as s:
        assert s.get(User, uid).role == "analyst"
    _post(client, f"/settings/users/{uid}/reset-password", new_password="another-long-password")
    with factory() as s:
        assert verify_password(s.get(User, uid).password_hash, "another-long-password")
    # audit rows never contain the password
    with factory() as s:
        for a in s.execute(select(AdminAudit)).scalars():
            assert "another-long-password" not in (a.detail or "")


def test_last_admin_guard(admin_client):
    client, factory = admin_client
    root_id = _user_id(factory, "root")
    # root is the only active admin: self actions blocked first, but even a
    # second admin cannot demote/disable/delete the last one — simulate by
    # creating admin2, then having root act on... root (self) and admin2.
    _post(
        client,
        "/settings/users/create",
        username="admin2",
        password="a-long-password",
        role="admin",
    )
    admin2_id = _user_id(factory, "admin2")
    # two active admins: disabling admin2 is allowed
    _post(client, f"/settings/users/{admin2_id}/toggle")
    with factory() as s:
        assert s.get(User, admin2_id).disabled is True
    # now root is the last active admin again: self-guard + last-admin guard
    assert "self" in _post(client, f"/settings/users/{root_id}/toggle").headers["location"]
    assert "self" in _post(client, f"/settings/users/{root_id}/delete").headers["location"]
    assert (
        "last_admin"
        in _post(client, f"/settings/users/{root_id}/role", role="user").headers["location"]
    )
    with factory() as s:
        row = s.get(User, root_id)
        assert row.role == "admin" and row.disabled is False


# --- activity tab ---


def test_activity_viewer_filters_and_counters(admin_client):
    client, factory = admin_client
    with factory() as s:
        record_activity(s, "login_fail", actor_name="ghost", client_ip="203.0.113.9")
        # route value chosen to be unique in the page (nav links contain /victims)
        record_activity(s, "page_view", actor_name="root", route="/groups/424242")
        record_activity(s, "access_denied", route="/settings/users", client_ip="203.0.113.9")
    body = client.get("/settings/activity").text
    assert "ghost" in body and "424242" in body
    filtered = client.get("/settings/activity?kind=login_fail").text
    assert "ghost" in filtered and "424242" not in filtered
    by_user = client.get("/settings/activity?user=roo").text
    assert "424242" in by_user and "ghost" not in by_user
