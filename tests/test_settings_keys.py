"""v0.7 auth plan step 9: service keys — write-only storage, env-over-DB.

The invariant that matters most: a stored key value never appears in any
response body, ever. The rest: admin-only surface, presence metadata,
resolution precedence, audit rows without values.
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
from pestilentia.models.tables import AdminAudit, ServiceKey
from pestilentia.service_keys import resolve_service_key
from pestilentia.web.app import app

SECRET_VALUE = "sk-verysecret-datamust-never-leak-12345"


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


def _set_key(client, service, value):
    return client.post(
        f"/settings/keys/{service}",
        data={"key_value": value, "csrf_token": web._generate_csrf_token()},
        follow_redirects=False,
    )


def test_keys_tab_is_admin_only(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="analyst", username="ana")
    assert client.get("/settings/keys").status_code == 403
    assert _set_key(client, "abuseipdb", "x").status_code == 403


def test_set_key_stores_and_shows_presence_only(admin_client):
    client, factory = admin_client
    assert _set_key(client, "abuseipdb", SECRET_VALUE).status_code == 303
    body = client.get("/settings/keys").text
    assert "stored" in body and "root" in body
    assert SECRET_VALUE not in body  # the invariant
    with factory() as s:
        row = s.execute(select(ServiceKey)).scalar_one()
        assert row.key_value == SECRET_VALUE
        assert row.updated_by_name == "root"


def test_key_value_never_in_audit(admin_client):
    client, factory = admin_client
    _set_key(client, "greynoise", SECRET_VALUE)
    with factory() as s:
        for a in s.execute(select(AdminAudit)).scalars():
            assert SECRET_VALUE not in (a.detail or "") + a.target + a.action


def test_unknown_service_404_and_empty_value_rejected(admin_client):
    client, _factory = admin_client
    assert _set_key(client, "nsa-backdoor", "x").status_code == 404
    r = _set_key(client, "abuseipdb", "   ")
    assert r.status_code == 303 and "err=empty" in r.headers["location"]


def test_delete_key(admin_client):
    client, factory = admin_client
    _set_key(client, "honeypot", SECRET_VALUE)
    r = client.post(
        "/settings/keys/honeypot/delete",
        data={"csrf_token": web._generate_csrf_token()},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with factory() as s:
        assert s.execute(select(ServiceKey)).scalar_one_or_none() is None


def test_resolution_env_wins_over_db(admin_client, monkeypatch):
    client, factory = admin_client
    _set_key(client, "abuseipdb", "db-value")
    with factory() as s:
        assert resolve_service_key(s, "abuseipdb") == "db-value"
        monkeypatch.setenv("PEST_KEY_ABUSEIPDB", "env-wins")
        assert resolve_service_key(s, "abuseipdb") == "env-wins"
        assert resolve_service_key(s, "unknown-service") == ""


def test_nvidia_resolution_uses_settings_field(admin_client, monkeypatch):
    client, factory = admin_client
    _set_key(client, "nvidia", "db-nvidia-key")
    with factory() as s:
        assert resolve_service_key(s, "nvidia") == "db-nvidia-key"
    monkeypatch.setattr(
        config,
        "_settings",
        Settings(secret_key="x" * 64, cookie_secure=False, ai_nvidia_api_key="env-nvidia-key"),
    )
    with factory() as s:
        assert resolve_service_key(s, "nvidia") == "env-nvidia-key"
