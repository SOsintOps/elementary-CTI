"""v0.7 auth plan step 8: the Sources admin tab.

No new storage: the tab drives the flags that already governed the
scheduler (DataSource.enabled, InfoUpdate "<name>_enabled", and
ArticleSource.enabled). What is new: the UI, the admin gate on it AND on
the pre-existing JSON toggle endpoints, and the audit trail.
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
from pestilentia.models.tables import AdminAudit, ArticleSource, DataSource, InfoUpdate
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
    with factory() as s:
        s.add(DataSource(source_name="ransomware.live", enabled=True))
        s.add(ArticleSource(name="Talos", url="https://x/feed", source_type="rss", enabled=True))
        s.commit()
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64, cookie_secure=False))
    monkeypatch.setattr(web, "_session_factory", factory)
    yield TestClient(app), factory
    web._session_factory = None
    config._settings = None


def _post(client, path):
    return client.post(
        path, data={"csrf_token": web._generate_csrf_token()}, follow_redirects=False
    )


def test_sources_tab_is_admin_only(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="analyst", username="ana")
    assert client.get("/settings/sources").status_code == 403


def test_tab_lists_all_three_families(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    body = client.get("/settings/sources").text
    assert "ransomware.live" in body
    assert "mitre" in body and "deepdarkcti" in body
    assert "Talos" in body


def test_primary_toggle_flips_flag_and_audits(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    with factory() as s:
        sid = s.execute(select(DataSource)).scalar_one().id
    assert _post(client, f"/settings/sources/primary/{sid}/toggle").status_code == 303
    with factory() as s:
        assert s.get(DataSource, sid).enabled is False
        audits = [(a.action, a.target) for a in s.execute(select(AdminAudit)).scalars()]
    assert ("source_disable", "ransomware.live") in audits


def test_enrichment_toggle_creates_and_flips_flag(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    _post(client, "/settings/sources/enrichment/mitre/toggle")
    with factory() as s:
        row = s.execute(
            select(InfoUpdate).where(InfoUpdate.category == "mitre_enabled")
        ).scalar_one()
        assert not row.number  # first toggle disables
    _post(client, "/settings/sources/enrichment/mitre/toggle")
    with factory() as s:
        row = s.execute(
            select(InfoUpdate).where(InfoUpdate.category == "mitre_enabled")
        ).scalar_one()
        assert row.number  # second re-enables


def test_feed_toggle_flips_articlesource(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    with factory() as s:
        fid = s.execute(select(ArticleSource)).scalar_one().id
    _post(client, f"/settings/sources/feed/{fid}/toggle")
    with factory() as s:
        assert s.get(ArticleSource, fid).enabled is False


def test_legacy_json_toggles_now_require_admin(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="user", username="reader")
    headers = {"X-CSRF-Token": web._generate_csrf_token()}
    assert client.post("/api/v1/source/ransomware.live/toggle", headers=headers).status_code == 403
    assert client.post("/api/v1/mitre/toggle", headers=headers).status_code == 403
    assert client.post("/api/v1/enrichment/articles/toggle", headers=headers).status_code == 403
    assert client.post("/api/v1/refresh", headers=headers).status_code == 403  # analyst-gated


def test_legacy_json_toggle_still_works_for_admin(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="admin", username="root")
    headers = {"X-CSRF-Token": web._generate_csrf_token()}
    r = client.post("/api/v1/source/ransomware.live/toggle", headers=headers)
    assert r.status_code == 200
    assert r.json()["enabled"] is False
