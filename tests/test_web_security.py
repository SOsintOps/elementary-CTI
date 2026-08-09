"""Security regression tests: safe_url filter, optional Basic Auth, avatar bounds."""

import base64

import pytest
from fastapi.testclient import TestClient

import pestilentia.config as config
from pestilentia.config import Settings
from pestilentia.web.app import _safe_url, app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_settings(monkeypatch):
    monkeypatch.setattr(
        config, "_settings", Settings(secret_key="x" * 64, auth_user="holmes", auth_pass="221b")
    )
    yield
    config._settings = None


@pytest.fixture
def open_settings(monkeypatch):
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    yield
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


# --- optional HTTP Basic Auth ---


def _basic(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_auth_disabled_by_default(client, open_settings):
    r = client.get("/avatar/test?size=16")
    assert r.status_code == 200


def test_auth_required_when_configured(client, auth_settings):
    r = client.get("/avatar/test?size=16")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Basic")


def test_healthz_is_public_even_with_auth(client, auth_settings):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_auth_rejects_wrong_credentials(client, auth_settings):
    r = client.get("/avatar/test?size=16", headers=_basic("holmes", "wrong"))
    assert r.status_code == 401


def test_auth_accepts_valid_credentials(client, auth_settings):
    r = client.get("/avatar/test?size=16", headers=_basic("holmes", "221b"))
    assert r.status_code == 200


def test_auth_rejects_malformed_header(client, auth_settings):
    r = client.get("/avatar/test?size=16", headers={"Authorization": "Basic !!!not-base64!!!"})
    assert r.status_code == 401


def test_auth_config_rejects_partial_pair(monkeypatch):
    # set PASS empty (not just absent) so a present .env file can't repopulate it
    monkeypatch.setenv("PEST_AUTH_USER", "holmes")
    monkeypatch.setenv("PEST_AUTH_PASS", "")
    with pytest.raises(SystemExit):
        config._load()


# --- avatar size bounds ---


def test_api_avatar_rejects_zero_size(client, open_settings):
    r = client.get("/api/v1/groups/test/avatar?size=0")
    assert r.status_code == 422


def test_api_avatar_rejects_oversize(client, open_settings):
    r = client.get("/api/v1/groups/test/avatar?size=100000")
    assert r.status_code == 422
