"""S3: every response carries the security headers, on every path and status.

The app served none of these before. Middleware runs on all responses, so the
tests check the boring guarantee that matters — presence everywhere, including
on a 401 and a 404, not just on the happy path.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import pestilentia.config as config
from pestilentia.config import Settings
from pestilentia.web.app import app

REQUIRED = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    yield TestClient(app)
    config._settings = None


@pytest.mark.parametrize("name,value", REQUIRED.items())
def test_core_headers_present_on_a_normal_page(client, name, value):
    assert client.get("/healthz").headers[name] == value


def test_csp_present_and_locks_the_dangerous_directives(client):
    csp = client.get("/healthz").headers["Content-Security-Policy"]
    # These do not depend on the Tailwind runtime and must be strict regardless.
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    assert "default-src 'self'" in csp


def test_permissions_policy_disables_powerful_features(client):
    pp = client.get("/healthz").headers["Permissions-Policy"]
    for feature in ("geolocation=()", "microphone=()", "camera=()"):
        assert feature in pp


def test_the_server_version_banner_is_not_leaked(client):
    assert client.get("/healthz").headers.get("Server") == "Elementary CTI"


def test_headers_are_present_on_the_login_redirect_too(client):
    """A response the session middleware generates itself (not a route
    handler) must still pass through the header middleware."""
    response = client.get("/no-such-page", follow_redirects=False)
    assert response.status_code == 303  # anonymous → bounced to /login
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_headers_are_present_on_a_401(client):
    """The auth rejection is built inside middleware; the header middleware
    wraps it, so the guarantee has to hold on the reject path."""
    response = client.get("/api/v1/stats")
    assert response.status_code == 401
    assert response.headers["X-Frame-Options"] == "DENY"


def test_the_csp_still_admits_what_the_ui_actually_uses(client):
    """A CSP that broke the Tailwind Play runtime would be reverted in minutes
    and teach no one anything. Until the build-step debt (UI-SPEC §9) is paid,
    this documents that the loosening is deliberate, not forgotten."""
    csp = client.get("/healthz").headers["Content-Security-Policy"]
    assert "'unsafe-eval'" in csp  # Tailwind Play compiles in-browser
    assert "img-src 'self' data:" in csp  # inline SVG/data-URI favicon + sparklines
