"""v0.7 auth plan step 4: baseline enforcement and the role matrix.

Anonymous requests reach nothing but the public paths: pages bounce to
/login (303), APIs get 401 JSON. Any authenticated role passes the baseline;
the finer analyst/admin gates are exercised through require_role directly,
so the matrix grows with the surfaces that use it (settings, IP analysis).
"""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.web.app import app, require_role

PAGE_ROUTES = [
    "/victims",
    "/groups",
    "/cyberattacks",
    "/map",
    "/search",
    "/btc",
    "/watchlist",
    "/attack",
    "/ai/articles",
    "/ai/campaigns",
    "/guide",
    "/changelog",
    "/pipeline",
]
API_ROUTES = [
    "/api/v1/stats",
    "/api/v1/groups",
    "/api/v1/victims",
    "/api/v1/map",
    "/api/v1/pipeline/status",
]


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


@pytest.mark.parametrize("path", PAGE_ROUTES)
def test_anonymous_page_bounces_to_login(env, path):
    client, _factory = env
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


@pytest.mark.parametrize("path", API_ROUTES)
def test_anonymous_api_gets_401_json(env, path):
    client, _factory = env
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 401
    assert r.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize("role", ["user", "analyst", "admin"])
def test_any_role_passes_the_baseline(env, authenticate, role):
    client, factory = env
    authenticate(client, factory, role=role, username=f"who-{role}")
    assert client.get("/watchlist").status_code == 200
    assert client.get("/api/v1/stats").status_code == 200


def test_openapi_docs_are_not_public(env):
    client, _factory = env
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(path, follow_redirects=False).status_code in (303, 401)


def test_login_page_stays_public(env):
    client, _factory = env
    assert client.get("/login").status_code == 200


@pytest.mark.parametrize("path", ["/", "/faq"])
def test_public_surfaces_serve_anonymous_visitors(env, path):
    """Step 5: the landing page and the FAQ are the anonymous storefront."""
    client, _factory = env
    assert client.get(path, follow_redirects=False).status_code == 200


# --- require_role: the finer gate, exercised on a probe app ---


def _probe_client(role: str | None) -> TestClient:
    probe = FastAPI()

    @probe.middleware("http")
    async def _fake_session(request: Request, call_next):
        request.state.user = (
            None if role is None else {"id": 1, "username": "t", "role": role, "theme": "light"}
        )
        return await call_next(request)

    @probe.get("/analyst-only", dependencies=[Depends(require_role("analyst"))])
    def analyst_only():
        return {"ok": True}

    @probe.get("/admin-only", dependencies=[Depends(require_role("admin"))])
    def admin_only():
        return {"ok": True}

    return TestClient(probe)


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        (None, "/analyst-only", 401),
        ("user", "/analyst-only", 403),
        ("analyst", "/analyst-only", 200),
        ("admin", "/analyst-only", 200),
        ("user", "/admin-only", 403),
        ("analyst", "/admin-only", 403),
        ("admin", "/admin-only", 200),
        ("bogus-role", "/admin-only", 403),  # unknown roles are default-deny
    ],
)
def test_require_role_matrix(role, path, expected):
    assert _probe_client(role).get(path).status_code == expected


# --- OWASP audit A01 (2026-08): curation surfaces are analyst-gated ---------
# The `user` tier is read-only by design (auth plan tier table); watchlist and
# alert mutations plus the health-check trigger are actions, not reads.

CURATION_POSTS = [
    "/watchlist/add",
    "/watchlist/1/delete",
    "/alerts/mark-read",
    "/api/v1/alerts/1/actioned",
    "/api/v1/health",
]


@pytest.mark.parametrize("path", CURATION_POSTS)
def test_user_role_cannot_mutate_curation_surfaces(env, authenticate, path):
    client, factory = env
    authenticate(client, factory, role="user", username="reader")
    token = web._generate_csrf_token()
    r = client.post(
        path,
        data={"csrf_token": token, "name": "x"},
        headers={"X-CSRF-Token": token},
        follow_redirects=False,
    )
    assert r.status_code == 403, path


def test_analyst_passes_curation_gate(env, authenticate):
    client, factory = env
    authenticate(client, factory, role="analyst", username="ana")
    token = web._generate_csrf_token()
    r = client.post(
        "/watchlist/add",
        data={"csrf_token": token, "name": "Acme Corp"},
        follow_redirects=False,
    )
    assert r.status_code == 303


# --- OWASP audit A01 (2026-08): /lang open-redirect hardening ---------------


@pytest.mark.parametrize("target", ["//evil.example", "/\\evil.example", "https://evil.example"])
def test_lang_switch_never_redirects_off_site(env, target):
    client, _factory = env
    r = client.get("/lang/en", params={"next": target}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
