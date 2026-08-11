# "My name is Sherlock Holmes. I am a consultant to the NYPD." — Sherlock Holmes, Elementary
import asyncio
import hashlib
import hmac
import json
import logging
import math
import re as _re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from sqlalchemy import false, func
from sqlalchemy.orm import Session, joinedload

import pestilentia.clients.ransomware_live  # register source
import pestilentia.notifications.log_channel  # noqa: F401
from pestilentia.activity import (
    KIND_ACCESS_DENIED,
    KIND_API_CALL,
    KIND_LOCKOUT,
    KIND_LOGIN_FAIL,
    KIND_LOGIN_OK,
    KIND_LOGOUT,
    KIND_PAGE_VIEW,
    KIND_PASSWORD_CHANGE,
    record_activity,
)
from pestilentia.clients.registry import SOURCES
from pestilentia.matching import fuzzy_match_watchlist
from pestilentia.models import (
    Alert,
    ArticleSource,
    Country,
    Cyberattack,
    DataSource,
    Group,
    InfoUpdate,
    Victim,
    Watchlist,
    create_all,
    get_session_factory,
)
from pestilentia.models.tables import (
    AdminAudit,
    GroupBtcTransaction,
    GroupTool,
    GroupTTP,
    ServiceKey,
    User,
    UserActivity,
)
from pestilentia.notifications import dispatch_alerts
from pestilentia.pipeline.backfill import BACKFILL_CATEGORY, BACKFILL_FIRST_YEAR
from pestilentia.pipeline.ingest import ingest_source
from pestilentia.security import hash_password, role_at_least, verify_password
from pestilentia.web import sessions as _sessions
from pestilentia.web.i18n import DEFAULT_LANG, LANG_LABELS, SUPPORTED_LANGS, translate
from pestilentia.web.mugshot import generate_mugshot

BASE_DIR = Path(__file__).parent
PER_PAGE = 50

# Paths reachable without authentication: liveness probe, favicon, the login
# flow, and the two anonymous surfaces (step 5) — the public dashboard on "/"
# (the route renders the TLP:CLEAR 30-day variant for anonymous visitors)
# and the FAQ. Anonymous views of public paths are not activity-logged.
_PUBLIC_PATHS = frozenset(
    {"/healthz", "/favicon.ico", "/login", "/", "/faq", "/lang/en", "/lang/it"}
)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    from pestilentia.config import get_settings
    from pestilentia.logging import setup_logging

    cfg = get_settings()
    setup_logging(cfg.log_level)
    # Bootstrap (v0.7 auth plan): with an empty users table, the legacy
    # PEST_AUTH_USER/PEST_AUTH_PASS pair seeds the first admin account so a
    # fresh deployment is never locked out and never open.
    if cfg.auth_user and cfg.auth_pass:
        session = get_db()
        try:
            if session.query(User).count() == 0:
                session.add(
                    User(
                        username=cfg.auth_user.strip().lower(),
                        password_hash=hash_password(cfg.auth_pass),
                        role="admin",
                    )
                )
                session.commit()
                logging.getLogger(__name__).warning(
                    "Bootstrap: created initial admin user %r from PEST_AUTH_USER "
                    "(empty users table). Manage accounts in /settings from now on.",
                    cfg.auth_user,
                )
        finally:
            session.close()
    yield


app = FastAPI(
    title="Elementary CTI",
    description="Cyber threat intelligence platform",
    lifespan=_lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.autoescape = True


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    """Unauthenticated liveness probe — no DB access, safe for Docker HEALTHCHECK."""
    return {"status": "ok"}


# --- Session auth + activity log (v0.7 auth plan, steps 3-4) ---
# One middleware, three jobs: resolve the session cookie into
# request.state.user (sliding the idle window), enforce the baseline
# "everything requires at least a logged-in user" (pages redirect to /login,
# APIs answer 401 JSON), and write the user_activity rows (every
# authenticated request, every denial). Finer gates (analyst/admin) are the
# require_role dependency on the routes that need them.
_ACTIVITY_EXEMPT = frozenset({"/login", "/logout"})  # they log their own richer events


def _set_session_cookie(response: Response, token: str) -> None:
    from pestilentia.config import get_settings

    response.set_cookie(
        _sessions.SESSION_COOKIE,
        token,
        max_age=_sessions.SESSION_ABSOLUTE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=get_settings().cookie_secure,
        path="/",
    )


@app.middleware("http")
async def _session_middleware(request: Request, call_next):
    from pestilentia.config import get_settings

    cfg = get_settings()
    request.state.user = None
    token = request.cookies.get(_sessions.SESSION_COOKIE)
    sdata = _sessions.verify_session(cfg.secret_key, token)
    fresh_token = None
    if sdata is not None:
        session = get_db()
        try:
            row = session.get(User, sdata.uid)
            if row is not None and not row.disabled:
                request.state.user = {
                    "id": row.id,
                    "username": row.username,
                    "role": row.role,
                    "theme": row.theme,
                }
                if int(time.time()) - sdata.ts > _sessions.SESSION_REFRESH_AFTER_SECONDS:
                    fresh_token = _sessions.refresh_session(cfg.secret_key, sdata)
            else:
                sdata = None  # disabled or deleted: drop the cookie below
        finally:
            session.close()

    path = request.url.path
    public = path in _PUBLIC_PATHS or path.startswith("/static")
    denied_anonymous = False
    if not public and request.state.user is None:
        # Baseline enforcement (step 4): no session, no content.
        denied_anonymous = True
        if path.startswith("/api/"):
            response = JSONResponse({"detail": "Authentication required"}, status_code=401)
        else:
            response = RedirectResponse("/login", status_code=303)
    else:
        response = await call_next(request)

    if fresh_token is not None:
        _set_session_cookie(response, fresh_token)
    elif token and sdata is None:
        response.delete_cookie(_sessions.SESSION_COOKIE, path="/")

    loggable = path not in _PUBLIC_PATHS and path not in _ACTIVITY_EXEMPT
    if loggable and not path.startswith("/static"):
        user = request.state.user
        denied = denied_anonymous or response.status_code in (401, 403)
        if user is not None or denied:
            kind = (
                KIND_ACCESS_DENIED
                if denied
                else (KIND_API_CALL if path.startswith("/api/") else KIND_PAGE_VIEW)
            )
            try:
                session = get_db()
                try:
                    record_activity(
                        session,
                        kind,
                        actor_id=user["id"] if user else None,
                        actor_name=user["username"] if user else None,
                        method=request.method,
                        route=path,
                        status=response.status_code,
                        client_ip=request.client.host if request.client else None,
                        user_agent=request.headers.get("user-agent"),
                    )
                finally:
                    session.close()
            except Exception:  # logging must never break the request
                logger.warning("user_activity write failed", exc_info=True)
    return response


# HTTP Basic Auth was retired here in step 4 of the v0.7 auth plan: the
# session middleware above now enforces login on everything outside
# _PUBLIC_PATHS, and PEST_AUTH_USER/PEST_AUTH_PASS live on only as the
# bootstrap seed for the first admin account (see _lifespan).


# --- Security response headers ---
# The app served none. These are cheap, apply to every response, and close the
# ordinary browser-side gaps: MIME sniffing, clickjacking, referer leakage, and
# the default grant of every powerful browser feature.
#
# Registered *after* the auth middleware on purpose: Starlette runs the
# last-added middleware outermost, so this wraps auth and stamps the headers
# onto the 401 short-circuit too, not only onto routed responses.
#
# The CSP is deliberately honest rather than aspirational. The UI loads the
# Tailwind Play *runtime*, which compiles classes in the browser via eval and
# injects styles inline, so `script-src` and `style-src` genuinely need
# 'unsafe-inline'/'unsafe-eval' today. Tightening this is gated on replacing
# that runtime with a build step — the standing debt in UI-SPEC.md §9 — and a
# CSP that lied by omitting what the page actually does would be worse than one
# that states it. Everything else is locked down: no framing, no base-tag
# hijack, no plugins, forms only to self. All assets are same-origin already
# (the permanent no-remote-assets rule), so 'self' costs the UI nothing.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'"
    ),
}


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    # uvicorn advertises its name and version by default; version banners only
    # help someone matching a target to a known exploit.
    response.headers["Server"] = "Elementary CTI"
    return response


# --- CSRF Protection ---
# Accepted model (HI-01): stateless HMAC tokens, no per-request nonce store —
# a leaked token is replayable within the TTL. Acceptable for an admin app
# behind Basic Auth on a trusted network; revisit if exposure changes.
_CSRF_TOKEN_TTL = 3600 * 4  # 4 hours


def _get_secret() -> str:
    from pestilentia.config import get_settings

    return get_settings().secret_key


def _generate_csrf_token() -> str:
    nonce = secrets.token_hex(16)
    ts = str(int(time.time()))
    payload = f"{nonce}:{ts}"
    sig = hmac.new(_get_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    parts = token.split(":")
    if len(parts) != 3:
        return False
    nonce, ts, sig = parts
    try:
        token_time = int(ts)
    except ValueError:
        return False
    if time.time() - token_time > _CSRF_TOKEN_TTL:
        return False
    expected = hmac.new(
        _get_secret().encode(), f"{nonce}:{ts}".encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


templates.env.globals["csrf_token"] = _generate_csrf_token

from pestilentia import __version__ as _app_version  # noqa: E402

templates.env.globals["app_version"] = _app_version
templates.env.globals["ui_langs"] = [(code, LANG_LABELS[code]) for code in SUPPORTED_LANGS]


def _require_csrf_header(x_csrf_token: str | None = Header(default=None)) -> None:
    if not _validate_csrf_token(x_csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")


# --- Role gate (v0.7 auth plan, step 4) ---
# The middleware already guarantees a logged-in user on every non-public
# route; this dependency adds the finer bar where a route needs more than
# the baseline (analyst for the analysis surfaces, admin for settings).
def require_role(minimum: str):
    def _dep(request: Request) -> dict:
        user = request.state.user
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not role_at_least(user["role"], minimum):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _dep


# Module-level dependency singletons (B008: no calls in argument defaults).
REQUIRE_ADMIN = Depends(require_role("admin"))
REQUIRE_ANALYST = Depends(require_role("analyst"))


# --- Login / logout (v0.7 auth plan, step 3) ---
_login_backoff = _sessions.LoginBackoff()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if request.state.user is not None:
        return RedirectResponse("/", status_code=303)
    return _render(request, "login.html", {"error": None})


@app.post("/login", include_in_schema=False)
def login_submit(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    from pestilentia.config import get_settings

    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    ip = _client_ip(request)
    ua = request.headers.get("user-agent")
    username = username.strip().lower()

    session = get_db()
    try:
        locked = _login_backoff.locked_for(username, ip)
        if locked:
            record_activity(
                session, KIND_LOCKOUT, actor_name=username or None, client_ip=ip, user_agent=ua
            )
            return _render(
                request,
                "login.html",
                {"error": _t_req(request, "err_locked", n=locked)},
                status_code=429,
            )

        row = None
        if username:
            row = session.query(User).filter(User.username == username).one_or_none()
        ok = row is not None and not row.disabled and verify_password(row.password_hash, password)
        if not ok:
            # One message for wrong user, wrong password and disabled account —
            # no oracle for enumeration.
            _login_backoff.record_failure(username, ip)
            record_activity(
                session, KIND_LOGIN_FAIL, actor_name=username or None, client_ip=ip, user_agent=ua
            )
            return _render(
                request,
                "login.html",
                {"error": _t_req(request, "err_invalid_credentials")},
                status_code=401,
            )

        _login_backoff.record_success(username, ip)
        row.last_login_at = datetime.now(UTC)
        session.commit()
        record_activity(
            session,
            KIND_LOGIN_OK,
            actor_id=row.id,
            actor_name=row.username,
            client_ip=ip,
            user_agent=ua,
        )
        # A brand-new token on every login: fresh sid, so a pre-login cookie
        # value can never name an authenticated session (fixation defence).
        # The ?in=1 marker lets the landing page detect the silent-failure
        # case where login succeeded but the browser refused the cookie
        # (e.g. Secure flag on a plain-HTTP deployment).
        token = _sessions.issue_session(get_settings().secret_key, row.id)
        response = RedirectResponse("/?in=1", status_code=303)
        _set_session_cookie(response, token)
        return response
    finally:
        session.close()


@app.post("/logout", include_in_schema=False)
def logout(request: Request, csrf_token: str = Form(default="")):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    user = request.state.user
    if user is not None:
        session = get_db()
        try:
            record_activity(
                session,
                KIND_LOGOUT,
                actor_id=user["id"],
                actor_name=user["username"],
                client_ip=_client_ip(request),
            )
        finally:
            session.close()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(_sessions.SESSION_COOKIE, path="/")
    return response


# --- UI language toggle (multi-language) ---
_LANG_COOKIE = "pest_lang"


def _t_req(request: Request, key: str, **fmt) -> str:
    """Translate a catalog key in the requester's language (route-side use,
    e.g. error messages rendered into templates)."""
    lang = request.cookies.get(_LANG_COOKIE, "")
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    text = translate(key, lang)
    return text.format(**fmt) if fmt else text


@app.get("/lang/{code}", include_in_schema=False)
def set_language(code: str, next: str = "/"):
    if code not in SUPPORTED_LANGS:
        raise HTTPException(status_code=404, detail="Unsupported language")
    # local paths only — no open redirect
    if not next.startswith("/") or next.startswith("//"):
        next = "/"
    response = RedirectResponse(next, status_code=303)
    response.set_cookie(_LANG_COOKIE, code, max_age=365 * 24 * 3600, samesite="lax", path="/")
    return response


# --- Settings (v0.7 auth plan, steps 6-9) ---
_MIN_PASSWORD_LEN = 10


def _settings_ctx(request: Request, tab: str, extra: dict | None = None) -> dict:
    ctx = {
        "active": "settings",
        "tab": tab,
        "is_admin": role_at_least(request.state.user["role"], "admin"),
    }
    if extra:
        ctx.update(extra)
    return ctx


@app.get("/settings", include_in_schema=False)
def settings_profile(request: Request, saved: str = ""):
    return _render(
        request,
        "settings_profile.html",
        _settings_ctx(request, "profile", {"saved": saved, "error": None}),
    )


@app.post("/settings/password", include_in_schema=False)
def settings_change_password(
    request: Request,
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    def _err(msg: str, code: int = 400):
        return _render(
            request,
            "settings_profile.html",
            _settings_ctx(request, "profile", {"saved": "", "error": msg}),
            status_code=code,
        )

    if len(new_password) < _MIN_PASSWORD_LEN:
        return _err(_t_req(request, "err_pw_short", n=_MIN_PASSWORD_LEN))
    if new_password != confirm_password:
        return _err(_t_req(request, "err_pw_mismatch"))

    session = get_db()
    try:
        row = session.get(User, request.state.user["id"])
        if row is None or not verify_password(row.password_hash, current_password):
            return _err(_t_req(request, "err_pw_current"), code=403)
        row.password_hash = hash_password(new_password)
        session.commit()
        record_activity(
            session,
            KIND_PASSWORD_CHANGE,
            actor_id=row.id,
            actor_name=row.username,
            client_ip=_client_ip(request),
        )
    finally:
        session.close()
    return RedirectResponse("/settings?saved=password", status_code=303)


@app.post("/settings/theme", include_in_schema=False)
def settings_change_theme(
    request: Request,
    theme: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    if theme not in ("light", "dark"):
        raise HTTPException(status_code=400, detail="Theme must be light or dark")
    session = get_db()
    try:
        row = session.get(User, request.state.user["id"])
        if row is not None:
            row.theme = theme
            session.commit()
    finally:
        session.close()
    return RedirectResponse("/settings?saved=theme", status_code=303)


# --- Settings: Users + Activity admin tabs (step 7) ---


def _audit(session: Session, request: Request, action: str, target: str, detail: str | None = None):
    """One admin_audit row per admin mutation. Never store secrets in detail."""
    actor = request.state.user
    session.add(
        AdminAudit(
            actor_id=actor["id"],
            actor_name=actor["username"],
            action=action[:32],
            target=target[:128],
            detail=detail[:2048] if detail else None,
        )
    )
    session.commit()


def _active_admin_count(session: Session) -> int:
    return session.query(User).filter(User.role == "admin", User.disabled == false()).count()


def _is_last_active_admin(session: Session, row: User) -> bool:
    return row.role == "admin" and not row.disabled and _active_admin_count(session) <= 1


_USERNAME_RE = _re.compile(r"^[a-z0-9_.-]{3,64}$")


@app.get("/settings/users", include_in_schema=False)
def settings_users(request: Request, _admin: dict = REQUIRE_ADMIN, err: str = ""):
    with get_db() as session:
        users = session.query(User).order_by(User.username).all()
        rows = [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "disabled": u.disabled,
                "created_at": u.created_at,
                "last_login_at": u.last_login_at,
            }
            for u in users
        ]
    return _render(
        request, "settings_users.html", _settings_ctx(request, "users", {"users": rows, "err": err})
    )


def _users_redirect(err: str = "") -> RedirectResponse:
    url = "/settings/users" + (f"?err={err}" if err else "")
    return RedirectResponse(url, status_code=303)


@app.post("/settings/users/create", include_in_schema=False)
def settings_users_create(
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    username: str = Form(default=""),
    password: str = Form(default=""),
    role: str = Form(default="user"),
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    username = username.strip().lower()
    if not _USERNAME_RE.fullmatch(username):
        return _users_redirect("bad_username")
    if len(password) < _MIN_PASSWORD_LEN:
        return _users_redirect("short_password")
    if role not in ("user", "analyst", "admin"):
        return _users_redirect("bad_role")
    with get_db() as session:
        if session.query(User).filter(User.username == username).count():
            return _users_redirect("exists")
        session.add(User(username=username, password_hash=hash_password(password), role=role))
        session.commit()
        _audit(session, request, "user_create", username, f"role={role}")
    return _users_redirect()


@app.post("/settings/users/{uid}/toggle", include_in_schema=False)
def settings_users_toggle(
    uid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    with get_db() as session:
        row = session.get(User, uid)
        if row is None:
            return _users_redirect("not_found")
        if row.id == request.state.user["id"]:
            return _users_redirect("self")
        if not row.disabled and _is_last_active_admin(session, row):
            return _users_redirect("last_admin")
        row.disabled = not row.disabled
        session.commit()
        _audit(session, request, "user_disable" if row.disabled else "user_enable", row.username)
    return _users_redirect()


@app.post("/settings/users/{uid}/delete", include_in_schema=False)
def settings_users_delete(
    uid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    with get_db() as session:
        row = session.get(User, uid)
        if row is None:
            return _users_redirect("not_found")
        if row.id == request.state.user["id"]:
            return _users_redirect("self")
        if _is_last_active_admin(session, row):
            return _users_redirect("last_admin")
        name = row.username
        session.delete(row)
        session.commit()
        _audit(session, request, "user_delete", name)
    return _users_redirect()


@app.post("/settings/users/{uid}/role", include_in_schema=False)
def settings_users_role(
    uid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    role: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    if role not in ("user", "analyst", "admin"):
        return _users_redirect("bad_role")
    with get_db() as session:
        row = session.get(User, uid)
        if row is None:
            return _users_redirect("not_found")
        if row.role == "admin" and role != "admin" and _is_last_active_admin(session, row):
            return _users_redirect("last_admin")
        old = row.role
        row.role = role
        session.commit()
        _audit(session, request, "user_role_change", row.username, f"{old} -> {role}")
    return _users_redirect()


@app.post("/settings/users/{uid}/reset-password", include_in_schema=False)
def settings_users_reset_password(
    uid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    new_password: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    if len(new_password) < _MIN_PASSWORD_LEN:
        return _users_redirect("short_password")
    with get_db() as session:
        row = session.get(User, uid)
        if row is None:
            return _users_redirect("not_found")
        row.password_hash = hash_password(new_password)
        session.commit()
        _audit(session, request, "user_password_reset", row.username)
    return _users_redirect()


# --- Settings: Sources admin tab (step 8) ---
# Reuses the toggle storage that already existed (DataSource.enabled,
# InfoUpdate "<name>_enabled" rows, ArticleSource.enabled) — no new table;
# recorded as a deviation in the step 6-9 plan.
_ENRICHMENT_NAMES = ("mitre", "ransomwhere", "deepdarkcti", "articles")


def _enrichment_enabled(session: Session, name: str) -> bool:
    row = session.query(InfoUpdate).filter_by(category=f"{name}_enabled").first()
    return True if row is None else bool(row.number)


@app.get("/settings/sources", include_in_schema=False)
def settings_sources(request: Request, _admin: dict = REQUIRE_ADMIN):
    with get_db() as session:
        primary = [
            {"id": d.id, "name": d.source_name, "enabled": d.enabled}
            for d in session.query(DataSource).order_by(DataSource.source_name)
        ]
        enrichments = [
            {"name": n, "enabled": _enrichment_enabled(session, n)} for n in _ENRICHMENT_NAMES
        ]
        feeds = [
            {"id": f.id, "name": f.name, "enabled": f.enabled, "tlp": f.default_tlp}
            for f in session.query(ArticleSource).order_by(ArticleSource.name)
        ]
    return _render(
        request,
        "settings_sources.html",
        _settings_ctx(
            request,
            "sources",
            {"primary": primary, "enrichments": enrichments, "feeds": feeds},
        ),
    )


@app.post("/settings/sources/primary/{sid}/toggle", include_in_schema=False)
def settings_sources_primary_toggle(
    sid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    with get_db() as session:
        row = session.get(DataSource, sid)
        if row is None:
            raise HTTPException(status_code=404, detail="Source not found")
        row.enabled = not row.enabled
        session.commit()
        _audit(
            session,
            request,
            "source_enable" if row.enabled else "source_disable",
            row.source_name,
        )
    return RedirectResponse("/settings/sources", status_code=303)


@app.post("/settings/sources/enrichment/{name}/toggle", include_in_schema=False)
def settings_sources_enrichment_toggle(
    name: str,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    if name not in _ENRICHMENT_NAMES:
        raise HTTPException(status_code=404, detail="Unknown enrichment")
    with get_db() as session:
        cat = f"{name}_enabled"
        row = session.query(InfoUpdate).filter_by(category=cat).first()
        if row is None:
            session.add(InfoUpdate(category=cat, number=0))
            enabled = False
        else:
            row.number = 0 if row.number else 1
            enabled = bool(row.number)
        session.commit()
        _audit(session, request, "source_enable" if enabled else "source_disable", name)
    return RedirectResponse("/settings/sources", status_code=303)


@app.post("/settings/sources/feed/{fid}/toggle", include_in_schema=False)
def settings_sources_feed_toggle(
    fid: int,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    with get_db() as session:
        row = session.get(ArticleSource, fid)
        if row is None:
            raise HTTPException(status_code=404, detail="Feed not found")
        row.enabled = not row.enabled
        session.commit()
        _audit(session, request, "source_enable" if row.enabled else "source_disable", row.name)
    return RedirectResponse("/settings/sources", status_code=303)


# --- Settings: Service keys admin tab (step 9) ---


@app.get("/settings/keys", include_in_schema=False)
def settings_keys(request: Request, _admin: dict = REQUIRE_ADMIN, err: str = ""):
    from pestilentia.service_keys import KNOWN_SERVICES, key_status

    with get_db() as session:
        statuses = [key_status(session, name) for name in KNOWN_SERVICES]
    return _render(
        request,
        "settings_keys.html",
        _settings_ctx(request, "keys", {"statuses": statuses, "err": err}),
    )


@app.post("/settings/keys/{service}", include_in_schema=False)
def settings_keys_set(
    service: str,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    key_value: str = Form(default=""),
    csrf_token: str = Form(default=""),
):
    from pestilentia.service_keys import KNOWN_SERVICES

    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    if service not in KNOWN_SERVICES:
        raise HTTPException(status_code=404, detail="Unknown service")
    if not key_value.strip():
        return RedirectResponse("/settings/keys?err=empty", status_code=303)
    actor = request.state.user
    with get_db() as session:
        row = session.query(ServiceKey).filter_by(service=service).first()
        if row is None:
            row = ServiceKey(service=service, key_value="")
            session.add(row)
        row.key_value = key_value.strip()
        row.updated_by_id = actor["id"]
        row.updated_by_name = actor["username"]
        row.updated_at = datetime.now(UTC)
        session.commit()
        _audit(session, request, "service_key_set", service)  # never the value
    return RedirectResponse("/settings/keys", status_code=303)


@app.post("/settings/keys/{service}/delete", include_in_schema=False)
def settings_keys_delete(
    service: str,
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    csrf_token: str = Form(default=""),
):
    if not _validate_csrf_token(csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
    with get_db() as session:
        row = session.query(ServiceKey).filter_by(service=service).first()
        if row is not None:
            session.delete(row)
            session.commit()
            _audit(session, request, "service_key_delete", service)
    return RedirectResponse("/settings/keys", status_code=303)


_ACTIVITY_WINDOWS = {"24h": 1, "7d": 7, "30d": 30}


@app.get("/settings/activity", include_in_schema=False)
def settings_activity(
    request: Request,
    _admin: dict = REQUIRE_ADMIN,
    kind: str = "",
    user: str = "",
    window: str = "7d",
):
    days = _ACTIVITY_WINDOWS.get(window, 7)
    cutoff = datetime.now(UTC) - timedelta(days=days)
    with get_db() as session:
        q = session.query(UserActivity).filter(UserActivity.ts >= cutoff)
        if kind:
            q = q.filter(UserActivity.kind == kind)
        if user:
            q = q.filter(UserActivity.actor_name.ilike(f"%{_escape_like(user)}%", escape="\\"))
        rows = q.order_by(UserActivity.ts.desc()).limit(200).all()
        counters = dict(
            session.query(UserActivity.kind, func.count(UserActivity.id))
            .filter(
                UserActivity.ts >= cutoff,
                UserActivity.kind.in_(["login_fail", "lockout", "access_denied"]),
            )
            .group_by(UserActivity.kind)
            .all()
        )
    return _render(
        request,
        "settings_activity.html",
        _settings_ctx(
            request,
            "activity",
            {
                "rows": rows,
                "counters": counters,
                "kind": kind,
                "user_filter": user,
                "window": window,
                "kinds": sorted(
                    {
                        "login_ok",
                        "login_fail",
                        "lockout",
                        "logout",
                        "access_denied",
                        "page_view",
                        "api_call",
                        "password_change",
                    }
                ),
            },
        ),
    )


def _escape_like(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _country_to_flag(iso_code: str) -> str:
    if not iso_code or len(iso_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso_code.upper())


def _parse_aliases(aliases_json: str | None) -> list[str]:
    if not aliases_json:
        return []
    try:
        parsed = json.loads(aliases_json)
    except (json.JSONDecodeError, TypeError):
        return []
    # Legacy rows may hold a JSON scalar instead of a list — a bare string
    # would iterate char-by-char in templates (LO-01)
    return parsed if isinstance(parsed, list) else [str(parsed)]


_SOURCE_LINE_RE = _re.compile(
    r"^\s*[Ss]ource\s*:\s*(https?://\S+)\s*$",
    _re.MULTILINE,
)


def _clean_description(text: str | None) -> Markup:
    """Convert raw HTML br tags to proper paragraphs, strip source attribution lines."""
    if not text:
        return Markup("")
    cleaned = _re.sub(r"<[Bb][Rr]\s*/?>", "\n", text)
    cleaned = _SOURCE_LINE_RE.sub("", cleaned)
    paragraphs = [p.strip() for p in _re.split(r"\n\s*\n", cleaned) if p.strip()]
    html = "".join(f"<p class='mb-2'>{Markup.escape(p)}</p>" for p in paragraphs)
    return Markup(html)


def _extract_sources(text: str | None) -> list[str]:
    """Extract source attribution URLs from description text."""
    if not text:
        return []
    cleaned = _re.sub(r"<[Bb][Rr]\s*/?>", "\n", text)
    return _SOURCE_LINE_RE.findall(cleaned)


def _parse_json_list(value: str | None) -> list:
    """Parse a JSON-encoded list, returning empty list on failure."""
    if not value:
        return []
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else [result]
    except (json.JSONDecodeError, TypeError):
        return []


def _safe_url(url: str | None) -> str:
    """Allow only http(s) URLs in href attributes — feed data is adversary-controlled,
    so javascript:/data:/vbscript: schemes must never reach the browser."""
    if not url:
        return "#"
    candidate = url.strip()
    if candidate.lower().startswith(("http://", "https://")):
        return candidate
    return "#"


def _parse_group_type(value: str | None) -> str:
    """Parse group type field — may be JSON dict like {'raas': false} or plain string."""
    if not value:
        return ""
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return ", ".join(k for k, v in parsed.items()) or ""
        return str(parsed)
    except (json.JSONDecodeError, TypeError):
        return value


templates.env.filters["flag"] = _country_to_flag
templates.env.filters["parse_aliases"] = _parse_aliases
templates.env.filters["clean_desc"] = _clean_description
templates.env.filters["extract_sources"] = _extract_sources
templates.env.filters["parse_json_list"] = _parse_json_list
templates.env.filters["parse_group_type"] = _parse_group_type
templates.env.filters["safe_url"] = _safe_url


# "The truth is rarely pure and never simple." — Sherlock Holmes, Elementary
def _render(request: Request, name: str, ctx: dict, status_code: int = 200):
    # UI language (EN default, IT via the sidebar toggle): resolved once per
    # request and injected as `lang` + a bound `t()` for every template.
    lang = request.cookies.get(_LANG_COOKIE, "")
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    ctx.setdefault("lang", lang)
    ctx.setdefault("t", lambda key: translate(key, lang))
    return templates.TemplateResponse(
        request=request, name=name, context=ctx, status_code=status_code
    )


logger = logging.getLogger(__name__)

_session_factory = None


def get_db() -> Session:
    global _session_factory
    if _session_factory is None:
        from pestilentia.config import get_settings

        cfg = get_settings()
        create_all(cfg.db_url)
        _session_factory = get_session_factory(cfg.db_url)
    return _session_factory()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _last_update(session: Session) -> datetime | None:
    return session.query(func.max(InfoUpdate.last_update_json)).scalar()


def _month_bucket(session: Session, column):
    """Truncate a datetime column to its month, in the DB, per dialect.

    Aggregating in SQL rather than in Python keeps the payload proportional to
    the number of months instead of the number of victims — the row count is
    what grows, and the browser should never see it.
    """
    if session.get_bind().dialect.name == "postgresql":
        return func.to_char(func.date_trunc("month", column), "YYYY-MM")
    return func.strftime("%Y-%m", column)


def _monthly_series(session: Session, id_col, date_col, months: int) -> list[dict]:
    """Rows per month over the trailing `months`, oldest first.

    Months with no rows are filled with zero: a line that silently skips empty
    months implies continuity that isn't there.
    """
    now = datetime.now(UTC)
    # Month arithmetic, not day arithmetic: stepping back N*31 days drifts and
    # lands in the wrong month, which shows up as an off-by-one window.
    total = (now.year * 12 + now.month - 1) - (months - 1)
    first = now.replace(year=total // 12, month=total % 12 + 1, day=1)
    bucket = _month_bucket(session, date_col)
    rows = (
        session.query(bucket.label("month"), func.count(id_col))
        .filter(date_col.isnot(None), date_col >= first)
        .group_by(bucket)
        .all()
    )
    counts = {m: n for m, n in rows if m}

    series: list[dict] = []
    year, month = first.year, first.month
    while (year, month) <= (now.year, now.month):
        key = f"{year:04d}-{month:02d}"
        series.append({"month": key, "count": counts.get(key, 0)})
        month += 1
        if month > 12:
            year, month = year + 1, 1
    return series


def _victim_timeline(session: Session, months: int = 24) -> list[dict]:
    return _monthly_series(session, Victim.id, Victim.attackdate, months)


def _pir_terms(session: Session) -> list[str]:
    """Priority Intelligence Requirements, derived from the active watchlist.

    PIRs are the 2026 answer to "more data is not better data": without a
    statement of what the analyst actually cares about, a feed pipeline
    accumulates noise by definition. Elementary CTI already records that
    statement — the watchlist is what this operator is watching — so it is read
    as the PIR set rather than duplicated into a new table (which would need an
    approved migration without saying anything the watchlist does not).

    Anticipating this in Phase 2 is deliberate: once an LLM router exists,
    relevance is what decides which articles are worth spending tokens on.
    """
    terms: set[str] = set()
    for row in session.query(Watchlist).filter(Watchlist.active.is_(True)).all():
        for raw in (row.name, row.domain, row.keywords or ""):
            for part in (raw or "").replace(";", ",").split(","):
                token = part.strip().lower()
                # Two characters match half the corpus by accident.
                if len(token) >= 3:
                    terms.add(token)
    return sorted(terms)


def _pir_hits(article, terms: list[str]) -> list[str]:
    """Which PIR terms this article mentions. Title and body only — never URL,
    where a vendor's own domain would match a watchlisted company by chance."""
    if not terms:
        return []
    haystack = f"{article.title or ''} {(article.body or '')[:20000]}".lower()
    return [t for t in terms if t in haystack]


# Match strength, strongest first. A domain match is documentary evidence; a
# keyword match is fuzzy and can be a coincidence. There is no severity column
# on Alert, so triage order is DERIVED from what the row actually records —
# inventing a stored severity would need a migration and would not be more true.
_MATCH_STRENGTH = {"domain": 0, "name": 1, "keyword": 2}
ALERT_RECENT_DAYS = 7


def _triage_alerts(alerts: list, recent_days: int = ALERT_RECENT_DAYS) -> dict:
    """Split alerts into act / review / archive.

    Flat lists make everything look equally urgent, which is the documented
    road to alert fatigue. The three tiers are: unread (needs a decision),
    read but recent (context), and older (history, collapsed by default).
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=recent_days)

    def _age_key(alert):
        created = alert.created_at
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        return created or now

    def _is_recent(alert) -> bool:
        return _age_key(alert) >= cutoff

    unread = [a for a in alerts if not a.seen]
    read = [a for a in alerts if a.seen]
    unread.sort(key=lambda a: (_MATCH_STRENGTH.get(a.match_field, 9), -_age_key(a).timestamp()))
    recent = sorted((a for a in read if _is_recent(a)), key=lambda a: _age_key(a), reverse=True)
    older = sorted((a for a in read if not _is_recent(a)), key=lambda a: _age_key(a), reverse=True)
    return {"unread": unread, "recent": recent, "older": older, "recent_days": recent_days}


def _group_sparks(session: Session, group_ids: list[int], months: int = 12) -> dict[int, list[int]]:
    """Monthly victim counts per group, for a whole page of groups at once.

    One grouped query rather than one per row: the adversary list renders 50
    groups a page, and a per-row query would mean 50 round trips.
    """
    if not group_ids:
        return {}
    now = datetime.now(UTC)
    total = (now.year * 12 + now.month - 1) - (months - 1)
    first = now.replace(year=total // 12, month=total % 12 + 1, day=1)
    bucket = _month_bucket(session, Victim.attackdate)
    rows = (
        session.query(Victim.group_id, bucket.label("month"), func.count(Victim.id))
        .filter(
            Victim.group_id.in_(group_ids),
            Victim.attackdate.isnot(None),
            Victim.attackdate >= first,
        )
        .group_by(Victim.group_id, bucket)
        .all()
    )
    counts: dict[int, dict[str, int]] = {}
    for gid, month, n in rows:
        if month:
            counts.setdefault(gid, {})[month] = n

    keys: list[str] = []
    year, month = first.year, first.month
    while (year, month) <= (now.year, now.month):
        keys.append(f"{year:04d}-{month:02d}")
        month += 1
        if month > 12:
            year, month = year + 1, 1

    # Every group gets a full-length series, including the silent ones — a
    # flat line is the signal "dormant", and omitting it would hide that.
    return {gid: [counts.get(gid, {}).get(k, 0) for k in keys] for gid in group_ids}


def _kpi_trend(session: Session, id_col, date_col, window_days: int = 30) -> dict:
    """Trailing-window count, its change vs the preceding window, and a spark.

    Only offered for metrics that actually carry a date. `Group`, `Country` and
    the source registry have no time dimension, so they get a bare count rather
    than an invented trend.
    """
    now = datetime.now(UTC)
    cur_start = now - timedelta(days=window_days)
    prev_start = now - timedelta(days=2 * window_days)

    def _count(lo, hi):
        return (
            session.query(func.count(id_col))
            .filter(date_col.isnot(None), date_col >= lo, date_col < hi)
            .scalar()
            or 0
        )

    current = _count(cur_start, now)
    previous = _count(prev_start, cur_start)
    # No baseline means no percentage — rendering one would invent a trend.
    delta_pct = round((current - previous) / previous * 100) if previous else None
    return {
        "current": current,
        "previous": previous,
        "delta_pct": delta_pct,
        "window_days": window_days,
        "spark": [p["count"] for p in _monthly_series(session, id_col, date_col, 12)],
    }


def _paginate(query, page: int):
    total = query.count()
    pages = max(1, math.ceil(total / PER_PAGE))
    items = query.offset((page - 1) * PER_PAGE).limit(PER_PAGE).all()
    return items, total, pages


def _victim_serialize(v: Victim) -> dict:
    return {
        "id": v.id,
        "victim_name": v.victim_name,
        "domain": v.domain,
        "group": v.group.group_name if v.group else None,
        "country": v.country.iso_code if v.country else None,
        "attackdate": v.attackdate.isoformat() if v.attackdate else None,
        "discovered": v.discovered.isoformat() if v.discovered else None,
        "activity": v.activity,
    }


def _group_serialize(g: Group, victim_count: int = 0) -> dict:
    return {
        "id": g.id,
        "group_name": g.group_name,
        "description": g.description,
        "url": g.url,
        "victim_count": victim_count,
    }


def _attack_serialize(a: Cyberattack) -> dict:
    return {
        "id": a.id,
        "victim_name": a.victim_name,
        "domain": a.domain,
        "country": a.country,
        "attack_date": a.attack_date.isoformat() if a.attack_date else None,
        "title": a.title,
        "summary": a.summary,
    }


# ---------------------------------------------------------------------------
# Web Pages
# ---------------------------------------------------------------------------


def _count_sources(session: Session) -> int:
    count = session.query(DataSource).count()
    # Count an enrichment only if it's currently enabled AND has run at
    # least once — a toggled-off enrichment is not an active source (ME-09)
    for name in ("mitre", "ransomwhere", "deepdarkcti"):
        has_run = (
            session.query(InfoUpdate).filter_by(category=f"{name}_enrichment").first() is not None
        )
        if has_run and _is_enrichment_enabled(session, name):
            count += 1
    return count


# "I know you're capable of more." — Joan Watson, Elementary
@app.get("/")
def dashboard(request: Request):
    now = datetime.now(UTC)
    if request.state.user is None:
        return _public_dashboard(request, now)
    with get_db() as session:
        stats = {
            "victims": session.query(Victim).count(),
            "groups": session.query(Group).count(),
            "cyberattacks": session.query(Cyberattack).count(),
            "countries": session.query(Country).count(),
            "sources": _count_sources(session),
        }

        recent_victims = {}
        top_groups = {}
        country_data = {}
        for label, days in [("7d", 7), ("1m", 30), ("1y", 365)]:
            cutoff = now - timedelta(days=days)
            recent_victims[label] = (
                session.query(Victim)
                .options(
                    joinedload(Victim.group),
                    joinedload(Victim.country),
                )
                .filter(Victim.discovered >= cutoff)
                .order_by(Victim.discovered.desc().nullslast())
                .limit(20)
                .all()
            )
            top_groups[label] = (
                session.query(Group, func.count(Victim.id).label("cnt"))
                .join(Victim, Victim.group_id == Group.id)
                .filter(Victim.attackdate >= cutoff)
                .group_by(Group.id)
                .order_by(func.count(Victim.id).desc())
                .limit(10)
                .all()
            )
            cc = (
                session.query(Country.iso_code, func.count(Victim.id))
                .join(Victim, Victim.country_id == Country.id)
                .filter(Victim.attackdate >= cutoff)
                .group_by(Country.iso_code)
                .all()
            )
            country_data[label] = [{"code": c, "count": n} for c, n in cc]
        last_update = _last_update(session)
        timeline = _victim_timeline(session)
        trends = {
            "victims": _kpi_trend(session, Victim.id, Victim.attackdate),
            "cyberattacks": _kpi_trend(session, Cyberattack.id, Cyberattack.attack_date),
        }

    return _render(
        request,
        "dashboard.html",
        {
            "active": "dashboard",
            "stats": stats,
            "recent_victims": recent_victims,
            "top_groups": top_groups,
            "country_data": country_data,
            "last_update": last_update,
            "timeline": timeline,
            "trends": trends,
        },
    )


def _public_dashboard(request: Request, now: datetime):
    """Anonymous landing (v0.7 auth plan, step 5): last-30-days aggregates
    and recent names from public-source structured data only. TLP-marked
    content (articles) is never queried here, so it cannot leak by
    construction. No drill-down links — everything deeper requires login."""
    cutoff = now - timedelta(days=30)
    with get_db() as session:
        stats = {
            "victims_30d": session.query(Victim).filter(Victim.discovered >= cutoff).count(),
            "groups_30d": (
                session.query(Victim.group_id)
                .filter(Victim.discovered >= cutoff, Victim.group_id.isnot(None))
                .distinct()
                .count()
            ),
            "cyberattacks_30d": (
                session.query(Cyberattack).filter(Cyberattack.attack_date >= cutoff).count()
            ),
            "countries_30d": (
                session.query(Victim.country_id)
                .filter(Victim.discovered >= cutoff, Victim.country_id.isnot(None))
                .distinct()
                .count()
            ),
        }
        recent_victims = (
            session.query(Victim)
            .options(joinedload(Victim.group), joinedload(Victim.country))
            .filter(Victim.discovered >= cutoff)
            .order_by(Victim.discovered.desc().nullslast())
            .limit(20)
            .all()
        )
        top_groups = (
            session.query(Group.group_name, func.count(Victim.id).label("cnt"))
            .join(Victim, Victim.group_id == Group.id)
            .filter(Victim.discovered >= cutoff)
            .group_by(Group.group_name)
            .order_by(func.count(Victim.id).desc())
            .limit(10)
            .all()
        )
        # Daily buckets computed in Python: 30 days of rows is small, and it
        # sidesteps SQLite/PG date-function differences.
        by_day: dict[str, int] = {}
        for (discovered,) in session.query(Victim.discovered).filter(Victim.discovered >= cutoff):
            if discovered is not None:
                by_day[discovered.strftime("%Y-%m-%d")] = (
                    by_day.get(discovered.strftime("%Y-%m-%d"), 0) + 1
                )
        timeline = [
            {"day": (cutoff + timedelta(days=i)).strftime("%Y-%m-%d")}
            | {"count": by_day.get((cutoff + timedelta(days=i)).strftime("%Y-%m-%d"), 0)}
            for i in range(1, 31)
        ]
    return _render(
        request,
        "dashboard_public.html",
        {
            "active": "dashboard",
            "stats": stats,
            "recent_victims": recent_victims,
            "top_groups": top_groups,
            "timeline": timeline,
            # Login round-trip landed here anonymous: the browser did not
            # keep the session cookie. Surface it instead of failing silently.
            "cookie_lost": request.query_params.get("in") == "1",
        },
    )


@app.get("/faq")
def faq(request: Request):
    """Public FAQ: renders docs/FAQ.md at request time (changelog pattern —
    the file must be copied by the Dockerfile, pinned by test)."""
    import markdown as _md

    # Per-language document resolution: docs/FAQ.<lang>.md, falling back to
    # the English docs/FAQ.md. Same convention for any future language.
    lang = request.cookies.get(_LANG_COOKIE, "")
    candidates = [FAQ_PATH.with_name(f"FAQ.{lang}.md")] if lang and lang != DEFAULT_LANG else []
    candidates.append(FAQ_PATH)
    source = None
    for path in candidates:
        try:
            source = path.read_text(encoding="utf-8")
            break
        except OSError:
            continue
    if source is None:
        source = "# FAQ\n\nThe FAQ file is missing from this deployment."
    html = _md.markdown(source, extensions=["tables", "fenced_code", "toc"])
    return _render(request, "faq.html", {"active": "faq", "faq_html": html})


@app.get("/victims")
def victims_list(
    request: Request,
    page: int = Query(default=1, ge=1),
    q: str = "",
    group: str = "",
    country: str = "",
):
    with get_db() as session:
        query = session.query(Victim).options(joinedload(Victim.group), joinedload(Victim.country))
        if q:
            query = query.filter(
                Victim.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                | Victim.domain.ilike(f"%{_escape_like(q)}%", escape="\\")
            )
        if group:
            query = query.join(Group).filter(Group.group_name == group)
        if country:
            query = query.join(Country).filter(Country.iso_code == country)

        query = query.order_by(Victim.attackdate.desc().nullslast())
        victims, total, pages = _paginate(query, page)
        all_groups = session.query(Group).order_by(Group.group_name).all()
        all_countries = session.query(Country).order_by(Country.iso_code).all()

    return _render(
        request,
        "victims.html",
        {
            "active": "victims",
            "victims": victims,
            "total": total,
            "page": page,
            "pages": pages,
            "q": q,
            "group": group,
            "country": country,
            "groups": all_groups,
            "countries": all_countries,
        },
    )


@app.get("/victims/{victim_id}")
def victim_detail(request: Request, victim_id: int):
    with get_db() as session:
        victim = (
            session.query(Victim)
            .options(
                joinedload(Victim.group),
                joinedload(Victim.country),
                joinedload(Victim.source),
                joinedload(Victim.duplicates),
                joinedload(Victim.organizations),
            )
            .filter(Victim.id == victim_id)
            .first()
        )
        if not victim:
            return _render(request, "404.html", {}, status_code=404)

    return _render(
        request,
        "victim_detail.html",
        {"active": "victims", "victim": victim},
    )


@app.get("/groups")
def groups_list(request: Request):
    with get_db() as session:
        groups = (
            session.query(Group, func.count(Victim.id).label("cnt"))
            .outerjoin(Victim, Victim.group_id == Group.id)
            .group_by(Group.id)
            .order_by(func.count(Victim.id).desc())
            .all()
        )
        sparks = _group_sparks(session, [g.id for g, _ in groups])

    return _render(
        request,
        "groups.html",
        {"active": "groups", "groups": groups, "sparks": sparks},
    )


@app.get("/groups/{group_id}")
def group_detail(request: Request, group_id: int):
    with get_db() as session:
        group = (
            session.query(Group)
            .options(
                joinedload(Group.source),
                joinedload(Group.locations),
                joinedload(Group.tools),
                joinedload(Group.ttps),
                joinedload(Group.references),
                joinedload(Group.comms),
            )
            .filter(Group.id == group_id)
            .first()
        )
        if not group:
            return _render(request, "404.html", {}, status_code=404)

        victim_count = session.query(Victim).filter(Victim.group_id == group_id).count()

        # BTC transaction stats
        btc_stats = (
            session.query(
                func.count(GroupBtcTransaction.id),
                func.sum(GroupBtcTransaction.amount_btc),
                func.sum(GroupBtcTransaction.amount_usd),
                func.count(func.distinct(GroupBtcTransaction.address)),
            )
            .filter(GroupBtcTransaction.group_id == group_id)
            .first()
        )
        btc_tx_count, btc_total_btc, btc_total_usd, btc_addr_count = btc_stats or (0, 0, 0, 0)
        victims = (
            session.query(Victim)
            .options(joinedload(Victim.country))
            .filter(Victim.group_id == group_id)
            .order_by(Victim.attackdate.desc().nullslast())
            .limit(50)
            .all()
        )

        country_counts = (
            session.query(Country.iso_code, func.count(Victim.id))
            .join(Victim, Victim.country_id == Country.id)
            .filter(Victim.group_id == group_id)
            .group_by(Country.iso_code)
            .all()
        )
        country_data = [{"code": c, "count": n} for c, n in country_counts]

        tools_by_cat = {}
        for t in group.tools:
            tools_by_cat.setdefault(t.category, []).append(t.tool_name)

        ttps_by_tactic = {}
        for t in group.ttps:
            ttps_by_tactic.setdefault(t.tactic_name, []).append(t)

        ttp_count = sum(len(v) for v in ttps_by_tactic.values())
        tool_count = sum(len(v) for v in tools_by_cat.values())
        top_countries = sorted(country_data, key=lambda x: x["count"], reverse=True)[:5]

        # Per-source evidence (evidence vs synthesis): MITRE full profile
        from pestilentia.models.tables import GroupSourceData

        mitre_profile = None
        mitre_fetched = None
        mitre_row = (
            session.query(GroupSourceData)
            .join(DataSource)
            .filter(
                GroupSourceData.group_name == group.group_name,
                DataSource.source_name == "MITRE ATT&CK",
            )
            .first()
        )
        if mitre_row:
            try:
                mitre_profile = json.loads(mitre_row.raw_data)
                mitre_fetched = mitre_row.fetched_at
            except (json.JSONDecodeError, TypeError):
                mitre_profile = None

        last_update = _last_update(session)
        spark = _group_sparks(session, [group.id]).get(group.id, [])

    return _render(
        request,
        "group_detail.html",
        {
            "active": "groups",
            "group": group,
            "mitre_profile": mitre_profile,
            "mitre_fetched": mitre_fetched,
            "victim_count": victim_count,
            "victims": victims,
            "country_data": country_data,
            "tools_by_cat": tools_by_cat,
            "ttps_by_tactic": ttps_by_tactic,
            "ttp_count": ttp_count,
            "tool_count": tool_count,
            "top_countries": top_countries,
            "btc_tx_count": btc_tx_count or 0,
            "btc_total_btc": float(btc_total_btc or 0),
            "btc_total_usd": float(btc_total_usd or 0),
            "btc_addr_count": btc_addr_count or 0,
            "is_hacktivist": _is_hacktivist(group),
            "last_update": last_update,
            "spark": spark,
        },
    )


def _is_hacktivist(group: Group) -> bool:
    # Persisted at ingest time (ME-11); see pestilentia.classify
    return bool(group.is_hacktivist)


@app.get("/cyberattacks")
def cyberattacks_list(
    request: Request,
    page: int = Query(default=1, ge=1),
    q: str = "",
    country: str = "",
):
    with get_db() as session:
        query = session.query(Cyberattack)
        if q:
            query = query.filter(
                Cyberattack.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                | Cyberattack.title.ilike(f"%{_escape_like(q)}%", escape="\\")
            )
        if country:
            query = query.filter(Cyberattack.country == country)

        query = query.order_by(Cyberattack.attack_date.desc().nullslast())
        attacks, total, pages = _paginate(query, page)

        countries = [
            r[0]
            for r in session.query(Cyberattack.country)
            .filter(Cyberattack.country.isnot(None))
            .distinct()
            .order_by(Cyberattack.country)
            .all()
        ]

    return _render(
        request,
        "cyberattacks.html",
        {
            "active": "cyberattacks",
            "attacks": attacks,
            "total": total,
            "page": page,
            "pages": pages,
            "q": q,
            "country": country,
            "countries": countries,
        },
    )


def _map_data(session: Session, period: str = "all") -> tuple[list[dict], int]:
    query = session.query(Country.iso_code, func.count(Victim.id)).join(
        Victim, Victim.country_id == Country.id
    )
    cutoffs = {"7d": 7, "15d": 15, "1m": 30, "1y": 365}
    if period in cutoffs:
        since = datetime.now(UTC) - timedelta(days=cutoffs[period])
        query = query.filter(Victim.attackdate >= since)
    rows = query.group_by(Country.iso_code).all()
    country_data = [{"code": c, "count": n} for c, n in rows]
    return country_data, sum(d["count"] for d in country_data)


@app.get("/map")
def map_view(request: Request, period: str = "all"):
    with get_db() as session:
        country_data, total_mapped = _map_data(session, period)

    return _render(
        request,
        "map.html",
        {
            "active": "map",
            "country_data": country_data,
            "total_mapped": total_mapped,
            "period": period,
        },
    )


@app.get("/api/v1/map")
def api_map_data(period: str = "all"):
    with get_db() as session:
        country_data, total_mapped = _map_data(session, period)
    return {"country_data": country_data, "total_mapped": total_mapped}


@app.get("/pipeline")
def pipeline_status(request: Request):
    with get_db() as session:
        data_sources_q = session.query(DataSource).all()

        # Batch counts in 3 queries instead of N*3
        victim_counts = dict(
            session.query(Victim.source_id, func.count(Victim.id)).group_by(Victim.source_id).all()
        )
        group_counts = dict(
            session.query(Group.source_id, func.count(Group.id)).group_by(Group.source_id).all()
        )
        attack_counts = dict(
            session.query(Cyberattack.source_id, func.count(Cyberattack.id))
            .group_by(Cyberattack.source_id)
            .all()
        )

        data_sources = []
        for ds in data_sources_q:
            ds.victim_count = victim_counts.get(ds.id, 0)
            ds.group_count = group_counts.get(ds.id, 0)
            ds.attack_count = attack_counts.get(ds.id, 0)
            data_sources.append(ds)

        # Batch backfill status: single query for all InfoUpdate categories
        backfill_rows = (
            session.query(InfoUpdate.category)
            .filter(
                InfoUpdate.category.like(f"{BACKFILL_CATEGORY}:%")
                | InfoUpdate.category.like("backfill_year:%")
            )
            .all()
        )
        backfill_categories = {r[0] for r in backfill_rows}

        sources = []
        for ds in data_sources_q:
            backfill_done = f"{BACKFILL_CATEGORY}:{ds.source_name}" in backfill_categories
            years_done = [
                year
                for year in range(BACKFILL_FIRST_YEAR, datetime.now(UTC).year + 1)
                if f"backfill_year:{ds.source_name}:{year}" in backfill_categories
            ]
            sources.append(
                {
                    "source_name": ds.source_name,
                    "backfill_done": backfill_done,
                    "years_done": years_done,
                    "enabled": ds.enabled,
                }
            )

        # MITRE enrichment status
        from pestilentia.clients.mitre_attack import MITRE_ENRICHMENT_CATEGORY

        mitre_row = session.query(InfoUpdate).filter_by(category=MITRE_ENRICHMENT_CATEGORY).first()
        mitre_enabled = _is_mitre_enabled(session)
        mitre_status = {
            "enabled": mitre_enabled,
            "last_enrichment": mitre_row.last_update_json if mitre_row else None,
            "groups_with_ttps": session.query(
                func.count(func.distinct(GroupTTP.group_id))
            ).scalar(),
            "total_ttps": session.query(func.count(GroupTTP.id)).scalar(),
            "total_tools": session.query(func.count(GroupTool.id)).scalar(),
            "groups_with_aliases": session.query(func.count(Group.id))
            .filter(Group.aliases.isnot(None))
            .scalar(),
        }

        # Ransomwhere enrichment status
        from pestilentia.clients.ransomwhere import RANSOMWHERE_CATEGORY

        rw_row = session.query(InfoUpdate).filter_by(category=RANSOMWHERE_CATEGORY).first()
        rw_status = {
            "enabled": _is_enrichment_enabled(session, "ransomwhere"),
            "last_enrichment": rw_row.last_update_json if rw_row else None,
            "total_txs": session.query(func.count(GroupBtcTransaction.id)).scalar(),
            "total_addresses": session.query(
                func.count(func.distinct(GroupBtcTransaction.address))
            ).scalar(),
            "groups_with_btc": session.query(
                func.count(func.distinct(GroupBtcTransaction.group_id))
            ).scalar(),
            "total_usd": float(
                session.query(func.sum(GroupBtcTransaction.amount_usd)).scalar() or 0
            ),
        }

        # deepdarkCTI enrichment status
        from pestilentia.clients.deepdarkcti import DEEPDARK_CATEGORY

        dd_row = session.query(InfoUpdate).filter_by(category=DEEPDARK_CATEGORY).first()
        from pestilentia.models.tables import GroupComm

        dd_status = {
            "enabled": _is_enrichment_enabled(session, "deepdarkcti"),
            "last_enrichment": dd_row.last_update_json if dd_row else None,
            "total_comms": session.query(func.count(GroupComm.id)).scalar(),
            "groups_with_comms": session.query(
                func.count(func.distinct(GroupComm.group_id))
            ).scalar(),
        }

        # Article ingest (AI pipeline Phase 2)
        from pestilentia.ai.sources import ARTICLES_CATEGORY
        from pestilentia.models.tables import Article, ArticleSource

        art_row = session.query(InfoUpdate).filter_by(category=ARTICLES_CATEGORY).first()
        art_status = {
            "enabled": _is_enrichment_enabled(session, "articles"),
            "last_enrichment": art_row.last_update_json if art_row else None,
            "total_articles": session.query(func.count(Article.id)).scalar() or 0,
            "full_text": session.query(func.count(Article.id))
            .filter(Article.truncated.is_(False))
            .scalar()
            or 0,
            "sources_enabled": session.query(func.count(ArticleSource.id))
            .filter(ArticleSource.enabled.is_(True))
            .scalar()
            or 0,
            "sources_total": session.query(func.count(ArticleSource.id)).scalar() or 0,
        }

        # Source health status
        from pestilentia.models.tables import SourceHealth

        health_rows = session.query(SourceHealth).all()
        health_map = {h.source_name: h for h in health_rows}

    return _render(
        request,
        "pipeline.html",
        {
            "active": "pipeline",
            "sources": sources,
            "data_sources": data_sources,
            "mitre": mitre_status,
            "ransomwhere": rw_status,
            "deepdarkcti": dd_status,
            "articles": art_status,
            "health": health_map,
        },
    )


# "The senses can be deceived, the eyes fooled." — Sherlock Holmes, Elementary
@app.get("/search")
def search(request: Request, q: str = ""):
    victims = []
    groups = []
    attacks = []

    if q:
        with get_db() as session:
            victims = (
                session.query(Victim)
                .options(joinedload(Victim.group), joinedload(Victim.country))
                .filter(
                    Victim.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                    | Victim.domain.ilike(f"%{_escape_like(q)}%", escape="\\")
                )
                .limit(50)
                .all()
            )
            eq = _escape_like(q)
            groups = (
                session.query(Group)
                .filter(Group.group_name.ilike(f"%{eq}%", escape="\\"))
                .limit(20)
                .all()
            )
            attacks = (
                session.query(Cyberattack)
                .filter(
                    Cyberattack.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                    | Cyberattack.title.ilike(f"%{_escape_like(q)}%", escape="\\")
                )
                .limit(50)
                .all()
            )

    return _render(
        request,
        "search.html",
        {
            "active": "search",
            "q": q,
            "victims": victims,
            "groups": groups,
            "attacks": attacks,
        },
    )


@app.get("/btc")
def btc_search(request: Request, q: str = ""):
    results = []
    summary = {}
    if q:
        q_clean = q.strip()
        with get_db() as session:
            # Search by address (exact or partial)
            query = (
                session.query(
                    GroupBtcTransaction.address,
                    Group.group_name,
                    Group.id.label("group_id"),
                    func.count(GroupBtcTransaction.id).label("tx_count"),
                    func.sum(GroupBtcTransaction.amount_btc).label("total_btc"),
                    func.sum(GroupBtcTransaction.amount_usd).label("total_usd"),
                    func.min(GroupBtcTransaction.tx_date).label("first_seen"),
                    func.max(GroupBtcTransaction.tx_date).label("last_seen"),
                )
                .join(Group, GroupBtcTransaction.group_id == Group.id)
                .filter(
                    GroupBtcTransaction.address.ilike(f"%{_escape_like(q_clean)}%", escape="\\")
                )
                .group_by(GroupBtcTransaction.address, Group.group_name, Group.id)
                .order_by(func.sum(GroupBtcTransaction.amount_usd).desc())
                .limit(50)
            )
            results = [
                {
                    "address": r.address,
                    "group_name": r.group_name,
                    "group_id": r.group_id,
                    "tx_count": r.tx_count,
                    "total_btc": float(r.total_btc or 0),
                    "total_usd": float(r.total_usd or 0),
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                }
                for r in query.all()
            ]
            if results:
                summary = {
                    "addresses": len(results),
                    "total_usd": sum(r["total_usd"] for r in results),
                    "total_btc": sum(r["total_btc"] for r in results),
                    "total_txs": sum(r["tx_count"] for r in results),
                }

    # Top addresses for empty search landing
    top_addresses = []
    if not q:
        with get_db() as session:
            top_q = (
                session.query(
                    GroupBtcTransaction.address,
                    Group.group_name,
                    Group.id.label("group_id"),
                    func.count(GroupBtcTransaction.id).label("tx_count"),
                    func.sum(GroupBtcTransaction.amount_usd).label("total_usd"),
                )
                .join(Group, GroupBtcTransaction.group_id == Group.id)
                .group_by(GroupBtcTransaction.address, Group.group_name, Group.id)
                .order_by(func.sum(GroupBtcTransaction.amount_usd).desc())
                .limit(20)
            )
            top_addresses = [
                {
                    "address": r.address,
                    "group_name": r.group_name,
                    "group_id": r.group_id,
                    "tx_count": r.tx_count,
                    "total_usd": float(r.total_usd or 0),
                }
                for r in top_q.all()
            ]

    return _render(
        request,
        "btc_search.html",
        {
            "active": "btc",
            "q": q,
            "results": results,
            "summary": summary,
            "top_addresses": top_addresses,
        },
    )


# "Emotional context, Watson, is a distraction." — Sherlock Holmes, Elementary
@app.get("/watchlist")
def watchlist_page(request: Request):
    with get_db() as session:
        targets = session.query(Watchlist).order_by(Watchlist.created_at.desc()).all()
        unread = session.query(Alert).filter(Alert.seen.is_(False)).count()
        alerts = (
            session.query(Alert)
            .options(joinedload(Alert.watchlist), joinedload(Alert.victim))
            .order_by(Alert.created_at.desc())
            .limit(50)
            .all()
        )
    return _render(
        request,
        "watchlist.html",
        {
            "active": "watchlist",
            "targets": targets,
            "alerts": alerts,
            "unread": unread,
            "triage": _triage_alerts(alerts),
        },
    )


@app.post("/watchlist/add")
def watchlist_add(
    name: str = Form(...),
    domain: str = Form(""),
    keywords: str = Form(""),
    csrf_token: str = Form(""),
):
    if not _validate_csrf_token(csrf_token):
        return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
    with get_db() as session:
        entry = Watchlist(name=name, domain=domain or None, keywords=keywords or None)
        session.add(entry)
        session.commit()
    return RedirectResponse("/watchlist", status_code=303)


@app.post("/watchlist/{wid}/delete")
def watchlist_delete(wid: int, csrf_token: str = Form("")):
    if not _validate_csrf_token(csrf_token):
        return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
    with get_db() as session:
        session.query(Watchlist).filter(Watchlist.id == wid).delete(synchronize_session="fetch")
        session.commit()
    return RedirectResponse("/watchlist", status_code=303)


@app.post("/api/v1/alerts/{alert_id}/actioned", dependencies=[Depends(_require_csrf_header)])
def api_mark_alert_actioned(alert_id: int):
    """Record that an alert led to a decision — or take that back.

    The SANS 2026 survey's central finding is that 91% of CISOs call CTI
    valuable while only 26% say it changes a decision. That gap is unmeasurable
    unless something records the difference between "seen" and "acted on", and
    nothing here did. Toggling, not one-way: a mistaken click must be
    reversible or the number stops meaning anything.
    """
    with get_db() as session:
        alert = session.query(Alert).filter_by(id=alert_id).first()
        if alert is None:
            return JSONResponse({"error": "Unknown alert"}, status_code=404)
        alert.actioned_at = None if alert.actioned_at else datetime.now(UTC)
        if alert.actioned_at:
            alert.seen = True  # acting on something you have not seen is not a state
        session.commit()
        return {"id": alert_id, "actioned": alert.actioned_at is not None}


@app.post("/alerts/mark-read")
def alerts_mark_read(csrf_token: str = Form("")):
    if not _validate_csrf_token(csrf_token):
        return JSONResponse({"error": "Invalid CSRF token"}, status_code=403)
    with get_db() as session:
        session.query(Alert).filter(Alert.seen.is_(False)).update(
            {"seen": True}, synchronize_session="fetch"
        )
        session.commit()
    return RedirectResponse("/watchlist", status_code=303)


# Repo root from src/pestilentia/web/app.py — the same relative position inside
# the container image, where the Dockerfile copies CHANGELOG.md next to src/.
CHANGELOG_PATH = Path(__file__).resolve().parent.parent.parent.parent / "CHANGELOG.md"
FAQ_PATH = CHANGELOG_PATH.parent / "docs" / "FAQ.md"


def _render_changelog() -> str:
    """Render CHANGELOG.md to HTML, or an explanatory note when it is absent.

    Returning an empty string here used to paint a blank panel that looked like
    a product with no history, rather than a deployment missing a file.
    """
    import markdown as _md

    try:
        source = CHANGELOG_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            '<p class="changelog-missing">The changelog is not available in this '
            "deployment. It ships as <code>CHANGELOG.md</code> at the repository "
            "root; the release history is also on the project repository.</p>"
        )
    return _md.markdown(source, extensions=["tables", "fenced_code"])


@app.get("/guide")
def guide(request: Request):
    # Full 1:1 translation (2026-08-11): guide_en.html for the English UI,
    # the original Italian guide for lang=it.
    name = "guide.html" if request.cookies.get(_LANG_COOKIE, "") == "it" else "guide_en.html"
    return _render(request, name, {"active": "guide", "changelog_html": _render_changelog()})


@app.get("/changelog")
def changelog(request: Request):
    # The curated Italian release notes live in changelog.html; for the
    # English UI the canonical CHANGELOG.md is rendered instead.
    if request.cookies.get(_LANG_COOKIE, "") == "it":
        return _render(request, "changelog.html", {"active": "changelog"})
    return _render(
        request,
        "changelog_en.html",
        {"active": "changelog", "changelog_html": _render_changelog()},
    )


# ---------------------------------------------------------------------------
# Avatar endpoint (pixel-art mugshot)
# ---------------------------------------------------------------------------


@app.get("/avatar/{name}")
def avatar(name: str, size: int = Query(default=200, ge=16, le=512)):
    img = generate_mugshot(name, size=size)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# ---------------------------------------------------------------------------
# REST API v1
# ---------------------------------------------------------------------------


@app.get("/api/v1/stats")
def api_stats():
    with get_db() as session:
        return {
            "victims": session.query(Victim).count(),
            "groups": session.query(Group).count(),
            "cyberattacks": session.query(Cyberattack).count(),
            "countries": session.query(Country).count(),
            "sources": _count_sources(session),
        }


# MITRE's canonical enterprise kill-chain order. Alphabetical would scramble
# the narrative an analyst reads left to right.
ATTACK_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@app.get("/attack")
def attack_matrix(request: Request, group_id: int | None = None):
    """ATT&CK coverage: tactics as columns, techniques as cells.

    Magnitude on a grid, so the colour job is sequential — one hue, more-is-
    darker. Cell value is the number of distinct adversaries seen using the
    technique (or, when scoped to one group, simply whether it uses it).
    """
    with get_db() as session:
        query = session.query(
            GroupTTP.tactic_name,
            GroupTTP.technique_id,
            GroupTTP.technique_name,
            func.count(func.distinct(GroupTTP.group_id)).label("groups"),
        )
        scoped_group = None
        if group_id is not None:
            scoped_group = session.query(Group).filter_by(id=group_id).first()
            if scoped_group is None:
                raise HTTPException(status_code=404, detail="Unknown group")
            query = query.filter(GroupTTP.group_id == group_id)
        rows = query.group_by(
            GroupTTP.tactic_name, GroupTTP.technique_id, GroupTTP.technique_name
        ).all()

        total_groups = session.query(func.count(func.distinct(GroupTTP.group_id))).scalar() or 0

    by_tactic: dict[str, list[dict]] = {}
    for tactic, tid, tname, groups in rows:
        by_tactic.setdefault(tactic, []).append({"id": tid, "name": tname, "groups": groups})
    for techniques in by_tactic.values():
        techniques.sort(key=lambda t: (-t["groups"], t["id"]))

    peak = max((t["groups"] for ts in by_tactic.values() for t in ts), default=0)
    # Known tactics first in kill-chain order, then anything the feed invents.
    ordered = [t for t in ATTACK_TACTIC_ORDER if t in by_tactic]
    ordered += sorted(t for t in by_tactic if t not in ATTACK_TACTIC_ORDER)

    return _render(
        request,
        "attack.html",
        {
            "active": "attack",
            "tactics": [(t, by_tactic[t]) for t in ordered],
            "peak": peak,
            "total_groups": total_groups,
            "scoped_group": scoped_group,
            "technique_count": len(rows),
        },
    )


@app.get("/ai/articles")
def articles_list(
    request: Request,
    page: int = Query(default=1, ge=1),
    q: str = "",
    source: str = "",
    tlp: str = "",
    pir_only: bool = False,
):
    """Read-only view of the ingested article corpus (Phase 2 success criterion 4).

    No LLM output here — these rows are what the fetcher stored, nothing more.
    """
    from pestilentia.models.tables import Article, ArticleSource

    with get_db() as session:
        query = session.query(Article).options(joinedload(Article.source))
        if q:
            query = query.filter(Article.title.ilike(f"%{_escape_like(q)}%", escape="\\"))
        if source:
            query = query.join(ArticleSource).filter(ArticleSource.name == source)
        if tlp:
            query = query.filter(Article.tlp == tlp)
        query = query.order_by(Article.published_at.desc().nullslast(), Article.fetched_at.desc())
        articles, total, pages = _paginate(query, page)

        sources = [
            name for (name,) in session.query(ArticleSource.name).order_by(ArticleSource.name).all()
        ]
        tlps = [
            t for (t,) in session.query(Article.tlp).distinct().order_by(Article.tlp).all() if t
        ]
        full_text_count = session.query(Article).filter(Article.truncated.is_(False)).count()

        pir_terms = _pir_terms(session)
        hits = {a.id: _pir_hits(a, pir_terms) for a in articles}
        if pir_only and pir_terms:
            articles = [a for a in articles if hits[a.id]]

    return _render(
        request,
        "articles.html",
        {
            "active": "articles",
            "articles": articles,
            "total": total,
            "page": page,
            "pages": pages,
            "q": q,
            "source": source,
            "tlp": tlp,
            "sources": sources,
            "tlps": tlps,
            "full_text_count": full_text_count,
            "pir_terms": pir_terms,
            "pir_hits": hits,
            "pir_only": pir_only,
        },
    )


@app.get("/ai/campaigns")
def campaigns_view(request: Request, limit: int = Query(default=500, ge=10, le=2000)):
    """Articles grouped into campaigns, computed on demand.

    Nothing is persisted: `articles` has no campaign column and adding one is
    an L2 migration. Recomputing keeps the threshold tunable while the value is
    still being proven, and at this corpus size it is cheap.
    """
    from pestilentia.ai.sources.clustering import (
        DEFAULT_THRESHOLD,
        EMBEDDING_THRESHOLD,
        cluster_articles,
    )
    from pestilentia.config import get_settings
    from pestilentia.models.tables import Article

    settings = get_settings()
    with get_db() as session:
        articles = (
            session.query(Article)
            .options(joinedload(Article.source))
            .order_by(Article.published_at.desc().nullslast(), Article.fetched_at.desc())
            .limit(limit)
            .all()
        )
        clusters, backend = cluster_articles(articles, backend=settings.cluster_backend)

    multi = [c for c in clusters if len(c) > 1]
    return _render(
        request,
        "campaigns.html",
        {
            "active": "campaigns",
            "clusters": multi,
            "total_articles": len(articles),
            "singletons": len(clusters) - len(multi),
            "backend": backend,
            "threshold": EMBEDDING_THRESHOLD if backend == "embedding" else DEFAULT_THRESHOLD,
        },
    )


@app.get("/api/v1/groups/{group_id}/stix")
def api_group_stix(group_id: int):
    """STIX 2.1 bundle for one adversary — pushable into MISP or OpenCTI.

    Object ids are deterministic, so re-exporting updates the consumer's
    objects instead of accumulating duplicates.
    """
    from pestilentia.ai.reports.stix import group_to_bundle

    with get_db() as session:
        group = (
            session.query(Group)
            .options(joinedload(Group.ttps), joinedload(Group.tools))
            .filter_by(id=group_id)
            .first()
        )
        if group is None:
            raise HTTPException(status_code=404, detail="Unknown group")
        bundle = group_to_bundle(group)

    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{group.group_name}-stix.json"'},
    )


@app.get("/api/v1/stats/timeline")
def api_stats_timeline(months: int = Query(default=24, ge=1, le=120)):
    """Victims per month, aggregated in SQL. Zero-filled, oldest first."""
    with get_db() as session:
        return {"months": months, "series": _victim_timeline(session, months)}


@app.get("/api/v1/victims")
def api_victims(
    page: int = Query(default=1, ge=1),
    q: str = "",
    group: str = "",
    country: str = "",
):
    with get_db() as session:
        query = session.query(Victim).options(joinedload(Victim.group), joinedload(Victim.country))
        if q:
            query = query.filter(
                Victim.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                | Victim.domain.ilike(f"%{_escape_like(q)}%", escape="\\")
            )
        if group:
            query = query.join(Group).filter(Group.group_name == group)
        if country:
            query = query.join(Country).filter(Country.iso_code == country)

        query = query.order_by(Victim.attackdate.desc().nullslast())
        items, total, pages = _paginate(query, page)

    return {
        "total": total,
        "page": page,
        "pages": pages,
        "items": [_victim_serialize(v) for v in items],
    }


@app.get("/api/v1/victims/{victim_id}")
def api_victim_detail(victim_id: int):
    with get_db() as session:
        v = (
            session.query(Victim)
            .options(joinedload(Victim.group), joinedload(Victim.country))
            .filter(Victim.id == victim_id)
            .first()
        )
        if not v:
            return JSONResponse({"error": "not found"}, status_code=404)
    return _victim_serialize(v)


@app.get("/api/v1/groups")
def api_groups():
    with get_db() as session:
        rows = (
            session.query(Group, func.count(Victim.id).label("cnt"))
            .outerjoin(Victim, Victim.group_id == Group.id)
            .group_by(Group.id)
            .order_by(func.count(Victim.id).desc())
            .all()
        )
    return [_group_serialize(g, cnt) for g, cnt in rows]


@app.get("/api/v1/groups/{group_id}")
def api_group_detail(group_id: int):
    with get_db() as session:
        g = session.query(Group).filter(Group.id == group_id).first()
        if not g:
            return JSONResponse({"error": "not found"}, status_code=404)
        cnt = session.query(Victim).filter(Victim.group_id == group_id).count()
    return _group_serialize(g, cnt)


@app.get("/api/v1/groups/{name}/avatar")
def api_group_avatar(name: str, size: int = Query(default=200, ge=16, le=512)):
    img = generate_mugshot(name, size=size)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/v1/cyberattacks")
def api_cyberattacks(page: int = Query(default=1, ge=1), q: str = "", country: str = ""):
    with get_db() as session:
        query = session.query(Cyberattack)
        if q:
            query = query.filter(
                Cyberattack.victim_name.ilike(f"%{_escape_like(q)}%", escape="\\")
                | Cyberattack.title.ilike(f"%{_escape_like(q)}%", escape="\\")
            )
        if country:
            query = query.filter(Cyberattack.country == country)

        query = query.order_by(Cyberattack.attack_date.desc().nullslast())
        items, total, pages = _paginate(query, page)

    return {
        "total": total,
        "page": page,
        "pages": pages,
        "items": [_attack_serialize(a) for a in items],
    }


@app.get("/api/v1/countries")
def api_countries():
    with get_db() as session:
        rows = (
            session.query(Country.iso_code, func.count(Victim.id))
            .join(Victim, Victim.country_id == Country.id)
            .group_by(Country.iso_code)
            .order_by(func.count(Victim.id).desc())
            .all()
        )
    return [{"code": c, "count": n} for c, n in rows]


# "The moment I let myself be affected by someone, I lose my edge." — Sherlock
def _check_watchlist(session: Session) -> list[int]:
    targets = session.query(Watchlist).filter(Watchlist.active.is_(True)).all()
    if not targets:
        return []
    existing_pairs = set(session.query(Alert.watchlist_id, Alert.victim_id).all())
    new_alert_ids: list[int] = []

    from sqlalchemy import or_

    for t in targets:
        conditions = []
        conditions.append(Victim.victim_name.ilike(f"%{_escape_like(t.name)}%", escape="\\"))
        if t.domain:
            conditions.append(Victim.domain.ilike(f"%{_escape_like(t.domain)}%", escape="\\"))
        if t.keywords:
            for kw in t.keywords.split(","):
                kw = kw.strip()
                if kw:
                    ekw = _escape_like(kw)
                    conditions.append(Victim.victim_name.ilike(f"%{ekw}%", escape="\\"))

        # Only fetch id + domain (not full ORM objects) to reduce memory
        matches = session.query(Victim.id, Victim.domain).filter(or_(*conditions)).all()
        for vid, vdomain in matches:
            if (t.id, vid) not in existing_pairs:
                match_field = "name"
                if t.domain and t.domain.lower() in (vdomain or "").lower():
                    match_field = "domain"
                alert = Alert(watchlist_id=t.id, victim_id=vid, match_field=match_field)
                session.add(alert)
                session.flush()
                new_alert_ids.append(alert.id)
                existing_pairs.add((t.id, vid))

    from pestilentia.config import get_settings

    threshold = get_settings().fuzzy_threshold
    fuzzy_alerts = fuzzy_match_watchlist(session, existing_pairs, threshold=threshold)
    for a in fuzzy_alerts:
        new_alert_ids.append(a.id)

    session.commit()
    return new_alert_ids


@app.post(
    "/api/v1/source/{source_name}/toggle",
    dependencies=[Depends(_require_csrf_header), REQUIRE_ADMIN],
)
def api_toggle_source(source_name: str):
    with get_db() as session:
        ds = session.query(DataSource).filter_by(source_name=source_name).first()
        if not ds:
            return JSONResponse({"error": "Source not found"}, status_code=404)
        ds.enabled = not ds.enabled
        session.commit()
        return {"source": source_name, "enabled": ds.enabled}


@app.post(
    "/api/v1/mitre/toggle",
    dependencies=[Depends(_require_csrf_header), REQUIRE_ADMIN],
)
def api_toggle_mitre():
    with get_db() as session:
        row = session.query(InfoUpdate).filter_by(category="mitre_enabled").first()
        if not row:
            session.add(InfoUpdate(category="mitre_enabled", number=0))
            session.commit()
            return {"source": "mitre", "enabled": False}
        row.number = 0 if row.number else 1
        session.commit()
        return {"source": "mitre", "enabled": bool(row.number)}


def _is_mitre_enabled(session: Session) -> bool:
    row = session.query(InfoUpdate).filter_by(category="mitre_enabled").first()
    if not row:
        return True  # enabled by default
    return bool(row.number)


def _is_enrichment_enabled(session: Session, name: str) -> bool:
    row = session.query(InfoUpdate).filter_by(category=f"{name}_enabled").first()
    if not row:
        return True  # enabled by default
    return bool(row.number)


@app.post(
    "/api/v1/enrichment/{name}/toggle",
    dependencies=[Depends(_require_csrf_header), REQUIRE_ADMIN],
)
def api_toggle_enrichment(name: str):
    allowed = {"ransomwhere", "deepdarkcti", "articles"}
    if name not in allowed:
        return JSONResponse({"error": f"Unknown enrichment: {name}"}, status_code=404)
    with get_db() as session:
        cat = f"{name}_enabled"
        row = session.query(InfoUpdate).filter_by(category=cat).first()
        if not row:
            session.add(InfoUpdate(category=cat, number=0))
            session.commit()
            return {"source": name, "enabled": False}
        row.number = 0 if row.number else 1
        session.commit()
        return {"source": name, "enabled": bool(row.number)}


@app.post(
    "/api/v1/refresh",
    dependencies=[Depends(_require_csrf_header), REQUIRE_ANALYST],
)
async def api_refresh():
    results = []
    mitre_stats: dict = {"skipped": True, "reason": "disabled"}
    rw_stats: dict = {"skipped": True, "reason": "disabled"}
    dd_stats: dict = {"skipped": True, "reason": "disabled"}
    with get_db() as session:
        for name, cls in SOURCES.items():
            # Check if source is enabled
            ds = session.query(DataSource).filter_by(source_name=name).first()
            if ds and not ds.enabled:
                results.append({"source": name, "skipped": True, "reason": "disabled"})
                continue

            source = cls()
            try:
                try:
                    r = await ingest_source(session, source)
                    session.commit()
                except Exception as exc:
                    session.rollback()
                    logger.exception("refresh ingest failed for %s", name)
                    results.append({"source": name, "error": str(exc)})
                    continue
                now = datetime.now(UTC)
                existing = (
                    session.query(InfoUpdate).filter_by(category=f"last_refresh:{name}").first()
                )
                if existing:
                    existing.last_update_json = now
                else:
                    session.add(InfoUpdate(category=f"last_refresh:{name}", last_update_json=now))
                session.commit()
                # Run watchlist matching in thread to avoid blocking event loop
                new_ids = await asyncio.to_thread(_check_watchlist, session)
                if new_ids:
                    await dispatch_alerts(session, new_ids)
                results.append(
                    {
                        "source": r.source,
                        "victims_added": r.victims_added,
                        "groups_added": r.groups_added,
                        "cyberattacks_added": r.cyberattacks_added,
                        "alerts_dispatched": len(new_ids),
                    }
                )
            finally:
                await source.close()

        # MITRE ATT&CK enrichment
        if _is_mitre_enabled(session):
            try:
                from pestilentia.clients.mitre_attack import enrich_groups_incremental

                mitre_stats = await asyncio.to_thread(
                    enrich_groups_incremental, session, force=True
                )
            except Exception as exc:
                session.rollback()
                logger.exception("MITRE enrichment failed during /api/v1/refresh")
                mitre_stats = {"error": str(exc)}

        # Ransomwhere BTC enrichment
        if _is_enrichment_enabled(session, "ransomwhere"):
            try:
                from pestilentia.clients.ransomwhere import enrich_ransomwhere

                rw_stats = await asyncio.to_thread(enrich_ransomwhere, session)
            except Exception as exc:
                session.rollback()
                logger.exception("Ransomwhere enrichment failed during /api/v1/refresh")
                rw_stats = {"error": str(exc)}

        # deepdarkCTI operational enrichment
        if _is_enrichment_enabled(session, "deepdarkcti"):
            try:
                from pestilentia.clients.deepdarkcti import enrich_deepdarkcti

                dd_stats = await asyncio.to_thread(enrich_deepdarkcti, session)
            except Exception as exc:
                session.rollback()
                logger.exception("deepdarkCTI enrichment failed during /api/v1/refresh")
                dd_stats = {"error": str(exc)}

    return {
        "status": "ok",
        "results": results,
        "mitre_enrichment": mitre_stats,
        "ransomwhere_enrichment": rw_stats,
        "deepdarkcti_enrichment": dd_stats,
    }


@app.get("/api/v1/pipeline/status")
def api_pipeline_status():
    with get_db() as session:
        data_sources = session.query(DataSource).all()
        victim_counts = dict(
            session.query(Victim.source_id, func.count(Victim.id)).group_by(Victim.source_id).all()
        )
        group_counts = dict(
            session.query(Group.source_id, func.count(Group.id)).group_by(Group.source_id).all()
        )
        attack_counts = dict(
            session.query(Cyberattack.source_id, func.count(Cyberattack.id))
            .group_by(Cyberattack.source_id)
            .all()
        )
        backfill_cats = {
            r[0]
            for r in session.query(InfoUpdate.category)
            .filter(InfoUpdate.category.like(f"{BACKFILL_CATEGORY}:%"))
            .all()
        }
        result = []
        for ds in data_sources:
            result.append(
                {
                    "source_name": ds.source_name,
                    "backfill_done": f"{BACKFILL_CATEGORY}:{ds.source_name}" in backfill_cats,
                    "victims": victim_counts.get(ds.id, 0),
                    "groups": group_counts.get(ds.id, 0),
                    "attacks": attack_counts.get(ds.id, 0),
                }
            )
    return result


@app.post("/api/v1/health", dependencies=[Depends(_require_csrf_header)])
async def api_health_check():
    from pestilentia.pipeline.health import run_health_checks

    with get_db() as session:
        results = await asyncio.to_thread(run_health_checks, session)
    return {"status": "ok", "checks": results}


@app.get("/api/v1/groups/{group_id}/geodata")
def api_group_geodata(group_id: int, period: str = "all"):
    days_map = {"7d": 7, "1m": 30, "1y": 365}
    with get_db() as session:
        query = (
            session.query(Country.iso_code, func.count(Victim.id))
            .join(Victim, Victim.country_id == Country.id)
            .filter(Victim.group_id == group_id)
        )
        if period in days_map:
            cutoff = datetime.now(UTC) - timedelta(days=days_map[period])
            query = query.filter(Victim.attackdate >= cutoff)
        return [{"code": c, "count": n} for c, n in query.group_by(Country.iso_code).all()]
