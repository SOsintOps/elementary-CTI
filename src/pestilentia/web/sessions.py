# Signed session tokens and the login backoff for the v0.7 auth plan
# (step 3). Pure helpers — no FastAPI, no models: app.py wires them.
#
# Token format: "uid.sid.iat.ts.sig" — all fields plain ints/hex, signed
# with HMAC-SHA256 over the secret. Stateless like the CSRF tokens (same
# accepted model): a leaked token is valid until expiry; revocation happens
# at the DB layer via User.disabled, re-checked on every request.
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass

SESSION_COOKIE = "pest_session"
# Absolute lifetime: a session dies 12 h after login no matter what.
SESSION_ABSOLUTE_SECONDS = 12 * 3600
# Idle lifetime: 2 h without a request ends the session.
SESSION_IDLE_SECONDS = 2 * 3600
# Sliding refresh: re-issue the cookie only when the recorded activity
# timestamp is older than this, so not every response carries Set-Cookie.
SESSION_REFRESH_AFTER_SECONDS = 300


@dataclass(frozen=True)
class SessionData:
    uid: int
    sid: str  # random per login — rotation defeats fixation
    iat: int  # login time (absolute expiry anchor)
    ts: int  # last-activity time (idle expiry anchor)


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), f"session:{payload}".encode(), hashlib.sha256).hexdigest()


def issue_session(secret: str, uid: int, *, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    payload = f"{uid}.{secrets.token_hex(16)}.{now}.{now}"
    return f"{payload}.{_sign(secret, payload)}"


def refresh_session(secret: str, data: SessionData, *, now: int | None = None) -> str:
    """Same sid and iat, new activity timestamp — the sliding part."""
    now = int(time.time()) if now is None else now
    payload = f"{data.uid}.{data.sid}.{data.iat}.{now}"
    return f"{payload}.{_sign(secret, payload)}"


def verify_session(secret: str, token: str | None, *, now: int | None = None) -> SessionData | None:
    """Signature + both expiries. None on any failure — never raises."""
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 5:
        return None
    uid_s, sid, iat_s, ts_s, sig = parts
    payload = f"{uid_s}.{sid}.{iat_s}.{ts_s}"
    if not hmac.compare_digest(sig, _sign(secret, payload)):
        return None
    try:
        uid, iat, ts = int(uid_s), int(iat_s), int(ts_s)
    except ValueError:
        return None
    now = int(time.time()) if now is None else now
    if now - iat > SESSION_ABSOLUTE_SECONDS or now - ts > SESSION_IDLE_SECONDS:
        return None
    if iat > now + 60 or ts > now + 60:  # clock-skew guard on forged-looking future stamps
        return None
    return SessionData(uid=uid, sid=sid, iat=iat, ts=ts)


# --- Login backoff -----------------------------------------------------------
# In-process, per (username, client-ip): 5 free attempts, then a lockout that
# doubles from 30 s up to 15 min. Single-process is accepted (mirrors the
# in-process throttling pattern used elsewhere); the Caddy layer adds a
# request-rate ceiling on top at step 10.
_FREE_ATTEMPTS = 5
_BASE_LOCK_SECONDS = 30
_MAX_LOCK_SECONDS = 900


class LoginBackoff:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[tuple[str, str], tuple[int, float]] = {}  # key -> (fails, locked_until)

    def _key(self, username: str, ip: str) -> tuple[str, str]:
        return (username.strip().lower(), ip)

    def locked_for(self, username: str, ip: str, *, now: float | None = None) -> int:
        """Seconds of lockout remaining; 0 when the attempt may proceed."""
        now = time.time() if now is None else now
        with self._lock:
            _, until = self._state.get(self._key(username, ip), (0, 0.0))
        return max(0, int(until - now) + (1 if until > now else 0))

    def record_failure(self, username: str, ip: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        key = self._key(username, ip)
        with self._lock:
            fails, until = self._state.get(key, (0, 0.0))
            fails += 1
            if fails >= _FREE_ATTEMPTS:
                lock = min(_BASE_LOCK_SECONDS * (2 ** (fails - _FREE_ATTEMPTS)), _MAX_LOCK_SECONDS)
                until = now + lock
            self._state[key] = (fails, until)

    def record_success(self, username: str, ip: str) -> None:
        with self._lock:
            self._state.pop(self._key(username, ip), None)
