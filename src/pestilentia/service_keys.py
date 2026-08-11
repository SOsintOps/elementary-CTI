# Service API-key resolution (v0.7 auth plan, step 9).
#
# One rule: the environment always wins over the database. An env var is the
# operator's explicit choice on the host; a DB row is a convenience set from
# the admin UI. Callers never read Settings key fields directly for these
# services — they ask resolve_service_key(), so the precedence lives in
# exactly one place. Values never travel to any client: the UI exposes
# presence only (see key_status()).
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from pestilentia.models import ServiceKey

# service -> (Settings attribute carrying the env override, or None to use
# the generic PEST_KEY_<SERVICE> variable)
KNOWN_SERVICES: dict[str, str | None] = {
    "nvidia": "ai_nvidia_api_key",
    "anthropic": None,
    "abuseipdb": None,
    "greynoise": None,
    "honeypot": None,
}


def _env_value(service: str) -> str:
    attr = KNOWN_SERVICES.get(service)
    if attr:
        from pestilentia.config import get_settings

        return getattr(get_settings(), attr, "") or ""
    return os.getenv(f"PEST_KEY_{service.upper()}", "") or ""


def resolve_service_key(session: Session, service: str) -> str:
    """The key a caller should use: env override first, then the DB row."""
    if service not in KNOWN_SERVICES:
        return ""
    env = _env_value(service)
    if env:
        return env
    row = session.query(ServiceKey).filter_by(service=service).first()
    return row.key_value if row else ""


def key_status(session: Session, service: str) -> dict:
    """Presence metadata for the admin UI. Never includes the value."""
    row = session.query(ServiceKey).filter_by(service=service).first()
    return {
        "service": service,
        "env_override": bool(_env_value(service)),
        "stored": row is not None,
        "updated_by": row.updated_by_name if row else None,
        "updated_at": row.updated_at if row else None,
    }
