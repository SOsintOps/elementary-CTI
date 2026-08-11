# User-activity recording and retention (v0.7 auth plan, step 3; OWASP A09).
# Root-level on purpose: both the web layer (writes) and the pipeline
# scheduler (purge) import it, so it may depend on models only.
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from pestilentia.models import UserActivity

logger = logging.getLogger(__name__)

# Event kinds — keep in sync with the plan and the Activity admin tab.
KIND_LOGIN_OK = "login_ok"
KIND_LOGIN_FAIL = "login_fail"
KIND_LOCKOUT = "lockout"
KIND_LOGOUT = "logout"
KIND_ACCESS_DENIED = "access_denied"
KIND_PAGE_VIEW = "page_view"
KIND_API_CALL = "api_call"


def record_activity(
    session: Session,
    kind: str,
    *,
    actor_id: int | None = None,
    actor_name: str | None = None,
    method: str | None = None,
    route: str | None = None,
    target: str | None = None,
    status: int | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Append one activity row. Truncates free-text fields; commits."""
    session.add(
        UserActivity(
            kind=kind[:24],
            actor_id=actor_id,
            actor_name=actor_name[:64] if actor_name else None,
            method=method[:8] if method else None,
            route=route[:256] if route else None,
            target=target[:256] if target else None,
            status=status,
            client_ip=client_ip[:64] if client_ip else None,
            user_agent=user_agent[:256] if user_agent else None,
        )
    )
    session.commit()


def purge_user_activity(session: Session, retention_days: int) -> int:
    """Delete rows older than the retention window. Returns rows removed."""
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    removed = (
        session.query(UserActivity)
        .filter(UserActivity.ts < cutoff)
        .delete(synchronize_session=False)
    )
    session.commit()
    if removed:
        logger.info("Purged %d user_activity rows older than %d days", removed, retention_days)
    return removed
