"""Source health monitor for Elementary CTI.

Periodically checks enrichment sources for availability, format integrity,
and data freshness. Stores results in source_health table and triggers
alerts when sources degrade.

Usage:
    python -m pestilentia.pipeline.health
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from pestilentia.clients.deepdarkcti import (
    DEEPDARK_FILES,
    parse_ransomware_table,
    parse_telegram_actors,
    parse_twitter_actors,
)
from pestilentia.clients.http import get_with_retry, head_with_retry
from pestilentia.models.tables import SourceHealth

log = logging.getLogger(__name__)

# Minimum expected row counts — if below these, format likely broken
_MIN_ROWS = {
    "deepdarkcti:ransomware_gang": 400,
    "deepdarkcti:telegram_threat_actors": 500,
    "deepdarkcti:twitter_threat_actors": 20,
    "ransomwhere": 5000,
    "mitre_attack": 100,
}

#: The off-device backup push, which reports its own outcome here after every
#: attempt (`scripts/push_db_backup.sh`).
BACKUP_PUSH_SOURCE = "db-backup-push"

#: How old the last successful off-device push may be before the platform says
#: so. The push runs daily, so two days tolerates one missed run and a clock
#: that drifted; four days is two consecutive silent failures, which is the
#: state that went unnoticed from the 12th to the 15th of August 2026.
_BACKUP_DEGRADED_AFTER_DAYS = 2
_BACKUP_DOWN_AFTER_DAYS = 4


def _upsert_health(session: Session, name: str, **kwargs) -> SourceHealth:
    row = session.query(SourceHealth).filter_by(source_name=name).first()
    if not row:
        row = SourceHealth(source_name=name)
        session.add(row)
    for k, v in kwargs.items():
        setattr(row, k, v)
    row.last_check = datetime.now(UTC)
    return row


def record_backup_push(
    session: Session,
    *,
    ok: bool,
    detail: str | None = None,
    dump_bytes: int | None = None,
) -> SourceHealth:
    """Record the outcome of one off-device backup push.

    Called by `scripts/push_db_backup.sh` after every attempt, success or
    failure, so the result survives in a place that outlives a reboot. The
    script already logs loudly, but on this host the *user* journal is not
    retained and a `oneshot` unit's failed state lives in memory, so between
    the 12th and the 15th of August 2026 three consecutive failures left no
    trace anywhere a person would look.
    """
    row = _upsert_health(
        session,
        BACKUP_PUSH_SOURCE,
        status="ok" if ok else "down",
        error_message=None if ok else (detail or "push failed"),
        row_count=dump_bytes,
    )
    if ok:
        row.last_ok = datetime.now(UTC)
    return row


def check_backup_push(session: Session) -> dict:
    """Judge the off-device backup by its own age, without waiting to be told.

    This is the half that `record_backup_push` cannot cover. A push that
    reports its failure is the easy case; the dangerous one is a push that
    never runs at all — a disabled timer, a machine that stayed off, a unit
    someone masked — because then nothing writes a row and nothing is wrong on
    the page. Reading `last_ok` and comparing it against the clock catches all
    three, and it catches them from inside the application, which is where a
    person is actually looking.

    Never invents an optimistic answer: a source that has never reported at all
    is `down` with that said in words, not `unknown`, because the question
    "when was the last off-device backup" has no reassuring default.
    """
    row = session.query(SourceHealth).filter_by(source_name=BACKUP_PUSH_SOURCE).first()
    now = datetime.now(UTC)

    if row is None or row.last_ok is None:
        _upsert_health(
            session,
            BACKUP_PUSH_SOURCE,
            status="down",
            error_message="no off-device backup has ever been recorded",
        )
        return {"source": BACKUP_PUSH_SOURCE, "status": "down", "age_days": None}

    last_ok = row.last_ok if row.last_ok.tzinfo else row.last_ok.replace(tzinfo=UTC)
    age_days = (now - last_ok).total_seconds() / 86400

    if age_days >= _BACKUP_DOWN_AFTER_DAYS:
        status = "down"
    elif age_days >= _BACKUP_DEGRADED_AFTER_DAYS:
        status = "degraded"
    else:
        status = "ok"

    # Only the ageing verdict is written here. `last_ok` and the push's own
    # error stay untouched: this function judges freshness, it does not claim
    # to know why the last attempt failed.
    row.status = status
    row.last_check = now
    if status != "ok":
        row.error_message = f"last successful off-device push was {age_days:.1f} days ago"
    return {"source": BACKUP_PUSH_SOURCE, "status": status, "age_days": round(age_days, 1)}


def check_deepdarkcti(session: Session) -> list[dict]:
    """Check all deepdarkCTI markdown files for availability and format."""
    results = []
    parsers = {
        "ransomware_gang": parse_ransomware_table,
        "telegram_threat_actors": parse_telegram_actors,
        "twitter_threat_actors": parse_twitter_actors,
    }

    for file_key, url in DEEPDARK_FILES.items():
        source_name = f"deepdarkcti:{file_key}"
        status_info = {"source": source_name}

        try:
            r = get_with_retry(url, timeout=15)
            status_info["http_status"] = r.status_code

            if r.status_code != 200:
                _upsert_health(
                    session,
                    source_name,
                    status="down",
                    http_status=r.status_code,
                    error_message=f"HTTP {r.status_code}",
                    format_valid=None,
                    row_count=None,
                )
                status_info["status"] = "down"
                log.warning("deepdarkCTI %s: HTTP %d", file_key, r.status_code)
                results.append(status_info)
                continue

            # Parse and validate format
            parser = parsers.get(file_key)
            if parser:
                rows = parser(r.text)
                row_count = len(rows)
                min_expected = _MIN_ROWS.get(source_name, 10)
                format_valid = row_count >= min_expected

                if format_valid:
                    status = "ok"
                    error_msg = None
                else:
                    status = "degraded"
                    error_msg = f"Only {row_count} rows (expected >= {min_expected})"
                    log.warning(
                        "deepdarkCTI %s: format degraded — %d rows (min %d)",
                        file_key,
                        row_count,
                        min_expected,
                    )

                health = _upsert_health(
                    session,
                    source_name,
                    status=status,
                    http_status=200,
                    row_count=row_count,
                    format_valid=format_valid,
                    error_message=error_msg,
                )
                if status == "ok":
                    health.last_ok = datetime.now(UTC)

                status_info.update(
                    {
                        "status": status,
                        "row_count": row_count,
                        "format_valid": format_valid,
                    }
                )

        except httpx.HTTPError as exc:
            _upsert_health(
                session,
                source_name,
                status="down",
                error_message=str(exc),
                format_valid=None,
                row_count=None,
            )
            status_info["status"] = "down"
            status_info["error"] = str(exc)
            log.error("deepdarkCTI %s unreachable: %s", file_key, exc)

        results.append(status_info)

    session.commit()
    return results


def check_ransomwhere(session: Session) -> dict:
    """Check Ransomwhere API availability."""
    source_name = "ransomwhere"
    try:
        with httpx.stream(
            "GET",
            "https://api.ransomwhe.re/export",
            timeout=15,
            follow_redirects=True,
        ) as r:
            if r.status_code == 200:
                health = _upsert_health(
                    session,
                    source_name,
                    status="ok",
                    http_status=200,
                    error_message=None,
                )
                health.last_ok = datetime.now(UTC)
                result = {"source": source_name, "status": "ok", "http_status": 200}
            else:
                _upsert_health(
                    session,
                    source_name,
                    status="down",
                    http_status=r.status_code,
                    error_message=f"HTTP {r.status_code}",
                )
                result = {"source": source_name, "status": "down", "http_status": r.status_code}
                log.warning("Ransomwhere: HTTP %d", r.status_code)
    except httpx.HTTPError as exc:
        _upsert_health(
            session,
            source_name,
            status="down",
            error_message=str(exc),
        )
        result = {"source": source_name, "status": "down", "error": str(exc)}
        log.error("Ransomwhere unreachable: %s", exc)

    session.commit()
    return result


def check_mitre(session: Session) -> dict:
    """Check MITRE STIX bundle availability."""
    source_name = "mitre_attack"
    url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
        "/master/enterprise-attack/enterprise-attack.json"
    )
    try:
        r = head_with_retry(url, timeout=15)
        if r.status_code == 200:
            health = _upsert_health(
                session,
                source_name,
                status="ok",
                http_status=200,
                error_message=None,
            )
            health.last_ok = datetime.now(UTC)
            result = {"source": source_name, "status": "ok", "http_status": 200}
        else:
            _upsert_health(
                session,
                source_name,
                status="down",
                http_status=r.status_code,
                error_message=f"HTTP {r.status_code}",
            )
            result = {"source": source_name, "status": "down", "http_status": r.status_code}
    except httpx.HTTPError as exc:
        _upsert_health(
            session,
            source_name,
            status="down",
            error_message=str(exc),
        )
        result = {"source": source_name, "status": "down", "error": str(exc)}

    session.commit()
    return result


def run_health_checks(session: Session) -> list[dict]:
    """Run all source health checks."""
    results = []
    results.extend(check_deepdarkcti(session))
    results.append(check_ransomwhere(session))
    results.append(check_mitre(session))
    # Reads the clock rather than the network: it asks how old the last
    # off-device backup is, which is the question nobody was asking.
    results.append(check_backup_push(session))
    log.info(
        "Health check complete: %s",
        {r["source"]: r["status"] for r in results},
    )
    return results


def _record_backup_push_cli(argv: list[str]) -> int:
    """`--record-backup-push ok|failed` for the backup script to call.

    Runs against the **configured** database rather than the tracked SQLite
    file, because the caller is the push script and its whole purpose is to say
    something about production. The script invokes this inside the web
    container, which already holds the production URL in its environment, so no
    credential is duplicated and the bare-`alembic`-migrates-the-wrong-database
    trap has no equivalent here.
    """
    import argparse

    from pestilentia.config import get_settings
    from pestilentia.models.base import get_session_factory

    parser = argparse.ArgumentParser(prog="pestilentia.pipeline.health")
    parser.add_argument("--record-backup-push", choices=("ok", "failed"), required=True)
    parser.add_argument("--detail", default="")
    parser.add_argument("--bytes", type=int, default=None)
    args = parser.parse_args(argv)

    factory = get_session_factory(get_settings().db_url)
    with factory() as session:
        record_backup_push(
            session,
            ok=args.record_backup_push == "ok",
            detail=args.detail or None,
            dump_bytes=args.bytes,
        )
        session.commit()
    return 0


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if "--record-backup-push" in sys.argv:
        raise SystemExit(_record_backup_push_cli(sys.argv[1:]))

    from pestilentia.models.base import get_session_factory

    factory = get_session_factory("sqlite:///elementaryctiDB.db")
    with factory() as session:
        results = run_health_checks(session)
        print("\n=== Source Health Check ===")
        for r in results:
            status = r["status"]
            icon = {"ok": "+", "degraded": "~", "down": "!"}[status]
            print(f"  [{icon}] {r['source']}: {status}")
            if "row_count" in r:
                print(f"      rows: {r['row_count']}")
            if "error" in r:
                print(f"      error: {r['error']}")
