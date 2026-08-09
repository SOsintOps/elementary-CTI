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


def _upsert_health(session: Session, name: str, **kwargs) -> SourceHealth:
    row = session.query(SourceHealth).filter_by(source_name=name).first()
    if not row:
        row = SourceHealth(source_name=name)
        session.add(row)
    for k, v in kwargs.items():
        setattr(row, k, v)
    row.last_check = datetime.now(UTC)
    return row


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
    log.info(
        "Health check complete: %s",
        {r["source"]: r["status"] for r in results},
    )
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
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
