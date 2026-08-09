# "You see but you do not observe." — Sherlock Holmes, Elementary
from __future__ import annotations

import logging

from sqlalchemy import func
from sqlalchemy.orm import Session
from thefuzz import fuzz

from pestilentia.models import Alert, InfoUpdate, Victim, Watchlist

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 85

# High-water marks for the incremental fuzzy scan (HI-09), stored in
# info_updates.number: highest victim id already scanned by every target
# that existed at the time, and highest watchlist id ever fully scanned.
VICTIM_HWM_CATEGORY = "watchlist_victim_hwm"
TARGET_HWM_CATEGORY = "watchlist_target_hwm"


def _normalize(s: str) -> str:
    return s.lower().strip()


def _get_hwm(session: Session, category: str) -> int:
    row = session.query(InfoUpdate).filter_by(category=category).first()
    return row.number or 0 if row else 0


def _set_hwm(session: Session, category: str, value: int) -> None:
    row = session.query(InfoUpdate).filter_by(category=category).first()
    if row:
        row.number = value
    else:
        session.add(InfoUpdate(category=category, number=value))


def fuzzy_match_watchlist(
    session: Session,
    existing_pairs: set[tuple[int, int]],
    threshold: int = DEFAULT_THRESHOLD,
) -> list[Alert]:
    """Fuzzy-match active watchlist targets against victims, incrementally.

    Targets already seen by a previous scan are only matched against
    victims added since (id above the stored high-water mark); a brand-new
    target gets one full scan over all victims. Keeps the per-refresh cost
    proportional to the new victims instead of O(targets x all victims).

    Note: a target deactivated across a scan and later re-activated may
    miss victims ingested while it was inactive (HI-09 trade-off).
    """
    targets = session.query(Watchlist).filter(Watchlist.active.is_(True)).all()
    if not targets:
        return []

    victim_hwm = _get_hwm(session, VICTIM_HWM_CATEGORY)
    target_hwm = _get_hwm(session, TARGET_HWM_CATEGORY)
    seen_targets = [t for t in targets if t.id <= target_hwm]
    new_targets = [t for t in targets if t.id > target_hwm]

    new_alerts: list[Alert] = []
    if seen_targets:
        new_victims = session.query(Victim).filter(Victim.id > victim_hwm).all()
        if new_victims:
            new_alerts += _scan(session, seen_targets, new_victims, existing_pairs, threshold)
    if new_targets:
        all_victims = session.query(Victim).all()
        new_alerts += _scan(session, new_targets, all_victims, existing_pairs, threshold)

    max_victim_id = session.query(func.max(Victim.id)).scalar() or 0
    _set_hwm(session, VICTIM_HWM_CATEGORY, max_victim_id)
    _set_hwm(session, TARGET_HWM_CATEGORY, max(t.id for t in targets))

    if new_alerts:
        logger.info(
            "Fuzzy matching found %d new alerts (threshold=%d)",
            len(new_alerts),
            threshold,
        )

    return new_alerts


def _scan(
    session: Session,
    targets: list[Watchlist],
    victims: list[Victim],
    existing_pairs: set[tuple[int, int]],
    threshold: int,
) -> list[Alert]:
    new_alerts: list[Alert] = []
    for t in targets:
        t_name = _normalize(t.name)
        t_domain = _normalize(t.domain) if t.domain else None
        t_keywords = [_normalize(kw) for kw in (t.keywords or "").split(",") if kw.strip()]

        for v in victims:
            if (t.id, v.id) in existing_pairs:
                continue

            match_field = _check_victim(t_name, t_domain, t_keywords, v, threshold)
            if match_field:
                alert = Alert(watchlist_id=t.id, victim_id=v.id, match_field=match_field)
                session.add(alert)
                session.flush()
                new_alerts.append(alert)
                existing_pairs.add((t.id, v.id))

    return new_alerts


def _check_victim(
    t_name: str,
    t_domain: str | None,
    t_keywords: list[str],
    victim: Victim,
    threshold: int,
) -> str | None:
    v_name = _normalize(victim.victim_name or "")
    v_domain = _normalize(victim.domain or "")

    if t_domain and v_domain and len(t_domain) >= 3 and len(v_domain) >= 3:
        score = fuzz.ratio(t_domain, v_domain)
        if score >= threshold:
            return f"fuzzy_domain:{score}"

    if v_name and t_name and len(v_name) >= 3 and len(t_name) >= 3:
        score = fuzz.token_sort_ratio(t_name, v_name)
        if score >= threshold:
            return f"fuzzy_name:{score}"

        for kw in t_keywords:
            if len(kw) < 3:
                continue
            score = fuzz.partial_ratio(kw, v_name)
            if score >= threshold:
                return f"fuzzy_keyword:{score}"

    return None
