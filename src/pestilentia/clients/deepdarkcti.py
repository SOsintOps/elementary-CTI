"""deepdarkCTI enrichment for Elementary CTI groups.

Parses multiple markdown tables from fastfire/deepdarkCTI on GitHub:
- ransomware_gang.md — onion site status, communication channels
- telegram_threat_actors.md — Telegram channels per group
- twitter_threat_actors.md — X/Twitter accounts per group

Usage:
    python -m pestilentia.clients.deepdarkcti
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.clients._util import normalize_group_name as _normalize
from pestilentia.clients.http import get_with_retry
from pestilentia.config import get_settings
from pestilentia.models.tables import Group, GroupComm, GroupLocation, InfoUpdate

log = logging.getLogger(__name__)

DEEPDARK_BASE = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"
DEEPDARK_FILES = {
    "ransomware_gang": f"{DEEPDARK_BASE}/ransomware_gang.md",
    "telegram_threat_actors": f"{DEEPDARK_BASE}/telegram_threat_actors.md",
    "twitter_threat_actors": f"{DEEPDARK_BASE}/twitter_threat_actors.md",
}
DEEPDARK_CATEGORY = "deepdarkcti_enrichment"

# Pattern to extract name and URL from markdown links: [Name](url)
_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

# Patterns to classify communication channels
_COMM_PATTERNS = [
    ("telegram", re.compile(r"https?://t\.me/\S+", re.I)),
    ("twitter", re.compile(r"https?://(?:twitter\.com|x\.com)/\S+", re.I)),
    ("email", re.compile(r"[\w.+-]+@[\w.-]+\.\w+", re.I)),
    ("tox", re.compile(r"[0-9A-Fa-f]{64,}", re.I)),
    ("session", re.compile(r"^05[0-9a-f]{64}$", re.I)),
    ("jabber", re.compile(r"[\w.+-]+@(?:xmpp|jabber)\.\S+", re.I)),
]

# Names in the table that are meta-entries, not actual gangs
_META_PREFIXES = {
    "ransomchats",
    "ransomfeed",
    "ransom db",
    "ransomware group sites",
    "ransomware groups monitoring tool",
    "ransomnews",
}


def _fetch_markdown(url: str) -> str:
    """Fetch a markdown file from GitHub."""
    log.info("Fetching deepdarkCTI: %s", url.split("/")[-1])
    r = get_with_retry(url, timeout=30)
    r.raise_for_status()
    return r.text


def parse_ransomware_table(md_text: str) -> list[dict]:
    """Parse markdown table rows into structured dicts.

    Returns list of dicts with keys: name, url, status, credentials, comms_raw, rss
    """
    rows = []
    in_table = False
    last_was_data = False

    for line in md_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            in_table = False
            last_was_data = False
            continue

        # Skip header/separator rows
        cells = [c.strip() for c in line.split("|")]
        # Split creates empty strings at start/end due to leading/trailing |
        cells = [c for c in cells if c]

        if not cells:
            continue

        # Detect separator row (all dashes)
        if all(re.match(r"^[-:]+$", c) for c in cells):
            # A separator always follows a header: if the previous line was
            # taken as data, it was really the next back-to-back table's
            # header with an unrecognized first column — drop it (LO-06)
            if in_table and last_was_data and rows:
                rows.pop()
            in_table = True
            last_was_data = False
            continue

        # Detect header row
        if cells[0].lower() in ("name", "**name**"):
            in_table = True
            last_was_data = False
            continue

        if not in_table:
            continue

        # Parse name cell — may contain markdown link
        name_cell = cells[0] if cells else ""
        link_match = _LINK_RE.search(name_cell)
        if link_match:
            name = link_match.group(1)
            url = link_match.group(2)
        else:
            name = name_cell
            url = ""

        # Strip qualifiers like "(Dark)", "(Deep)", "(Victims page)"
        clean_name = re.sub(
            r"\s*\((?:Dark|Deep|Victims?\s*page|Clearnet|Mirror)\)",
            "",
            name,
            flags=re.I,
        ).strip()

        # Skip meta-entries
        if clean_name.lower() in _META_PREFIXES:
            last_was_data = False
            continue

        status = cells[1].strip().upper() if len(cells) > 1 else ""
        credentials = cells[2].strip() if len(cells) > 2 else ""
        comms_raw = cells[3].strip() if len(cells) > 3 else ""
        rss = cells[4].strip() if len(cells) > 4 else ""

        rows.append(
            {
                "name": clean_name,
                "url": url,
                "status": status,
                "credentials": credentials,
                "comms_raw": comms_raw,
                "rss": rss,
            }
        )
        last_was_data = True

    log.info("Parsed %d rows from deepdarkCTI ransomware table", len(rows))
    return rows


def parse_telegram_actors(md_text: str) -> list[dict]:
    """Parse telegram_threat_actors.md table.

    Columns: Telegram | Status | Threat Actor Name | Type of attacks
    Returns list of dicts with keys: name, url, status, attack_type
    """
    rows = []
    in_table = False

    for line in md_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            in_table = False
            continue

        cells = [c.strip() for c in line.split("|")]
        cells = [c for c in cells if c]

        if not cells:
            continue

        if all(re.match(r"^[-:]+$", c) for c in cells):
            in_table = True
            continue

        if cells[0].lower() in ("telegram", "**telegram**", "link"):
            in_table = True
            continue

        if not in_table:
            continue

        url_cell = cells[0].strip() if cells else ""
        link_match = _LINK_RE.search(url_cell)
        if link_match:
            url = link_match.group(2)
        elif url_cell.startswith("http"):
            url = url_cell
        else:
            url = ""

        status = cells[1].strip().upper() if len(cells) > 1 else ""
        name = cells[2].strip() if len(cells) > 2 else ""
        attack_type = cells[3].strip() if len(cells) > 3 else ""

        if not name or not url:
            continue

        rows.append(
            {
                "name": name,
                "url": url,
                "status": status,
                "attack_type": attack_type,
            }
        )

    log.info("Parsed %d rows from deepdarkCTI telegram_threat_actors", len(rows))
    return rows


def parse_twitter_actors(md_text: str) -> list[dict]:
    """Parse twitter_threat_actors.md table.

    Columns: Link | Description | Category | Status (approx)
    Returns list of dicts with keys: name, url, status
    """
    rows = []
    in_table = False

    for line in md_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            in_table = False
            continue

        cells = [c.strip() for c in line.split("|")]
        cells = [c for c in cells if c]

        if not cells:
            continue

        if all(re.match(r"^[-:]+$", c) for c in cells):
            in_table = True
            continue

        if cells[0].lower() in ("link", "**link**", "twitter"):
            in_table = True
            continue

        if not in_table:
            continue

        # Col 0: Link (raw URL or markdown link), Col 1: Description (= name)
        url_cell = cells[0].strip() if cells else ""
        link_match = _LINK_RE.search(url_cell)
        if link_match:
            url = link_match.group(2)
        elif url_cell.startswith("http"):
            url = url_cell
        else:
            url = ""

        # Name from Description column (col 1)
        name = cells[1].strip() if len(cells) > 1 else ""
        if not name or not url:
            continue

        status = ""
        for c in cells[2:]:
            if c.upper() in ("ONLINE", "OFFLINE", "EXPIRED", "VALID", "SUSPENDED"):
                status = c.upper()
                break

        rows.append(
            {
                "name": name,
                "url": url,
                "status": status,
            }
        )

    log.info("Parsed %d rows from deepdarkCTI twitter_threat_actors", len(rows))
    return rows


def extract_comms(comms_raw: str) -> list[tuple[str, str]]:
    """Extract typed communication channels from raw string.

    Returns list of (channel_type, channel_value) tuples.
    """
    if not comms_raw or comms_raw == "-":
        return []

    results = []
    # Split on common separators
    parts = re.split(r"\s*[-\u2013\u2014]\s*|\s*,\s*|\s*\|\s*", comms_raw)

    for part in parts:
        part = part.strip()
        if not part or part == "-":
            continue

        matched = False
        for ch_type, pattern in _COMM_PATTERNS:
            m = pattern.search(part)
            if m:
                results.append((ch_type, m.group(0)))
                matched = True
                break

        if not matched and part.startswith("http"):
            results.append(("website", part))

    return results


def _build_name_index(groups: list[Group]) -> dict[str, Group]:
    """Build normalized name → Group lookup including aliases."""
    index: dict[str, Group] = {}
    for g in groups:
        index[_normalize(g.group_name)] = g
        if g.aliases:
            try:
                aliases = json.loads(g.aliases)
                if isinstance(aliases, list):
                    for alias in aliases:
                        norm = _normalize(str(alias))
                        if norm:
                            index[norm] = g
            except (json.JSONDecodeError, TypeError):
                pass
    return index


def _safe_add_comm(session: Session, comm: GroupComm) -> bool:
    sp = session.begin_nested()
    try:
        session.add(comm)
        sp.commit()
        return True
    except IntegrityError:
        sp.rollback()
        return False
    except Exception:
        # Close the savepoint before propagating, or the outer
        # transaction stays poisoned for the rest of the cycle (ME-02)
        sp.rollback()
        raise


def _get_last_enrichment(session: Session) -> datetime | None:
    row = session.query(InfoUpdate).filter_by(category=DEEPDARK_CATEGORY).first()
    if row and row.last_update_json:
        return row.last_update_json
    return None


def _set_last_enrichment(session: Session, ts: datetime) -> None:
    row = session.query(InfoUpdate).filter_by(category=DEEPDARK_CATEGORY).first()
    if row:
        row.last_update_json = ts
    else:
        session.add(InfoUpdate(category=DEEPDARK_CATEGORY, last_update_json=ts))


def enrich_deepdarkcti(session: Session, force: bool = False) -> dict:
    """Enrich groups with deepdarkCTI operational data.

    Args:
        session: Active SQLAlchemy session.
        force: Bypass freshness check.

    Returns:
        Stats dict with enrichment counts.
    """
    stats = {
        "gangs_total": 0,
        "gangs_matched": 0,
        "comms_added": 0,
        "statuses_updated": 0,
        "urls_added": 0,
        "skipped": False,
    }

    # Freshness check
    if not force:
        last = _get_last_enrichment(session)
        if last:
            cfg = get_settings()
            cutoff = datetime.now(UTC) - timedelta(hours=cfg.deepdarkcti_enrichment_hours)
            if last > cutoff:
                log.info(
                    "deepdarkCTI enrichment fresh (last=%s) — skipping",
                    last,
                )
                stats["skipped"] = True
                return stats

    # Build match index (shared across all files)
    all_groups = session.query(Group).all()
    name_index = _build_name_index(all_groups)
    matched_groups: set[int] = set()
    # Track whether at least one file was fetched + parsed. If every file fails
    # (e.g. transient network/DNS outage), we must NOT mark the enrichment as
    # done — otherwise the freshness gate suppresses retries for a full week
    # (ME-05). Leaving the timestamp untouched retries on the next cycle (~4h).
    any_success = False

    # ── 1. ransomware_gang.md ──
    try:
        md_text = _fetch_markdown(DEEPDARK_FILES["ransomware_gang"])
        rows = parse_ransomware_table(md_text)
        any_success = True
        gangs: dict[str, list[dict]] = {}
        for row in rows:
            gangs.setdefault(row["name"], []).append(row)
        stats["gangs_total"] = len(gangs)

        for gang_name, gang_rows in gangs.items():
            norm = _normalize(gang_name)
            group = name_index.get(norm)
            if not group:
                continue

            if group.id not in matched_groups:
                stats["gangs_matched"] += 1
                matched_groups.add(group.id)

            for row in gang_rows:
                url = row.get("url", "")
                status_str = row.get("status", "")
                is_online = "ONLINE" in status_str

                if url and ".onion" in url:
                    existing_loc = (
                        session.query(GroupLocation).filter_by(group_id=group.id, fqdn=url).first()
                    )
                    if existing_loc:
                        if existing_loc.available != is_online:
                            existing_loc.available = is_online
                            existing_loc.updated = datetime.now(UTC)
                            stats["statuses_updated"] += 1
                    else:
                        loc = GroupLocation(
                            group_id=group.id,
                            fqdn=url,
                            title=gang_name,
                            type="onion" if ".onion" in url else "clearnet",
                            available=is_online,
                            updated=datetime.now(UTC),
                        )
                        session.add(loc)
                        stats["urls_added"] += 1

                comms = extract_comms(row.get("comms_raw", ""))
                for ch_type, ch_value in comms:
                    comm = GroupComm(
                        group_id=group.id,
                        channel_type=ch_type,
                        channel_value=ch_value,
                        source="deepdarkcti",
                    )
                    if _safe_add_comm(session, comm):
                        stats["comms_added"] += 1
    except (httpx.HTTPError, ValueError, KeyError):
        log.exception("Failed to process ransomware_gang.md")

    # ── 2. telegram_threat_actors.md ──
    try:
        md_text = _fetch_markdown(DEEPDARK_FILES["telegram_threat_actors"])
        tg_rows = parse_telegram_actors(md_text)
        any_success = True
        for row in tg_rows:
            norm = _normalize(row["name"])
            group = name_index.get(norm)
            if not group:
                continue
            if group.id not in matched_groups:
                stats["gangs_matched"] += 1
                matched_groups.add(group.id)
            url = row.get("url", "")
            if url and "t.me" in url:
                comm = GroupComm(
                    group_id=group.id,
                    channel_type="telegram",
                    channel_value=url,
                    source="deepdarkcti",
                )
                if _safe_add_comm(session, comm):
                    stats["comms_added"] += 1
    except (httpx.HTTPError, ValueError, KeyError):
        log.exception("Failed to process telegram_threat_actors.md")

    # ── 3. twitter_threat_actors.md ──
    try:
        md_text = _fetch_markdown(DEEPDARK_FILES["twitter_threat_actors"])
        tw_rows = parse_twitter_actors(md_text)
        any_success = True
        for row in tw_rows:
            norm = _normalize(row["name"])
            group = name_index.get(norm)
            if not group:
                continue
            if group.id not in matched_groups:
                stats["gangs_matched"] += 1
                matched_groups.add(group.id)
            url = row.get("url", "")
            if url and ("twitter.com" in url or "x.com" in url):
                comm = GroupComm(
                    group_id=group.id,
                    channel_type="twitter",
                    channel_value=url,
                    source="deepdarkcti",
                )
                if _safe_add_comm(session, comm):
                    stats["comms_added"] += 1
    except (httpx.HTTPError, ValueError, KeyError):
        log.exception("Failed to process twitter_threat_actors.md")

    if any_success:
        _set_last_enrichment(session, datetime.now(UTC))
    else:
        log.warning(
            "deepdarkCTI: all source files failed to fetch/parse — leaving last-enrichment "
            "timestamp untouched so the next cycle retries instead of waiting a full interval"
        )
    session.commit()

    log.info(
        "deepdarkCTI enrichment: %d/%d gangs matched, +%d comms, +%d urls, %d status updates",
        stats["gangs_matched"],
        stats["gangs_total"],
        stats["comms_added"],
        stats["urls_added"],
        stats["statuses_updated"],
    )
    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from pestilentia.models.base import get_session_factory

    factory = get_session_factory("sqlite:///elementaryctiDB.db")
    with factory() as session:
        result = enrich_deepdarkcti(session, force=True)
        print("\n=== deepdarkCTI Enrichment Results ===")
        for k, v in result.items():
            print(f"  {k}: {v}")
