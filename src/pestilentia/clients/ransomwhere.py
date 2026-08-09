"""Ransomwhere BTC payment enrichment for Elementary CTI groups.

Downloads the full export from api.ransomwhe.re, matches families to
Elementary CTI groups by BTC address or normalized name, and imports
transaction data.

Usage:
    python -m pestilentia.clients.ransomwhere
"""

from __future__ import annotations

import json
import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.clients._util import normalize_group_name as _normalize
from pestilentia.clients.http import get_with_retry
from pestilentia.config import get_settings
from pestilentia.models.tables import Group, GroupBtcTransaction, InfoUpdate

log = logging.getLogger(__name__)

RANSOMWHERE_API = "https://api.ransomwhe.re/export"
RANSOMWHERE_CATEGORY = "ransomwhere_enrichment"

# Families too generic to match by name alone
SKIP_FAMILIES = {
    "unknown",
    "test",
    "generic",
    "other",
}


def fetch_ransomwhere_export() -> list[dict]:
    """Fetch full BTC address export from Ransomwhere API."""
    log.info("Fetching Ransomwhere export from %s …", RANSOMWHERE_API)
    r = get_with_retry(RANSOMWHERE_API, timeout=60)
    r.raise_for_status()
    data = r.json()
    # API returns {"result": [...]} wrapper
    if isinstance(data, dict) and "result" in data:
        return data["result"]
    if isinstance(data, list):
        return data
    log.warning("Unexpected Ransomwhere response format: %s", type(data))
    return []


def _build_address_index(groups: list[Group]) -> dict[str, Group]:
    """Build BTC address → Group lookup from existing btc_addresses JSON field."""
    index: dict[str, Group] = {}
    for g in groups:
        if not g.btc_addresses:
            continue
        try:
            addrs = json.loads(g.btc_addresses)
            if isinstance(addrs, list):
                for addr in addrs:
                    if isinstance(addr, str) and addr.strip():
                        index[addr.strip()] = g
            elif isinstance(addrs, str):
                index[addrs.strip()] = g
        except (json.JSONDecodeError, TypeError):
            if isinstance(g.btc_addresses, str) and g.btc_addresses.strip():
                index[g.btc_addresses.strip()] = g
    return index


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
                        if norm and norm not in SKIP_FAMILIES:
                            index[norm] = g
            except (json.JSONDecodeError, TypeError):
                pass
    return index


def _match_family(
    family: str,
    addresses: list[str],
    addr_index: dict[str, Group],
    name_index: dict[str, Group],
) -> Group | None:
    """Match a Ransomwhere family to an Elementary CTI group."""
    # Primary: BTC address match
    for addr in addresses:
        if addr in addr_index:
            return addr_index[addr]

    # Secondary: normalized name match
    norm = _normalize(family)
    if norm and norm not in SKIP_FAMILIES and norm in name_index:
        return name_index[norm]

    return None


def _get_last_enrichment(session: Session) -> datetime | None:
    row = session.query(InfoUpdate).filter_by(category=RANSOMWHERE_CATEGORY).first()
    if row and row.last_update_json:
        return row.last_update_json
    return None


def _set_last_enrichment(session: Session, ts: datetime) -> None:
    row = session.query(InfoUpdate).filter_by(category=RANSOMWHERE_CATEGORY).first()
    if row:
        row.last_update_json = ts
    else:
        session.add(InfoUpdate(category=RANSOMWHERE_CATEGORY, last_update_json=ts))


def _safe_add_tx(session: Session, tx: GroupBtcTransaction) -> bool:
    sp = session.begin_nested()
    try:
        session.add(tx)
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


def enrich_ransomwhere(session: Session, force: bool = False) -> dict:
    """Enrich groups with Ransomwhere BTC payment data.

    Args:
        session: Active SQLAlchemy session.
        force: Bypass freshness check.

    Returns:
        Stats dict with enrichment counts.
    """
    stats = {
        "families_total": 0,
        "families_matched": 0,
        "addresses_added": 0,
        "transactions_added": 0,
        "total_usd": 0.0,
        "skipped": False,
    }

    # Freshness check
    if not force:
        last = _get_last_enrichment(session)
        if last:
            cfg = get_settings()
            cutoff = datetime.now(UTC) - timedelta(hours=cfg.ransomwhere_enrichment_hours)
            if last > cutoff:
                log.info(
                    "Ransomwhere enrichment fresh (last=%s, cutoff=%s) — skipping",
                    last,
                    cutoff,
                )
                stats["skipped"] = True
                return stats

    # Fetch data
    records = fetch_ransomwhere_export()
    if not records:
        log.warning("Ransomwhere export returned no records")
        return stats

    # Build family → records mapping
    families: dict[str, list[dict]] = {}
    for rec in records:
        family = rec.get("family", "unknown")
        families.setdefault(family, []).append(rec)
    stats["families_total"] = len(families)

    # Build match indexes
    all_groups = session.query(Group).all()
    addr_index = _build_address_index(all_groups)
    name_index = _build_name_index(all_groups)

    # Match and import
    for family, family_records in families.items():
        addresses = [r.get("address", "") for r in family_records if r.get("address")]
        group = _match_family(family, addresses, addr_index, name_index)
        if not group:
            continue

        stats["families_matched"] += 1
        log.info("MATCH: Ransomwhere '%s' → '%s'", family, group.group_name)

        # Collect new addresses for btc_addresses field update
        new_addrs = set()

        for rec in family_records:
            address = rec.get("address", "")
            if not address:
                continue
            new_addrs.add(address)

            # Import transactions
            for tx in rec.get("transactions", []):
                tx_hash = tx.get("hash", "")
                if not tx_hash:
                    continue

                amount_sat = tx.get("amount", 0)
                amount_btc = amount_sat / 1e8 if amount_sat else 0
                amount_usd = tx.get("amountUSD", 0) or 0
                tx_time = tx.get("time")
                tx_date = None
                if tx_time:
                    with suppress(ValueError, OSError, TypeError):
                        tx_date = datetime.fromtimestamp(tx_time, tz=UTC)

                btc_tx = GroupBtcTransaction(
                    group_id=group.id,
                    address=address,
                    tx_hash=tx_hash,
                    amount_btc=amount_btc,
                    amount_usd=amount_usd,
                    tx_date=tx_date,
                    source="ransomwhere",
                )
                if _safe_add_tx(session, btc_tx):
                    stats["transactions_added"] += 1
                    stats["total_usd"] += float(amount_usd)

        # Update Group.btc_addresses with new addresses
        if new_addrs:
            try:
                existing = json.loads(group.btc_addresses) if group.btc_addresses else []
            except (json.JSONDecodeError, TypeError):
                existing = []
            if not isinstance(existing, list):
                existing = [existing] if existing else []
            existing_set = set(existing)
            added = new_addrs - existing_set
            if added:
                existing.extend(sorted(added))
                group.btc_addresses = json.dumps(existing)
                stats["addresses_added"] += len(added)

    _set_last_enrichment(session, datetime.now(UTC))
    session.commit()

    log.info(
        "Ransomwhere enrichment: %d/%d families matched, +%d txs ($%.0f USD)",
        stats["families_matched"],
        stats["families_total"],
        stats["transactions_added"],
        stats["total_usd"],
    )
    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from pestilentia.models.base import get_session_factory

    factory = get_session_factory("sqlite:///elementaryctiDB.db")
    with factory() as session:
        result = enrich_ransomwhere(session, force=True)
        print("\n=== Ransomwhere Enrichment Results ===")
        for k, v in result.items():
            print(f"  {k}: {v}")
