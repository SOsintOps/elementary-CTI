"""MITRE ATT&CK enrichment for Elementary CTI groups.

Downloads enterprise-attack.json (STIX 2.1), matches MITRE groups to
Elementary CTI groups by normalized name/alias, and imports TTPs, software,
aliases, country of origin, and reference URLs.

Supports incremental mode: checks bundle freshness via HTTP HEAD, filters
STIX objects modified since last enrichment, and matches newly ingested groups.

Usage:
    python -m pestilentia.clients.mitre_attack
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.clients._util import normalize_group_name as _normalize
from pestilentia.clients.base import SourceError
from pestilentia.clients.http import get_with_retry, head_with_retry
from pestilentia.models.base import get_session_factory
from pestilentia.models.tables import Group, GroupReference, GroupTool, GroupTTP, InfoUpdate
from pestilentia.pipeline.source_evidence import get_or_create_source, upsert_source_evidence

log = logging.getLogger(__name__)

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

MITRE_ENRICHMENT_CATEGORY = "mitre_enrichment"

CACHE_PATH = Path("data/enterprise-attack.json")

TACTIC_MAP = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

COUNTRY_PATTERNS = [
    (re.compile(r"\bRussia\b", re.I), "RU"),
    (re.compile(r"\bRussian\b", re.I), "RU"),
    (re.compile(r"\bChina\b", re.I), "CN"),
    (re.compile(r"\bChinese\b", re.I), "CN"),
    (re.compile(r"\bIran\b", re.I), "IR"),
    (re.compile(r"\bIranian\b", re.I), "IR"),
    (re.compile(r"\bNorth Korea\b", re.I), "KP"),
    (re.compile(r"\bDPRK\b", re.I), "KP"),
    (re.compile(r"\bSouth Korea\b", re.I), "KR"),
    (re.compile(r"\bVietnam\b", re.I), "VN"),
    (re.compile(r"\bPakistan\b", re.I), "PK"),
    (re.compile(r"\bTurkey\b", re.I), "TR"),
    (re.compile(r"\bTurkish\b", re.I), "TR"),
    (re.compile(r"\bIsrael\b", re.I), "IL"),
    (re.compile(r"\bIndia\b", re.I), "IN"),
    (re.compile(r"\bIndian\b", re.I), "IN"),
    (re.compile(r"\bBrazil\b", re.I), "BR"),
    (re.compile(r"\bLebanon\b", re.I), "LB"),
    (re.compile(r"\bPalestinian\b", re.I), "PS"),
    (re.compile(r"\bUkrain\b", re.I), "UA"),
    (re.compile(r"\bBelarus\b", re.I), "BY"),
    (re.compile(r"\bNigeria\b", re.I), "NG"),
]

SKIP_MATCHES = {
    "cactus",
    "karma",
    "knight",
    "shadow",
    "silent",
    "snake",
    "bert",
    "hive",
    "royal",
    "playboy",
    "onyx",
}


# "The game is afoot." — Sherlock Holmes, Elementary
def download_stix_bundle(url: str = MITRE_STIX_URL, force: bool = False) -> dict:
    """Return the STIX bundle, from the on-disk cache unless ``force`` is True.

    The cache has no TTL: callers that need freshness must check
    ``check_bundle_freshness`` themselves and pass ``force=True`` (HI-03).
    """
    if CACHE_PATH.exists() and not force:
        log.info("Using cached STIX bundle: %s", CACHE_PATH)
        return json.loads(CACHE_PATH.read_text())
    log.info("Downloading STIX bundle from %s …", url)
    r = get_with_retry(url, timeout=60)
    r.raise_for_status()
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_bytes(r.content)
    return r.json()


def check_bundle_freshness(url: str = MITRE_STIX_URL, stored_etag: str = "") -> tuple[bool, str]:
    """HTTP HEAD to check if STIX bundle changed. Returns (changed, new_etag)."""
    try:
        r = head_with_retry(url, timeout=15)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("Bundle freshness check failed: %s — assuming changed", exc)
        return True, ""

    etag = r.headers.get("etag", "")
    last_modified = r.headers.get("last-modified", "")
    remote_tag = etag or last_modified

    if stored_etag and remote_tag == stored_etag:
        log.info("STIX bundle unchanged (etag=%s)", remote_tag[:40])
        return False, remote_tag

    log.info("STIX bundle changed (old=%s, new=%s)", stored_etag[:40], remote_tag[:40])
    return True, remote_tag


def parse_mitre_groups(bundle: dict) -> list[dict]:
    results = []
    for obj in bundle["objects"]:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_refs = obj.get("external_references", [])
        mitre_id = ""
        mitre_url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                mitre_url = ref.get("url", "")
                break
        results.append(
            {
                "stix_id": obj["id"],
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": obj.get("description", ""),
                "mitre_id": mitre_id,
                "mitre_url": mitre_url,
            }
        )
    return results


def parse_mitre_techniques(bundle: dict) -> dict[str, dict]:
    techniques = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_refs = obj.get("external_references", [])
        tech_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break
        if not tech_id:
            continue
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                slug = phase["phase_name"]
                if slug in TACTIC_MAP:
                    tactics.append(TACTIC_MAP[slug])
        techniques[obj["id"]] = {
            "technique_id": tech_id,
            "technique_name": obj.get("name", ""),
            "description": (obj.get("description") or "")[:500],
            "tactics": tactics,
        }
    return techniques


def parse_mitre_software(bundle: dict) -> dict[str, dict]:
    software = {}
    for obj in bundle["objects"]:
        if obj.get("type") not in ("tool", "malware"):
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        software[obj["id"]] = {
            "name": obj.get("name", ""),
            "type": obj.get("type", ""),
        }
    return software


def parse_relationships(bundle: dict) -> list[dict]:
    rels = []
    for obj in bundle["objects"]:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        rels.append(
            {
                "source_ref": obj["source_ref"],
                "target_ref": obj["target_ref"],
            }
        )
    return rels


def extract_country(description: str) -> str | None:
    # Whole description, not just the first paragraph: MITRE often states
    # the operational origin in paragraph 2 (LO-05)
    if not description:
        return None
    for pattern, code in COUNTRY_PATTERNS:
        if pattern.search(description):
            return code
    return None


def validate_bundle(bundle: object) -> dict:
    """Fail loudly on a malformed STIX bundle instead of a deep KeyError (ME-07)."""
    if not isinstance(bundle, dict) or "objects" not in bundle:
        got = type(bundle).__name__
        raise SourceError("mitre", f"Invalid STIX bundle: missing 'objects' key (got {got})")
    return bundle


def match_groups(
    mitre_groups: list[dict],
    pest_groups: list[Group],
) -> list[tuple[dict, Group]]:
    pest_lookup: dict[str, Group] = {}
    for g in pest_groups:
        pest_lookup[_normalize(g.group_name)] = g

    matches = []
    for mg in mitre_groups:
        all_names = [mg["name"], *mg.get("aliases", [])]
        for name in all_names:
            norm = _normalize(name)
            if norm in SKIP_MATCHES:
                continue
            if norm in pest_lookup:
                matches.append((mg, pest_lookup[norm]))
                via = "" if name == mg["name"] else f" (via alias '{name}')"
                log.info(
                    "MATCH: MITRE '%s' → Pestilentia '%s'%s",
                    mg["name"],
                    pest_lookup[norm].group_name,
                    via,
                )
                break
    return matches


def _safe_add(session, obj):
    sp = session.begin_nested()
    try:
        session.add(obj)
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


SOFTWARE_TO_GROUP = {
    "lockbit 3.0": "lockbit",
    "lockbit 2.0": "lockbit",
    "conti": "conti",
    "blackcat": "alphv",
    "revil": "revil",
    "black basta": "blackbasta",
    "clop": "clop",
    "royal": "royal",
    "babuk": "babuk",
    "ragnar locker": "ragnarlocker",
    "cuba": "cuba",
    "rhysida": "rhysida",
    "hive": "hive",
    "avaddon": "avaddon",
    "darkside": "darkside",
    "diavol": "diavol",
    "maze": "maze",
    "netwalker": "netwalker",
    "pysa": "pysa",
    "sodinokibi": "revil",
    "medusalocker": "medusalocker",
    "phobos": "phobos",
    "avos locker": "avoslocker",
}


def _import_ttps_for_group(session, pg, tech_stix_ids, techniques, stats):
    for tech_stix_id in tech_stix_ids:
        tech = techniques[tech_stix_id]
        for tactic_id, tactic_name in tech["tactics"]:
            ttp = GroupTTP(
                group_id=pg.id,
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                technique_id=tech["technique_id"],
                technique_name=tech["technique_name"],
                technique_details=tech["description"][:500] if tech["description"] else None,
            )
            if _safe_add(session, ttp):
                stats["ttps_added"] += 1


def _read_etag_file() -> str:
    etag_path = CACHE_PATH.with_suffix(".etag")
    if etag_path.exists():
        return etag_path.read_text().strip()
    return ""


def _write_etag_file(etag: str) -> None:
    etag_path = CACHE_PATH.with_suffix(".etag")
    etag_path.parent.mkdir(parents=True, exist_ok=True)
    etag_path.write_text(etag)


def _get_last_enrichment(session: Session) -> datetime | None:
    row = session.query(InfoUpdate).filter_by(category=MITRE_ENRICHMENT_CATEGORY).first()
    if row and row.last_update_json:
        return row.last_update_json
    return None


def _set_last_enrichment(session: Session, ts: datetime) -> None:
    row = session.query(InfoUpdate).filter_by(category=MITRE_ENRICHMENT_CATEGORY).first()
    if row:
        row.last_update_json = ts
    else:
        session.add(InfoUpdate(category=MITRE_ENRICHMENT_CATEGORY, last_update_json=ts))


def _merge_aliases(pg: Group, mitre_aliases: list[str]) -> list[str]:
    """Union MITRE aliases with the ones already on the group (ME-03).

    Ingestion's `_merge_altname` sets aliases MITRE doesn't know about
    (e.g. "BlackCat" vs MITRE's "ALPHV") — overwriting would lose them on
    every enrichment pass. Dedup is case-insensitive (first form wins);
    the group's own name is excluded.
    """
    try:
        existing = json.loads(pg.aliases) if pg.aliases else []
    except (json.JSONDecodeError, TypeError):
        existing = []
    if not isinstance(existing, list):
        existing = [str(existing)]

    own_name = (pg.group_name or "").lower()
    merged: dict[str, str] = {}
    for alias in [*existing, *mitre_aliases]:
        if alias and alias.lower() != own_name:
            merged.setdefault(alias.lower(), alias)
    return sorted(merged.values(), key=str.lower)


def _enrich_matched_groups(
    session: Session,
    matches: list[tuple[dict, Group]],
    group_techs: dict[str, list[str]],
    group_sw: dict[str, list[str]],
    techniques: dict[str, dict],
    software: dict[str, dict],
    stats: dict,
) -> None:
    mitre_ds = get_or_create_source(session, "MITRE ATT&CK", "https://attack.mitre.org")
    for mg, pg in matches:
        # Preserve the full MITRE profile as attributed evidence (it is far
        # richer than the feed description and was previously discarded)
        upsert_source_evidence(session, pg.group_name, mitre_ds.id, json.dumps(mg, default=str))

        if mg.get("aliases"):
            pg.aliases = json.dumps(_merge_aliases(pg, mg["aliases"]))
            stats["aliases_set"] += 1

        country = extract_country(mg.get("description", ""))
        if country:
            pg.country_of_origin = country
            stats["countries_set"] += 1

        if mg.get("mitre_url"):
            ref = GroupReference(group_id=pg.id, url=mg["mitre_url"])
            if _safe_add(session, ref):
                stats["refs_added"] += 1

        _import_ttps_for_group(session, pg, group_techs.get(mg["stix_id"], []), techniques, stats)

        for sw_stix_id in group_sw.get(mg["stix_id"], []):
            sw = software[sw_stix_id]
            tool = GroupTool(
                group_id=pg.id,
                category="MITRE Software",
                tool_name=sw["name"],
            )
            if _safe_add(session, tool):
                stats["tools_added"] += 1


def _enrich_software_matches(
    session: Session,
    software: dict[str, dict],
    sw_techs: dict[str, list[str]],
    techniques: dict[str, dict],
    pest_by_name: dict[str, Group],
    stats: dict,
) -> None:
    for sw_stix_id, sw_data in software.items():
        sw_name_lower = sw_data["name"].lower()
        pest_group_name = SOFTWARE_TO_GROUP.get(sw_name_lower)
        if not pest_group_name:
            continue
        pg = pest_by_name.get(pest_group_name)
        if not pg:
            continue
        log.info("SW MATCH: MITRE software '%s' → '%s'", sw_data["name"], pg.group_name)
        stats["matched_software"] += 1
        tech_ids = sw_techs.get(sw_stix_id, [])
        _import_ttps_for_group(session, pg, tech_ids, techniques, stats)


def _build_relationship_maps(
    relationships: list[dict],
    group_stix_ids: dict[str, dict],
    techniques: dict[str, dict],
    software: dict[str, dict],
) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, list[str]]]:
    group_techs: dict[str, list[str]] = {}
    group_sw: dict[str, list[str]] = {}
    sw_techs: dict[str, list[str]] = {}
    for rel in relationships:
        src, tgt = rel["source_ref"], rel["target_ref"]
        if src in group_stix_ids:
            if tgt in techniques:
                group_techs.setdefault(src, []).append(tgt)
            elif tgt in software:
                group_sw.setdefault(src, []).append(tgt)
        if src in software and tgt in techniques:
            sw_techs.setdefault(src, []).append(tgt)
    return group_techs, group_sw, sw_techs


def _new_stats() -> dict:
    return {
        "matched_groups": 0,
        "matched_software": 0,
        "ttps_added": 0,
        "tools_added": 0,
        "refs_added": 0,
        "aliases_set": 0,
        "countries_set": 0,
        "skipped": False,
    }


def enrich_groups(db_url: str = "sqlite:///elementaryctiDB.db") -> dict:
    """Full enrichment — downloads bundle and processes all groups."""
    bundle = validate_bundle(download_stix_bundle())
    return _enrich_from_bundle(bundle, db_url)


def enrich_groups_incremental(
    session: Session,
    force: bool = False,
) -> dict:
    """Incremental enrichment — skips if bundle unchanged, processes only delta.

    Args:
        session: Active SQLAlchemy session.
        force: Bypass freshness check and re-enrich everything.

    Returns:
        Stats dict with enrichment counts.
    """
    stats = _new_stats()

    # Step 1: Check bundle freshness
    changed = True  # assume changed by default (force mode skips check)
    if not force:
        stored_etag = _read_etag_file()
        changed, new_etag = check_bundle_freshness(stored_etag=stored_etag)

        if not changed:
            # Even if bundle unchanged, check for new groups not yet enriched
            last_enrichment = _get_last_enrichment(session)
            new_groups = _find_unenriched_groups(session)
            if not new_groups:
                log.info("STIX bundle unchanged and no new groups — skipping enrichment")
                stats["skipped"] = True
                return stats
            log.info(
                "STIX bundle unchanged but %d new groups found — enriching new groups only",
                len(new_groups),
            )

        if new_etag:
            _write_etag_file(new_etag)

    # Step 2: Download/load bundle (bypass cache when bundle changed or forced)
    bundle = validate_bundle(download_stix_bundle(force=force or changed))

    # Step 3: Parse
    mitre_groups = parse_mitre_groups(bundle)
    techniques = parse_mitre_techniques(bundle)
    software = parse_mitre_software(bundle)
    relationships = parse_relationships(bundle)

    log.info(
        "Parsed: %d groups, %d techniques, %d software, %d relationships",
        len(mitre_groups),
        len(techniques),
        len(software),
        len(relationships),
    )

    group_stix_ids = {mg["stix_id"]: mg for mg in mitre_groups}
    group_techs, group_sw, sw_techs = _build_relationship_maps(
        relationships,
        group_stix_ids,
        techniques,
        software,
    )

    # Step 4: Filter by modification date for truly incremental processing
    last_enrichment = _get_last_enrichment(session)
    if last_enrichment and not force:
        mitre_groups = _filter_modified_since(mitre_groups, bundle, last_enrichment)
        log.info(
            "Filtered to %d MITRE groups modified since %s",
            len(mitre_groups),
            last_enrichment,
        )

    # Step 5: Enrich
    all_groups = session.query(Group).all()
    pest_by_name = {g.group_name.lower(): g for g in all_groups}

    matches = match_groups(mitre_groups, all_groups)
    stats["matched_groups"] = len(matches)

    _enrich_matched_groups(session, matches, group_techs, group_sw, techniques, software, stats)
    _enrich_software_matches(session, software, sw_techs, techniques, pest_by_name, stats)

    # Step 6: Track enrichment timestamp
    _set_last_enrichment(session, datetime.now(UTC))
    session.commit()

    log.info("Incremental enrichment complete: %s", stats)
    return stats


def _find_unenriched_groups(session: Session) -> list[Group]:
    """Find groups that have no MITRE TTPs yet (likely newly ingested)."""
    enriched_ids = {row[0] for row in session.query(GroupTTP.group_id).distinct().all()}
    all_groups = session.query(Group).all()
    return [g for g in all_groups if g.id not in enriched_ids]


def _filter_modified_since(
    mitre_groups: list[dict],
    bundle: dict,
    since: datetime,
) -> list[dict]:
    """Keep only MITRE groups whose STIX object was modified after `since`."""
    # `since` comes from the DB as a naive datetime under PostgreSQL; STIX
    # `modified` parses to tz-aware UTC. Coerce to aware UTC to compare safely.
    if since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    stix_modified: dict[str, str] = {}
    for obj in bundle["objects"]:
        if obj.get("type") == "intrusion-set":
            stix_modified[obj["id"]] = obj.get("modified", "")

    filtered = []
    for mg in mitre_groups:
        mod_str = stix_modified.get(mg["stix_id"], "")
        if not mod_str:
            filtered.append(mg)
            continue
        try:
            mod_dt = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            if mod_dt > since:
                filtered.append(mg)
        except ValueError:
            filtered.append(mg)

    return filtered


def _enrich_from_bundle(bundle: dict, db_url: str) -> dict:
    """Full enrichment from a loaded bundle (legacy path)."""
    mitre_groups = parse_mitre_groups(bundle)
    techniques = parse_mitre_techniques(bundle)
    software = parse_mitre_software(bundle)
    relationships = parse_relationships(bundle)

    log.info(
        "Parsed: %d groups, %d techniques, %d software, %d relationships",
        len(mitre_groups),
        len(techniques),
        len(software),
        len(relationships),
    )

    group_stix_ids = {mg["stix_id"]: mg for mg in mitre_groups}
    group_techs, group_sw, sw_techs = _build_relationship_maps(
        relationships,
        group_stix_ids,
        techniques,
        software,
    )

    session_factory = get_session_factory(db_url)
    stats = _new_stats()

    with session_factory() as session:
        all_groups = session.query(Group).all()
        pest_by_name = {g.group_name.lower(): g for g in all_groups}

        matches = match_groups(mitre_groups, all_groups)
        stats["matched_groups"] = len(matches)

        _enrich_matched_groups(session, matches, group_techs, group_sw, techniques, software, stats)
        _enrich_software_matches(session, software, sw_techs, techniques, pest_by_name, stats)

        session.commit()

    return stats


# "I am better with you, Watson. I'm sharper, I'm more focused." — Sherlock Holmes, Elementary
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    stats = enrich_groups()
    print("\n=== MITRE ATT&CK Enrichment Results ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
