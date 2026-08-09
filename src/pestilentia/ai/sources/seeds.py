# "I never guess. It is a shocking habit." — Sherlock Holmes, Elementary
"""Curated article-source seed (Phase 2, user-approved 2026-06-12).

Selection is data-driven: ranked by how often each vendor appears in our
adversaries' group_references (CISA 27, DFIR Report 19, Talos/Microsoft 8...).
All feeds live-verified. Public sources → TLP clear.
"""

from sqlalchemy.orm import Session

from pestilentia.models.tables import ArticleSource

SEED_SOURCES: list[dict] = [
    {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "trust_weight": 0.9,
        "cadence_hours": 6,
    },
    {
        "name": "The DFIR Report",
        "url": "https://thedfirreport.com/feed/",
        "trust_weight": 0.9,
        "cadence_hours": 12,
    },
    {
        "name": "Unit 42 (Palo Alto Networks)",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "trust_weight": 0.85,
        "cadence_hours": 12,
    },
    {
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "trust_weight": 0.85,
        "cadence_hours": 12,
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "trust_weight": 0.8,
        "cadence_hours": 12,
    },
    {
        "name": "SentinelLABS",
        "url": "https://www.sentinelone.com/labs/feed/",
        "trust_weight": 0.85,
        "cadence_hours": 12,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "trust_weight": 0.6,
        "cadence_hours": 4,
    },
    {
        "name": "The Record (Recorded Future News)",
        "url": "https://therecord.media/feed",
        "trust_weight": 0.6,
        "cadence_hours": 4,
    },
    # --- Second wave (2026-08-07). Every URL probed live before adding;
    # Sophos redirects to a 404 and Mandiant/Google serve HTML rather than a
    # feed, so neither is here despite being on the original shortlist. ---
    {
        "name": "WeLiveSecurity (ESET)",
        "url": "https://www.welivesecurity.com/en/rss/feed/",
        "trust_weight": 0.85,
        "cadence_hours": 4,
    },
    {
        "name": "Trend Micro Research",
        "url": "https://feeds.feedburner.com/TrendMicroResearch",
        "trust_weight": 0.85,
        "cadence_hours": 4,
    },
    {
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/",
        "trust_weight": 0.85,
        "cadence_hours": 4,
    },
    {
        "name": "Securelist (Kaspersky GReAT)",
        "url": "https://securelist.com/feed/",
        "trust_weight": 0.85,
        "cadence_hours": 4,
    },
]


def seed_article_sources(session: Session) -> int:
    """Insert missing seed sources (idempotent by name). Returns rows added."""
    added = 0
    for spec in SEED_SOURCES:
        if session.query(ArticleSource).filter_by(name=spec["name"]).first():
            continue
        session.add(
            ArticleSource(
                name=spec["name"],
                url=spec["url"],
                source_type="rss",
                default_tlp="clear",
                trust_weight=spec["trust_weight"],
                cadence_hours=spec["cadence_hours"],
            )
        )
        added += 1
    return added
