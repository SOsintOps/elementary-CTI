# "The criminal mind is a complex one." — Sherlock Holmes, Elementary
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pestilentia.models.base import Base


class DataSource(Base):
    __tablename__ = "data_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class Country(Base):
    __tablename__ = "countries"

    id: Mapped[int] = mapped_column(primary_key=True)
    iso_code: Mapped[str] = mapped_column(String(5), unique=True, nullable=False)
    country_name: Mapped[str | None] = mapped_column(String(100))
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)


# "I'm not a detective. I'm a consulting detective." — Sherlock Holmes, Elementary
class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_hacktivist: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    parser: Mapped[bool | None] = mapped_column(Boolean)
    meta: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    aliases: Mapped[str | None] = mapped_column(Text)
    country_of_origin: Mapped[str | None] = mapped_column(String(5))
    group_type: Mapped[str | None] = mapped_column(String(100))
    extensions: Mapped[str | None] = mapped_column(Text)
    lineage: Mapped[str | None] = mapped_column(Text)
    btc_addresses: Mapped[str | None] = mapped_column(Text)
    profile_urls: Mapped[str | None] = mapped_column(Text)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("data_sources.id"))

    locations: Mapped[list["GroupLocation"]] = relationship(back_populates="group")
    tools: Mapped[list["GroupTool"]] = relationship(back_populates="group")
    ttps: Mapped[list["GroupTTP"]] = relationship(back_populates="group")
    references: Mapped[list["GroupReference"]] = relationship(back_populates="group")
    source: Mapped[DataSource | None] = relationship()
    btc_txs: Mapped[list["GroupBtcTransaction"]] = relationship(back_populates="group")
    comms: Mapped[list["GroupComm"]] = relationship(back_populates="group")


class GroupLocation(Base):
    __tablename__ = "group_locations"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"))
    fqdn: Mapped[str | None] = mapped_column(Text)
    slug: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(String(100))
    type: Mapped[str | None] = mapped_column(String(50))
    available: Mapped[bool | None] = mapped_column(Boolean)
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    lastscrape: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    group: Mapped[Group] = relationship(back_populates="locations")


class GroupTool(Base):
    __tablename__ = "group_tools"
    __table_args__ = (UniqueConstraint("group_id", "category", "tool_name", name="uq_group_tool"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"))
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)

    group: Mapped[Group] = relationship(back_populates="tools")


class GroupTTP(Base):
    __tablename__ = "group_ttps"
    __table_args__ = (UniqueConstraint("group_id", "technique_id", name="uq_group_ttp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"))
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=False)
    tactic_name: Mapped[str] = mapped_column(String(100), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False)
    technique_details: Mapped[str | None] = mapped_column(Text)

    group: Mapped[Group] = relationship(back_populates="ttps")


class GroupReference(Base):
    __tablename__ = "group_references"
    __table_args__ = (UniqueConstraint("group_id", "url", name="uq_group_ref"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"))
    url: Mapped[str] = mapped_column(String(500), nullable=False)

    group: Mapped[Group] = relationship(back_populates="references")


class Cert(Base):
    __tablename__ = "certs"

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[str | None] = mapped_column(String(100), unique=True)
    team_name: Mapped[str | None] = mapped_column(String(200))
    team_full: Mapped[str | None] = mapped_column(String(300))
    email: Mapped[str | None] = mapped_column(String(200))
    website: Mapped[str | None] = mapped_column(String(300))
    source: Mapped[str | None] = mapped_column(String(50))
    country_id: Mapped[int | None] = mapped_column(ForeignKey("countries.id"))
    data_source_id: Mapped[int | None] = mapped_column(ForeignKey("data_sources.id"))

    constituencies: Mapped[list["CertConstituency"]] = relationship(back_populates="cert")


class CertConstituency(Base):
    __tablename__ = "certs_constituency"

    id: Mapped[int] = mapped_column(primary_key=True)
    cert_id: Mapped[int] = mapped_column(ForeignKey("certs.id"))
    value: Mapped[str | None] = mapped_column(String(200))

    cert: Mapped[Cert] = relationship(back_populates="constituencies")


# "I have every confidence in your ability." — Joan Watson, Elementary
class Victim(Base):
    __tablename__ = "victims"
    __table_args__ = (UniqueConstraint("domain", "attackdate", name="uq_victim_domain_date"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_name: Mapped[str | None] = mapped_column(String(300))
    domain: Mapped[str | None] = mapped_column(String(300))
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"))
    country_id: Mapped[int | None] = mapped_column(ForeignKey("countries.id"))
    attackdate: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claim_url: Mapped[str | None] = mapped_column(Text)
    screenshot: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    activity: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("data_sources.id"))

    group: Mapped[Group | None] = relationship()
    country: Mapped[Country | None] = relationship()
    source: Mapped[DataSource | None] = relationship()
    duplicates: Mapped[list["VictimDuplicate"]] = relationship(back_populates="victim")
    infostealer: Mapped["VictimInfostealer | None"] = relationship(back_populates="victim")
    press: Mapped[list["VictimPress"]] = relationship(back_populates="victim")
    updates: Mapped[list["VictimUpdate"]] = relationship(back_populates="victim")
    organizations: Mapped[list["VictimOrganization"]] = relationship(back_populates="victim")


class VictimDuplicate(Base):
    __tablename__ = "victim_duplicates"

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    dup_attackdate: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dup_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dup_group: Mapped[str | None] = mapped_column(String(100))
    dup_link: Mapped[str | None] = mapped_column(Text)

    victim: Mapped[Victim] = relationship(back_populates="duplicates")


class VictimInfostealer(Base):
    __tablename__ = "victim_infostealer"

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    employees: Mapped[int | None] = mapped_column(Integer)
    employees_url: Mapped[int | None] = mapped_column(Integer)
    thirdparties: Mapped[int | None] = mapped_column(Integer)
    thirdparties_domain: Mapped[int | None] = mapped_column(Integer)
    users: Mapped[int | None] = mapped_column(Integer)
    users_url: Mapped[int | None] = mapped_column(Integer)
    last_update: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    victim: Mapped[Victim] = relationship(back_populates="infostealer")


class VictimPress(Base):
    __tablename__ = "victim_press"

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    press_link: Mapped[str | None] = mapped_column(Text)
    press_source: Mapped[str | None] = mapped_column(Text)
    press_summary: Mapped[str | None] = mapped_column(Text)

    victim: Mapped[Victim] = relationship(back_populates="press")


class VictimUpdate(Base):
    __tablename__ = "victim_updates"

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    update_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    update_description: Mapped[str | None] = mapped_column(Text)
    update_link: Mapped[str | None] = mapped_column(Text)

    victim: Mapped[Victim] = relationship(back_populates="updates")


class Cyberattack(Base):
    __tablename__ = "cyberattacks"
    __table_args__ = (
        UniqueConstraint("victim_name", "attack_date", name="uq_cyberattack_victim_date"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_name: Mapped[str | None] = mapped_column(String(300))
    domain: Mapped[str | None] = mapped_column(String(300))
    country: Mapped[str | None] = mapped_column(String(50))
    attack_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    title: Mapped[str | None] = mapped_column(String(300))
    summary: Mapped[str | None] = mapped_column(Text)
    article_url: Mapped[str | None] = mapped_column(String(500))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("data_sources.id"))

    source: Mapped[DataSource | None] = relationship()


class InfoUpdate(Base):
    """Generic per-category state rows, discriminated by ``category``.

    Known category namespaces (ME-10 — keep lookups exact-match, never LIKE,
    since related categories share prefixes, e.g. ``mitre_*``):
    - ``mitre_enrichment`` / ``ransomwhere_enrichment`` / ``deepdarkcti_enrichment``
      / ``ai_articles_enrichment``
      — last-run timestamp of each enrichment (``last_update_json``)
    - ``mitre_enabled`` / ``ransomwhere_enabled`` / ``deepdarkcti_enabled``
      / ``articles_enabled``
      — feature toggles (``number``: 1/0; missing row = enabled)
    - ``watchlist_victim_hwm`` / ``watchlist_target_hwm`` — incremental
      fuzzy-scan high-water marks (``number``, HI-09)
    - per-source feed categories — last-update timestamps per feed format
    """

    __tablename__ = "info_updates"

    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str | None] = mapped_column(String(50))
    last_update_rss: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_update_json: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_update_csv: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    number: Mapped[int | None] = mapped_column(Integer)


class SourceHealth(Base):
    __tablename__ = "source_health"
    __table_args__ = (UniqueConstraint("source_name", name="uq_source_health"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown")  # ok, degraded, down
    last_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ok: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    http_status: Mapped[int | None] = mapped_column(Integer)
    row_count: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    format_valid: Mapped[bool | None] = mapped_column(Boolean)


class ManualOverride(Base):
    __tablename__ = "manual_overrides"

    id: Mapped[int] = mapped_column(primary_key=True)
    original_name: Mapped[str | None] = mapped_column(String(300))
    original_domain: Mapped[str | None] = mapped_column(String(300))
    matched_name: Mapped[str | None] = mapped_column(String(300))
    matched_domain: Mapped[str | None] = mapped_column(String(300))
    similarity_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    similarity_level: Mapped[str | None] = mapped_column(String(50))
    approved: Mapped[bool | None] = mapped_column(Boolean)
    analyst_id: Mapped[int | None] = mapped_column(Integer)
    override_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    comments: Mapped[str | None] = mapped_column(Text)


# --- ADR-004: Company enrichment tables ---


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    legal_name: Mapped[str | None] = mapped_column(String(300))
    display_name: Mapped[str | None] = mapped_column(String(300))
    domain: Mapped[str | None] = mapped_column(String(300), unique=True)
    lei: Mapped[str | None] = mapped_column(String(20), unique=True)
    sector: Mapped[str | None] = mapped_column(String(100))
    country_id: Mapped[int | None] = mapped_column(ForeignKey("countries.id"))
    employee_count: Mapped[int | None] = mapped_column(Integer)
    gleif_id: Mapped[str | None] = mapped_column(String(50))
    wikidata_id: Mapped[str | None] = mapped_column(String(20))
    opencorporates_id: Mapped[str | None] = mapped_column(String(100))
    enrichment_source: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC)
    )

    country: Mapped[Country | None] = relationship()
    identifiers: Mapped[list["OrganizationIdentifier"]] = relationship(
        back_populates="organization"
    )


class OrganizationIdentifier(Base):
    __tablename__ = "organization_identifiers"

    id: Mapped[int] = mapped_column(primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    identifier_type: Mapped[str | None] = mapped_column(String(50))
    identifier_value: Mapped[str | None] = mapped_column(String(100))
    source: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    organization: Mapped[Organization] = relationship(back_populates="identifiers")


class VictimOrganization(Base):
    __tablename__ = "victim_organizations"
    __table_args__ = (UniqueConstraint("victim_id", "organization_id", name="uq_victim_org"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    match_method: Mapped[str | None] = mapped_column(String(50))
    match_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    victim: Mapped[Victim] = relationship(back_populates="organizations")
    organization: Mapped[Organization] = relationship()


class GroupBtcTransaction(Base):
    __tablename__ = "group_btc_transactions"
    __table_args__ = (UniqueConstraint("address", "tx_hash", name="uq_btc_tx"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    address: Mapped[str] = mapped_column(String(100), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    amount_btc: Mapped[float | None] = mapped_column(Numeric(18, 8))
    amount_usd: Mapped[float | None] = mapped_column(Numeric(14, 2))
    tx_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(50), default="ransomwhere")

    group: Mapped[Group] = relationship(back_populates="btc_txs")


class GroupComm(Base):
    __tablename__ = "group_comms"
    __table_args__ = (
        UniqueConstraint("group_id", "channel_type", "channel_value", name="uq_group_comm"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    channel_value: Mapped[str] = mapped_column(String(500), nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="deepdarkcti")

    group: Mapped[Group] = relationship(back_populates="comms")


class GroupSourceData(Base):
    __tablename__ = "group_source_data"
    __table_args__ = (UniqueConstraint("group_name", "source_id", name="uq_group_source"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    raw_data: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    source: Mapped[DataSource] = relationship()


class GroupSourceHistory(Base):
    """Superseded versions of group_source_data rows (evidence history).

    When a source's payload for a group *changes*, the previous version is
    archived here before being replaced — adversary self-descriptions evolve
    and the history is itself intelligence.
    """

    __tablename__ = "group_source_history"
    __table_args__ = (Index("ix_gsh_group_source", "group_name", "source_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    raw_data: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    superseded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


# "Nothing is more important than an unsolved case." — Sherlock Holmes, Elementary
class Watchlist(Base):
    __tablename__ = "watchlist"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(300))
    keywords: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    watchlist_id: Mapped[int] = mapped_column(ForeignKey("watchlist.id", ondelete="CASCADE"))
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id", ondelete="CASCADE"))
    match_field: Mapped[str] = mapped_column(String(50), nullable=False)
    seen: Mapped[bool] = mapped_column(Boolean, default=False)
    # "Seen" is not "acted on" (migration 0013). The SANS 2026 gap — 91% call
    # CTI valuable, 26% say it changes a decision — is unmeasurable without
    # recording whether an alert ever led to one.
    actioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    watchlist: Mapped[Watchlist] = relationship()
    victim: Mapped[Victim] = relationship()


class NotificationSubscription(Base):
    __tablename__ = "notification_subscriptions"
    __table_args__ = (UniqueConstraint("channel", "config_key", name="uq_notif_sub"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    channel: Mapped[str] = mapped_column(String(50), nullable=False)
    config_key: Mapped[str] = mapped_column(String(200), nullable=False)
    config_value: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class EnrichmentReview(Base):
    __tablename__ = "enrichment_review"

    id: Mapped[int] = mapped_column(primary_key=True)
    victim_id: Mapped[int] = mapped_column(ForeignKey("victims.id"))
    candidate_org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    match_method: Mapped[str | None] = mapped_column(String(50))
    match_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    enrichment_source: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    comments: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


# --- ADR-006 §5: AI pipeline tables (Phase 1) ---
# "Every piece of evidence tells a story." — Sherlock Holmes, Elementary


class ArticleSource(Base):
    __tablename__ = "article_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, default="rss")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    trust_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    default_tlp: Mapped[str] = mapped_column(String(16), nullable=False, default="clear")
    share_with_third_party: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cadence_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    articles: Mapped[list["Article"]] = relationship(back_populates="source")
    # Conditional GET (migration 0013). Opaque validator strings straight from
    # the upstream response — never parsed, only echoed back.
    etag: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Article(Base):
    __tablename__ = "articles"
    __table_args__ = (
        UniqueConstraint("url_canonical_hash", name="uq_article_url_hash"),
        Index("ix_article_source_id", "source_id"),
        Index("ix_article_published_at", "published_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("article_sources.id", ondelete="SET NULL"), nullable=True
    )
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    url_canonical_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_simhash: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    tlp: Mapped[str] = mapped_column(String(16), nullable=False, default="clear")
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    summary_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    article_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    source: Mapped["ArticleSource | None"] = relationship(back_populates="articles")
    # NOT NULL FKs with DB-level ON DELETE CASCADE: delete-orphan keeps in-session
    # semantics consistent; passive_deletes lets the database cascade do the work
    # instead of SQLAlchemy emitting UPDATE ... SET article_id = NULL.
    analysis_runs: Mapped[list["ArticleAnalysisRun"]] = relationship(
        back_populates="article", cascade="all, delete-orphan", passive_deletes=True
    )
    audit_rows: Mapped[list["AiEnrichmentAudit"]] = relationship(
        back_populates="article", cascade="all, delete-orphan", passive_deletes=True
    )


class ArticleAnalysisRun(Base):
    __tablename__ = "article_analysis_runs"
    __table_args__ = (
        UniqueConstraint("article_id", "state", name="uq_run_article_state"),
        Index("ix_run_article_status", "article_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    article_id: Mapped[int] = mapped_column(
        ForeignKey("articles.id", ondelete="CASCADE"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    model_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    usd_cost: Mapped[float | None] = mapped_column(Numeric(10, 6), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_output_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    article: Mapped["Article"] = relationship(back_populates="analysis_runs")


class LlmCallLog(Base):
    __tablename__ = "llm_call_logs"
    __table_args__ = (
        Index("ix_llmlog_provider_month", "provider_name", "year_month"),
        Index("ix_llmlog_article", "article_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    article_id: Mapped[int | None] = mapped_column(
        ForeignKey("articles.id", ondelete="SET NULL"), nullable=True
    )
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("article_analysis_runs.id", ondelete="SET NULL"), nullable=True
    )
    provider_name: Mapped[str] = mapped_column(String(50), nullable=False)
    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    year_month: Mapped[str] = mapped_column(String(7), nullable=False)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    usd_cost: Mapped[float] = mapped_column(Numeric(10, 6), nullable=False, default=0.0)
    state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )


class AiEnrichmentAudit(Base):
    __tablename__ = "ai_enrichment_audit"
    __table_args__ = (
        Index("ix_aieaud_target", "table_name", "row_id", "created_at"),
        Index("ix_aieaud_decision", "decision", "created_at"),
        Index("ix_aieaud_article", "article_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    article_id: Mapped[int] = mapped_column(
        ForeignKey("articles.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("article_analysis_runs.id", ondelete="SET NULL"), nullable=True
    )
    table_name: Mapped[str] = mapped_column(String(64), nullable=False)
    row_id: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    before_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    tlp: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    article: Mapped["Article"] = relationship(back_populates="audit_rows")


class GroupAliasProposal(Base):
    __tablename__ = "group_alias_proposals"
    __table_args__ = (
        Index("ix_aliasprop_group", "group_id"),
        Index("ix_aliasprop_status", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int | None] = mapped_column(
        ForeignKey("groups.id", ondelete="SET NULL"), nullable=True
    )
    article_id: Mapped[int] = mapped_column(
        ForeignKey("articles.id", ondelete="CASCADE"), nullable=False
    )
    proposed_alias: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    theme: Mapped[str] = mapped_column(String(16), nullable=False, default="light")
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AdminAudit(Base):
    __tablename__ = "admin_audit"
    __table_args__ = (
        Index("ix_admaud_ts", "ts"),
        Index("ix_admaud_action", "action", "ts"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    # actor_name is a snapshot: audit rows must survive the deletion of the actor.
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_name: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(2048), nullable=True)


class UserActivity(Base):
    __tablename__ = "user_activity"
    __table_args__ = (
        Index("ix_useract_ts", "ts"),
        Index("ix_useract_actor", "actor_id", "ts"),
        Index("ix_useract_kind", "kind", "ts"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    # NULL actor_id + NULL actor_name = anonymous request (e.g. denied attempt).
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    route: Mapped[str | None] = mapped_column(String(256), nullable=True)
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
