from datetime import datetime

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.models import (
    AiEnrichmentAudit,
    ArticleSource,
    Base,
    Country,
    Cyberattack,
    DataSource,
    EnrichmentReview,
    Group,
    Organization,
    OrganizationIdentifier,
    Victim,
    VictimDuplicate,
    VictimOrganization,
)


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


EXPECTED_TABLES = [
    "data_sources",
    "countries",
    "groups",
    "group_locations",
    "certs",
    "certs_constituency",
    "victims",
    "victim_duplicates",
    "victim_infostealer",
    "victim_press",
    "victim_updates",
    "cyberattacks",
    "info_updates",
    "manual_overrides",
    "organizations",
    "organization_identifiers",
    "victim_organizations",
    "enrichment_review",
    "article_sources",
    "articles",
    "article_analysis_runs",
    "llm_call_logs",
    "ai_enrichment_audit",
    "group_alias_proposals",
]


def test_all_tables_created(engine):
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    for expected in EXPECTED_TABLES:
        assert expected in tables, f"Missing table: {expected}"


def test_insert_victim(session):
    source = DataSource(source_name="ransomware.live", base_url="https://api.ransomware.live")
    session.add(source)
    session.flush()

    country = Country(iso_code="US", country_name="United States")
    session.add(country)
    session.flush()

    group = Group(group_name="lockbit", source_id=source.id)
    session.add(group)
    session.flush()

    victim = Victim(
        victim_name="acme-corp",
        domain="acme.com",
        group_id=group.id,
        country_id=country.id,
        attackdate=datetime(2026, 1, 15),
        discovered=datetime(2026, 1, 16),
        source_id=source.id,
    )
    session.add(victim)
    session.commit()

    result = session.query(Victim).filter_by(domain="acme.com").one()
    assert result.victim_name == "acme-corp"
    assert result.group.group_name == "lockbit"
    assert result.country.iso_code == "US"
    assert result.source.source_name == "ransomware.live"


def test_duplicate_victim_rejected(session):
    victim1 = Victim(
        victim_name="acme-corp",
        domain="acme.com",
        attackdate=datetime(2026, 1, 15),
    )
    session.add(victim1)
    session.commit()

    victim2 = Victim(
        victim_name="acme-corp",
        domain="acme.com",
        attackdate=datetime(2026, 1, 15),
    )
    session.add(victim2)
    with pytest.raises(IntegrityError):
        session.commit()


def test_victim_duplicate_tracking(session):
    victim = Victim(victim_name="acme-corp", domain="acme.com", attackdate=datetime(2026, 1, 15))
    session.add(victim)
    session.flush()

    dup = VictimDuplicate(
        victim_id=victim.id,
        dup_attackdate=datetime(2026, 1, 15),
        dup_group="blackcat",
        dup_link="http://onion.example",
    )
    session.add(dup)
    session.commit()

    result = session.query(Victim).one()
    assert len(result.duplicates) == 1
    assert result.duplicates[0].dup_group == "blackcat"


def test_insert_cyberattack(session):
    attack = Cyberattack(
        victim_name="globex",
        domain="globex.com",
        country="DE",
        attack_date=datetime(2026, 2, 1),
        title="Globex hit",
    )
    session.add(attack)
    session.commit()

    result = session.query(Cyberattack).one()
    assert result.victim_name == "globex"
    assert result.attack_date.year == 2026


def test_organization_enrichment(session):
    org = Organization(
        legal_name="Acme Corporation",
        display_name="Acme Corp",
        domain="acme.com",
        lei="529900T8BM49AURSDO55",
        sector="Manufacturing",
        enrichment_source="gleif",
    )
    session.add(org)
    session.flush()

    ident = OrganizationIdentifier(
        organization_id=org.id,
        identifier_type="LEI",
        identifier_value="529900T8BM49AURSDO55",
        source="gleif",
    )
    session.add(ident)
    session.commit()

    result = session.query(Organization).one()
    assert result.lei == "529900T8BM49AURSDO55"
    assert len(result.identifiers) == 1


def test_victim_organization_link(session):
    victim = Victim(victim_name="acme-corp", domain="acme.com", attackdate=datetime(2026, 1, 15))
    org = Organization(legal_name="Acme Corporation", domain="acme.com")
    session.add_all([victim, org])
    session.flush()

    link = VictimOrganization(
        victim_id=victim.id,
        organization_id=org.id,
        match_method="domain_exact",
        match_score=100.0,
    )
    session.add(link)
    session.commit()

    result = session.query(Victim).one()
    assert len(result.organizations) == 1
    assert result.organizations[0].match_method == "domain_exact"


def test_enrichment_review(session):
    victim = Victim(victim_name="acme-corp", domain="acme.com", attackdate=datetime(2026, 1, 15))
    org = Organization(legal_name="Acme Inc", domain="acmeinc.com")
    session.add_all([victim, org])
    session.flush()

    review = EnrichmentReview(
        victim_id=victim.id,
        candidate_org_id=org.id,
        match_method="fuzzy_name",
        match_score=82.5,
        enrichment_source="gleif",
        status="pending",
    )
    session.add(review)
    session.commit()

    result = session.query(EnrichmentReview).one()
    assert result.status == "pending"
    assert result.match_score == 82.5


def test_sqlite_and_postgresql_url():
    sqlite_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(sqlite_engine)
    inspector = inspect(sqlite_engine)
    assert "victims" in inspector.get_table_names()


def test_get_engine_is_memoized_per_url(tmp_path):
    from pestilentia.models.base import dispose_engines, get_engine

    dispose_engines()
    url_a = f"sqlite:///{tmp_path / 'a.db'}"
    url_b = f"sqlite:///{tmp_path / 'b.db'}"
    assert get_engine(url_a) is get_engine(url_a)
    assert get_engine(url_a) is not get_engine(url_b)
    dispose_engines()


def test_sqlite_engine_enables_wal(tmp_path):
    from pestilentia.models.base import dispose_engines, get_engine

    dispose_engines()
    engine = get_engine(f"sqlite:///{tmp_path / 'wal.db'}")
    with engine.connect() as conn:
        mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar()
    assert mode == "wal"
    dispose_engines()


def test_insert_article_source(session):
    source = ArticleSource(
        name="Krebs on Security",
        url="https://krebsonsecurity.com/feed/",
        source_type="rss",
    )
    session.add(source)
    session.commit()

    result = session.query(ArticleSource).one()
    assert result.name == "Krebs on Security"
    assert result.default_tlp == "clear"
    assert result.share_with_third_party is True
    assert result.trust_weight == 0.5


def test_ai_enrichment_audit_is_distinct_table(session):
    # SC-2: ai_enrichment_audit is a separate table distinct from enrichment_review
    assert "ai_enrichment_audit" in EXPECTED_TABLES
    # AiEnrichmentAudit has NO victim_id (that belongs to EnrichmentReview)
    assert not hasattr(AiEnrichmentAudit, "victim_id")
    # AiEnrichmentAudit has AI-audit-specific attributes
    assert hasattr(AiEnrichmentAudit, "table_name")
    assert hasattr(AiEnrichmentAudit, "row_id")
    assert hasattr(AiEnrichmentAudit, "before_json")
    assert hasattr(AiEnrichmentAudit, "after_json")
    assert hasattr(AiEnrichmentAudit, "confidence")
