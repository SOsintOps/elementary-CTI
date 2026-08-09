"""Evidence storage: change-detection upsert + history archiving."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.models import DataSource
from pestilentia.models.base import Base
from pestilentia.models.tables import GroupSourceData, GroupSourceHistory
from pestilentia.pipeline.source_evidence import get_or_create_source, upsert_source_evidence


def _setup_db() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_first_payload_is_stored():
    factory = _setup_db()
    with factory() as session:
        ds = get_or_create_source(session, "testsource")
        assert upsert_source_evidence(session, "lockbit", ds.id, '{"v": 1}') is True
        session.commit()
        assert session.query(GroupSourceData).count() == 1
        assert session.query(GroupSourceHistory).count() == 0


def test_unchanged_payload_is_skipped():
    factory = _setup_db()
    with factory() as session:
        ds = get_or_create_source(session, "testsource")
        upsert_source_evidence(session, "lockbit", ds.id, '{"v": 1}')
        session.commit()
        first_fetch = session.query(GroupSourceData).one().fetched_at

        assert upsert_source_evidence(session, "lockbit", ds.id, '{"v": 1}') is False
        session.commit()
        row = session.query(GroupSourceData).one()
        assert row.fetched_at == first_fetch
        assert session.query(GroupSourceHistory).count() == 0


def test_changed_payload_archives_previous_version():
    factory = _setup_db()
    with factory() as session:
        ds = get_or_create_source(session, "testsource")
        upsert_source_evidence(session, "lockbit", ds.id, '{"v": 1}')
        session.commit()

        assert upsert_source_evidence(session, "lockbit", ds.id, '{"v": 2}') is True
        session.commit()

        current = session.query(GroupSourceData).one()
        assert current.raw_data == '{"v": 2}'
        archived = session.query(GroupSourceHistory).one()
        assert archived.raw_data == '{"v": 1}'
        assert archived.group_name == "lockbit"
        assert archived.superseded_at is not None


def test_get_or_create_source_is_idempotent():
    factory = _setup_db()
    with factory() as session:
        a = get_or_create_source(session, "MITRE ATT&CK", "https://attack.mitre.org")
        b = get_or_create_source(session, "MITRE ATT&CK")
        assert a.id == b.id
        assert session.query(DataSource).filter_by(source_name="MITRE ATT&CK").count() == 1
