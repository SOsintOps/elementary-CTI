"""W10: ATT&CK coverage matrix — kill-chain ordering, scoping, sequential scale."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import Group, GroupTTP
from pestilentia.web.app import ATTACK_TACTIC_ORDER, app


@pytest.fixture
def seeded(monkeypatch, authenticate):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        a = Group(group_name="alpha")
        b = Group(group_name="beta")
        session.add_all([a, b])
        session.flush()
        # T1486 used by both groups; T1190 by one. Impact comes last in the
        # kill chain, Initial Access early — so ordering is observable.
        session.add_all(
            [
                GroupTTP(
                    group_id=a.id,
                    tactic_id="TA0040",
                    tactic_name="Impact",
                    technique_id="T1486",
                    technique_name="Data Encrypted for Impact",
                ),
                GroupTTP(
                    group_id=b.id,
                    tactic_id="TA0040",
                    tactic_name="Impact",
                    technique_id="T1486",
                    technique_name="Data Encrypted for Impact",
                ),
                GroupTTP(
                    group_id=a.id,
                    tactic_id="TA0001",
                    tactic_name="Initial Access",
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                ),
            ]
        )
        session.commit()
        ids = {"alpha": a.id, "beta": b.id}

    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    monkeypatch.setattr(web, "_session_factory", factory)
    client = TestClient(app)
    authenticate(client, factory)
    client.ids = ids
    yield client
    web._session_factory = None
    config._settings = None


def test_matrix_lists_techniques_with_adversary_counts(seeded):
    body = seeded.get("/attack").text
    assert "T1486" in body
    assert "Data Encrypted for Impact" in body
    assert "2 adversaries" in body, "T1486 is used by both groups"


def test_tactics_render_in_kill_chain_order_not_alphabetical(seeded):
    """Alphabetical would put Impact before Initial Access and scramble the story."""
    body = seeded.get("/attack").text
    assert body.index("Initial Access") < body.index("Impact")
    assert ATTACK_TACTIC_ORDER.index("Initial Access") < ATTACK_TACTIC_ORDER.index("Impact")


def test_scoping_to_a_group_hides_other_groups_techniques(seeded):
    body = seeded.get(f"/attack?group_id={seeded.ids['beta']}").text
    assert "T1486" in body
    assert "T1190" not in body, "beta does not use T1190"


def test_unknown_group_is_404(seeded):
    assert seeded.get("/attack?group_id=99999").status_code == 404


def test_empty_matrix_explains_itself(monkeypatch, authenticate):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    monkeypatch.setattr(web, "_session_factory", factory)
    try:
        client = TestClient(app)
        authenticate(client, factory)
        body = client.get("/attack").text
        assert "No ATT&amp;CK techniques recorded" in body  # entity-escaped in HTML
    finally:
        web._session_factory = None
        config._settings = None


def test_absence_is_labelled_as_unobserved_not_unused(seeded):
    """A blank cell means "not seen in our data", which the page must say."""
    body = seeded.get("/attack").text
    assert "non osservata nei nostri dati" in body
