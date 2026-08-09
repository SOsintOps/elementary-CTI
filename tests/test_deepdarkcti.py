"""ME-05 regression: a total fetch failure must not mark the enrichment as done."""

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pestilentia.clients.deepdarkcti as dd
from pestilentia.clients.deepdarkcti import (
    DEEPDARK_CATEGORY,
    enrich_deepdarkcti,
)
from pestilentia.models import Base, InfoUpdate


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _last_enrichment(session):
    row = session.query(InfoUpdate).filter_by(category=DEEPDARK_CATEGORY).first()
    return row.last_update_json if row else None


def test_all_files_failing_does_not_set_timestamp(monkeypatch):
    # Simulate a total network/DNS outage: every file fetch raises.
    def boom(url):
        raise httpx.ConnectError("network down")

    monkeypatch.setattr(dd, "_fetch_markdown", boom)
    session = _session()

    enrich_deepdarkcti(session)

    assert _last_enrichment(session) is None  # must retry next cycle, not in a week


def test_partial_success_sets_timestamp(monkeypatch):
    # One file parses, the others fail -> enrichment counts as done.
    def one_ok(url):
        if "ransomware_gang" in url:
            return "| Name | URL | Status |\n|---|---|---|\n"
        raise httpx.ConnectError("network down")

    monkeypatch.setattr(dd, "_fetch_markdown", one_ok)
    session = _session()

    enrich_deepdarkcti(session)

    assert _last_enrichment(session) is not None
