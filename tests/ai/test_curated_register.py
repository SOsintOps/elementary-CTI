# "There is nothing more deceptive than an obvious fact." — Sherlock Holmes
"""The register tells the truth about its own sources, and the readers agree.

Written on 2026-08-15, the day `nordvpn-servers` was found to have been frozen
upstream since March 2024 while its register entry claimed a daily cadence. The
file was byte-identical to upstream, so nothing local was broken and nothing
could have noticed: a stale feed and a stable one are the same bytes. What was
missing was somewhere to write down what the publisher had actually been
observed doing, and a source of address space that had not stopped moving.
"""

import gzip

import pytest

from pestilentia.ai.enrichment.exclusions import RentedSpace
from pestilentia.clients import curated_feeds
from pestilentia.clients.curated_feeds import (
    FEEDS,
    FEEDS_BY_NAME,
    HOSTING_ASNS,
    FeedKind,
    load_asn_ranges,
    load_tor_exit_addresses,
)


def test_every_feed_names_a_licence_somebody_read():
    """The clause that cost a source: no licence, no entry."""
    for feed in FEEDS:
        assert feed.licence.strip(), f"{feed.name} has no licence recorded"


def test_the_dead_feed_admits_it_is_dead():
    frozen = FEEDS_BY_NAME["nordvpn-servers"]
    assert frozen.is_frozen
    assert frozen.frozen_since == "2024-03-04"
    # Asserting on the prose would only test the wording. What must hold is that
    # the freeze is a field a reader can act on, and that the entry no longer
    # asserts a cadence as its warrant.
    assert frozen.warrant.strip() != "Daily."
    assert frozen.frozen_since in frozen.warrant


def test_the_live_feeds_are_not_marked_frozen():
    for name in ("misp-galaxy-threat-actor", "microsoft-ip-ranges", "iptoasn-v4"):
        assert not FEEDS_BY_NAME[name].is_frozen


def test_tor_is_its_own_kind_rather_than_folded_into_rented_space():
    """Both exclude, but they mean different things and the data keeps them apart."""
    assert FEEDS_BY_NAME["tor-exit-addresses"].kind is FeedKind.ANONYMITY_NETWORK
    assert FEEDS_BY_NAME["iptoasn-v4"].kind is FeedKind.INFRASTRUCTURE_CONTEXT


def test_every_curated_asn_carries_its_reason():
    for asn, reason in HOSTING_ASNS.items():
        assert isinstance(asn, int)
        assert len(reason) > 10, f"AS{asn} has no defensible reason written"


def _write_ip2asn(tmp_path, rows):
    path = tmp_path / "ip2asn-v4.tsv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for row in rows:
            handle.write("\t".join(row) + "\n")
    return path


@pytest.fixture
def asn_feed(tmp_path, monkeypatch):
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    return FEEDS_BY_NAME["iptoasn-v4"]


def test_only_the_curated_asns_are_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    _write_ip2asn(
        tmp_path,
        [
            ("1.0.0.0", "1.0.0.255", "13335", "US", "CLOUDFLARENET"),
            ("2.0.0.0", "2.0.0.255", "3269", "IT", "TELECOM ITALIA"),
            ("3.0.0.0", "3.0.0.255", "9009", "RO", "M247"),
            ("4.0.0.0", "4.0.0.255", "0", "None", "Not routed"),
        ],
    )
    spans = load_asn_ranges()
    assert spans == ["1.0.0.0-1.0.0.255", "3.0.0.0-3.0.0.255"]


def test_a_renamed_provider_is_still_matched(tmp_path, monkeypatch):
    """Matching is on the number, so an upstream rewording changes nothing.

    Keying on the description would have failed silently the day someone edited
    it, which is the same class of defect as trusting a folder called Daily.
    """
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    _write_ip2asn(tmp_path, [("3.0.0.0", "3.0.0.255", "9009", "RO", "SOMETHING ELSE ENTIRELY")])
    assert load_asn_ranges() == ["3.0.0.0-3.0.0.255"]


def test_a_missing_asn_file_yields_nothing_rather_than_pretending(tmp_path, monkeypatch):
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    assert load_asn_ranges() == []


def test_tor_exit_addresses_are_read_from_their_own_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    (tmp_path / "tor-exit-addresses.txt").write_text(
        "ExitNode AAAA1111\n"
        "Published 2026-08-15 06:00:00\n"
        "LastStatus 2026-08-15 07:00:00\n"
        "ExitAddress 185.220.101.1 2026-08-15 07:10:00\n"
        "ExitNode BBBB2222\n"
        "ExitAddress 185.220.101.2 2026-08-15 07:20:00\n",
        encoding="utf-8",
    )
    assert load_tor_exit_addresses() == ["185.220.101.1", "185.220.101.2"]


def test_a_span_covers_the_addresses_inside_it_and_no_others():
    space = RentedSpace.from_entries(["3.0.0.0-3.0.0.255"])
    assert space.covers("3.0.0.7")
    assert space.covers("3.0.0.0")
    assert space.covers("3.0.0.255")
    assert not space.covers("3.0.1.0")
    assert not space.covers("2.255.255.255")


def test_spans_addresses_and_prefixes_coexist():
    space = RentedSpace.from_entries(["3.0.0.0-3.0.0.255", "10.1.2.3", "192.0.2.0/24"])
    assert space.covers("3.0.0.9")
    assert space.covers("10.1.2.3")
    assert space.covers("192.0.2.77")
    assert not space.covers("10.1.2.4")


def test_a_reversed_or_mixed_span_is_dropped_rather_than_raised_on():
    space = RentedSpace.from_entries(["3.0.0.255-3.0.0.0", "1.2.3.4-::1", "not-an-address"])
    assert not space


def test_the_bisection_finds_the_right_span_among_many():
    """A linear scan would pass this too; the point is that bisection agrees."""
    spans = [f"{n}.0.0.0-{n}.0.0.255" for n in range(1, 200)]
    space = RentedSpace.from_entries(spans)
    assert space.covers("7.0.0.1")
    assert space.covers("199.0.0.254")
    assert not space.covers("7.0.1.1")
    assert not space.covers("200.0.0.1")


def test_an_ipv6_address_is_not_matched_against_an_ipv4_span():
    space = RentedSpace.from_entries(["0.0.0.1-255.255.255.255"])
    assert not space.covers("2001:db8::1")


def test_a_frozen_feed_is_not_read_as_current_exclusion_data(tmp_path, monkeypatch):
    """The contradiction this guard removes, caught in the act.

    On 2026-08-15 the register was corrected to call `nordvpn-servers` a point
    observation of March 2024 while `load_address_ranges` went on feeding its
    6,135 addresses into live exclusion decisions. Documentation that describes
    a behaviour the code does not have is worse than no documentation, because
    it is believed.
    """
    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    frozen = FEEDS_BY_NAME["nordvpn-servers"]
    live = FEEDS_BY_NAME["microsoft-ip-ranges"]
    assert frozen.is_frozen and not live.is_frozen

    frozen.path.write_text("id,ip_address\n1,203.0.113.7\n", encoding="utf-8")
    live.path.write_text("prefix\n198.51.100.0/24\n", encoding="utf-8")

    entries = curated_feeds.load_address_ranges()
    assert "198.51.100.0/24" in entries, "a live feed must still be read"
    assert "203.0.113.7" not in entries, "a frozen feed must not reach live exclusion"


def test_the_rule_is_on_the_field_and_not_on_the_feed_name(tmp_path, monkeypatch):
    """Freezing any feed is enough; nobody has to remember to edit the reader."""
    import dataclasses

    monkeypatch.setattr(curated_feeds, "FEED_DIR", tmp_path)
    live = FEEDS_BY_NAME["microsoft-ip-ranges"]
    live.path.write_text("prefix\n198.51.100.0/24\n", encoding="utf-8")
    assert "198.51.100.0/24" in curated_feeds.load_address_ranges()

    newly_frozen = dataclasses.replace(live, frozen_since="2026-01-01")
    monkeypatch.setitem(curated_feeds.FEEDS_BY_NAME, live.name, newly_frozen)
    assert "198.51.100.0/24" not in curated_feeds.load_address_ranges()
