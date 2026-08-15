# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""Whose address is this, tested on the two the live acceptance actually wrote.

Both fixtures below are verbatim from the acceptance run of 2026-08-15, not
invented: one is what the gate got wrong and one is what it got right, and a
rule that cannot tell them apart is not worth having.
"""

import pytest

from pestilentia.ai.enrichment.exclusions import (
    PLATFORM_DOMAINS,
    RentedSpace,
    not_the_adversarys,
    rented_address,
)

# What the gate gave to `warlock`, at a high score, from an anchored quote.
MICROSOFT_CDN = (
    "https://vscode.download.prss.microsoft.com/dbazure/download/insider/"
    "09401e712d4ffa5e497787978fe90c1557a0092b/vscode_cli_win32_x64_cli.zip"
)
# What the gate gave to `chaos`, and was right to.
REAL_C2 = "http://172.86.126.18:443/update_ms.msi"


def test_the_url_that_started_this_is_refused_with_a_reason():
    """The measured defect: an intruder downloading a legitimate tool does not
    make the vendor's distribution network into the intruder's property."""
    reason = not_the_adversarys(MICROSOFT_CDN)

    assert reason, "this is the case the rule exists for"
    assert "Microsoft" in reason


def test_the_indicator_the_gate_was_right_about_survives():
    """An address the adversary stood up is exactly what must get through."""
    assert not_the_adversarys(REAL_C2) == ""


def test_a_leak_site_is_never_excluded():
    """The one address in this domain that genuinely is the group's own.

    An exclusion list that reaches a leak site has removed the best evidence
    there is, which is why the check for it comes before the domain list rather
    than after.
    """
    onion = "http://wlckabcdefghijklmnopqrstuvwxyz234567.onion/leaks"

    assert not_the_adversarys(onion) == ""


@pytest.mark.parametrize(
    "url",
    [
        "https://raw.githubusercontent.com/someone/repo/main/payload.ps1",
        "https://vdfccjpnedujhrzscjtq.supabase.co/storage/v1/object/public/image/v4.msi",
        "https://cdn.discordapp.com/attachments/1/2/loader.exe",
    ],
)
def test_a_rented_platform_is_refused_even_when_it_hosts_the_payload(url):
    """The declared loss, pinned so nobody meets it as a surprise.

    These really are hosting adversary files. They are still refused, because
    the field being written is a permanent property of a group and the account
    behind any of them will be closed by Friday. The indicator itself stays in
    `article_iocs`: what is refused is the promotion, not the fact.
    """
    assert not_the_adversarys(url) != ""


def test_a_subdomain_is_covered_by_its_domain():
    assert not_the_adversarys("https://anything.deep.github.com/x") != ""


def test_a_domain_that_merely_ends_in_the_same_letters_is_not_covered():
    """`notgithub.com` is not GitHub, and a suffix match that thinks so would
    exclude somebody's real infrastructure for looking a bit like a platform."""
    assert not_the_adversarys("https://notgithub.com/payload") == ""


def test_an_unparseable_url_is_not_treated_as_excluded():
    """The default has to be *keep*. A parser that fails on odd input and
    returns 'excluded' would delete evidence whenever an article defangs a URL
    in a way this code did not expect."""
    assert not_the_adversarys("") == ""
    assert not_the_adversarys("not a url at all") == ""


def test_every_entry_says_why_it_is_there():
    """A list with unexplained entries is a list that grows until it is wrong."""
    assert all(reason.strip() for reason in PLATFORM_DOMAINS.values())
    assert len(PLATFORM_DOMAINS) < 60, "short enough that somebody rereads it"


# --- addresses, which come from the published feeds rather than from here ----


def test_an_address_inside_a_published_range_says_nothing_durable():
    reason = rented_address("192.0.2.55", ranges=("192.0.2.0/24",))

    assert "192.0.2.0/24" in reason


def test_an_address_outside_every_range_is_kept():
    assert rented_address("172.86.126.18", ranges=("192.0.2.0/24",)) == ""


def test_a_malformed_range_is_skipped_rather_than_crashing_the_gate():
    """These lists are fetched daily from someone else. One bad line must cost
    that line, not the run."""
    assert rented_address("192.0.2.55", ranges=("nonsense", "192.0.2.0/24")) != ""


def test_something_that_is_not_an_address_is_not_an_address():
    assert rented_address("example.com", ranges=("192.0.2.0/24",)) == ""


# --- the published space, built once and asked often -------------------------


def test_a_server_the_vpn_list_publishes_is_rented():
    """The point of the daily lists: an exit node says nothing about who used it."""
    space = RentedSpace.from_entries(["194.99.105.99", "13.104.0.0/14"])

    assert "rented server" in space.covers("194.99.105.99")
    assert "13.104.0.0/14" in space.covers("13.107.6.152")


def test_the_real_c2_is_not_in_anybody_published_space():
    """The address the gate was right about, held against the actual feeds."""
    space = RentedSpace.from_entries(["194.99.105.99", "13.104.0.0/14"])

    assert space.covers("172.86.126.18") == ""


def test_the_conflict_markers_one_publisher_ships_cost_their_own_lines():
    """Measured, not imagined: the NordVPN file carries six unresolved merge
    markers among twelve thousand rows. Grade A is a claim about who publishes
    a file, never about the file being clean."""
    space = RentedSpace.from_entries(["<<<<<<< HEAD", "194.99.105.99", "=======", ">>>>>>> main"])

    assert space.covers("194.99.105.99") != ""
    assert len(space.exact) == 1


def test_an_empty_space_excludes_nothing_rather_than_everything():
    """A feed that was never fetched and a feed that excludes nothing look the
    same in the output and mean opposite things."""
    assert not RentedSpace()
    assert RentedSpace().covers("194.99.105.99") == ""


def test_a_url_whose_host_is_a_rented_address_is_refused():
    """The two mechanisms meet here: a URL can name its host either way."""
    space = RentedSpace.from_entries(["194.99.105.99"])

    assert not_the_adversarys("http://194.99.105.99:8080/panel", space) != ""
    assert not_the_adversarys(REAL_C2, space) == ""


def test_without_the_feeds_the_gate_refuses_to_enrich_rather_than_promoting_blind(monkeypatch):
    """A missing feed must not read as a clean bill of health.

    The check that cannot run and the check that found nothing write the same
    thing into the database, and only one of them is true. This follows the
    ATT&CK bundle's rule: absent data stops the work rather than degrading it
    into something that looks like work.
    """
    from pestilentia.ai.enrichment import gate

    gate._rented_space.cache_clear()
    monkeypatch.setattr(gate, "load_address_ranges", lambda: ())
    try:
        assert gate._infrastructure_from(None, None) == {}
    finally:
        gate._rented_space.cache_clear()
