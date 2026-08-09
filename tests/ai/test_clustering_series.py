"""A4: the recurring-series guard, and backend selection.

A3 measured that both vectorisers merge a publisher's recurring column into one
"campaign", and that embeddings make it worse rather than better. These tests
pin the guard that fixes it — and, just as importantly, pin the case the guard
must NOT catch.
"""

from __future__ import annotations

import pytest

from pestilentia.ai.sources.clustering import (
    MIN_SERIES_LENGTH,
    cluster_articles,
    select_backend,
    series_key,
    series_suppression_keys,
)


class _Article:
    def __init__(self, title, body=None, source=None):
        self.title = title
        self.body = body
        self.source = type("Source", (), {"name": source})() if source else None


def test_dated_instalments_share_one_key():
    """Titles from Check Point's weekly bulletin on the live corpus
    (en dash written as ASCII; the punctuation strip treats them alike)."""
    assert series_key("3rd August - Threat Intelligence Report") == series_key(
        "27th July - Threat Intelligence Report"
    )


def test_month_and_year_are_stripped():
    """WeLiveSecurity's monthly column, as it appears on the corpus."""
    assert series_key(
        "This month in security with Tony Anscombe - June 2026 edition"
    ) == series_key("This month in security with Tony Anscombe - April 2026 edition")


def test_singular_and_plural_counts_agree():
    """CISA alternates 'One Known Exploited Vulnerability' with 'Three ...
    Vulnerabilities'; a template match has to survive both."""
    assert series_key("CISA Adds One Known Exploited Vulnerability to Catalog") == series_key(
        "CISA Adds Three Known Exploited Vulnerabilities to Catalog"
    )


def test_different_incidents_keep_different_keys():
    assert series_key("Akira ransomware hits a manufacturer") != series_key(
        "ChainDrop npm worm spreads through CI"
    )


def test_a_series_needs_three_instalments():
    """Two same-source lookalikes are not yet cadence."""
    titles = ["1st June - Weekly Report", "8th June - Weekly Report"]
    keys = series_suppression_keys(["Check Point"] * 2, titles)
    assert keys == [None, None]

    titles.append("15th June - Weekly Report")
    keys = series_suppression_keys(["Check Point"] * 3, titles)
    assert all(key is not None for key in keys)
    assert len(set(keys)) == 1


def test_the_flash_alert_pair_is_never_suppressed():
    """The regression this guard could most easily cause. The DFIR Report's
    flash alert about its own Akira write-up is same-source with a nearly
    identical title, and is one of the three groupings A3 confirmed as
    genuine. A blanket same-source rule would silently break it."""
    titles = [
        "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira",
        "Flash Alert: From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira",
    ]
    assert series_suppression_keys(["The DFIR Report"] * 2, titles) == [None, None]


def test_the_same_template_across_two_outlets_is_not_a_series():
    """A template only means cadence within one publisher. Two outlets landing
    on the same headline is a signal about the story, not noise."""
    keys = series_suppression_keys(
        ["BleepingComputer", "The Record", "Unit 42"],
        ["Levi Strauss breach"] * 3,
    )
    assert keys == [None, None, None]


def test_untitled_articles_are_not_pooled_into_one_series():
    keys = series_suppression_keys(["CISA"] * 3, [None, "", None])
    assert keys == [None, None, None]


def test_a_recurring_series_does_not_become_one_campaign():
    """End to end on the TF-IDF path: instalments that would otherwise merge
    stay apart, while a genuine pair still joins."""
    articles = [
        _Article("6th July - Threat Intelligence Report", source="Check Point"),
        _Article("13th July - Threat Intelligence Report", source="Check Point"),
        _Article("20th July - Threat Intelligence Report", source="Check Point"),
        _Article("LockBit hits Acme Hospital via Citrix appliance exploit", source="A"),
        _Article("Acme Hospital LockBit intrusion through the Citrix appliance", source="B"),
    ]
    clusters, backend = cluster_articles(articles, backend="tfidf")
    assert backend == "tfidf"

    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 1, 1, 2], "the three instalments stay separate; the real pair joins"


@pytest.mark.parametrize("requested", ["tfidf", "embedding"])
def test_an_explicit_backend_is_never_silently_downgraded(requested):
    """An operator who pinned a backend should see a failure if it is broken,
    not a quiet fallback that hides a bad deploy."""
    assert select_backend(requested) == requested


def test_auto_resolves_to_something_usable():
    assert select_backend("auto") in {"embedding", "tfidf"}


def test_min_series_length_is_above_two():
    """Documents the constant the flash-alert case depends on."""
    assert MIN_SERIES_LENGTH >= 3
