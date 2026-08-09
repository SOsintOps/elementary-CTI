"""W13: campaign clustering — same-campaign coverage groups, unrelated stays apart.

Distinct from dedup: simhash answers "is this the same article?", clustering
answers "are these different articles about the same campaign?".
"""

from pestilentia.ai.sources.clustering import (
    DEFAULT_THRESHOLD,
    cluster_articles,
    cluster_documents,
    tokenize,
)


class _Article:
    def __init__(self, title, body=None):
        self.title = title
        self.body = body


def test_tokenize_keeps_the_terms_that_identify_a_campaign():
    """Adversary names, malware families and CVE ids must survive stopwording."""
    tokens = tokenize("The LockBit affiliate exploited CVE-2026-1234 with Cobalt Strike")
    assert "lockbit" in tokens
    assert "cve-2026-1234" in tokens
    assert "cobalt" in tokens
    assert "the" not in tokens
    assert "with" not in tokens


# TF-IDF is corpus-relative: with two or three documents every term has the
# same document frequency and the weighting says nothing. These fixtures ship a
# background corpus so the tests exercise the algorithm under the conditions it
# actually runs in, rather than a degenerate one.
BACKGROUND = [
    "Cloud revenue expands across three new European datacentre regions",
    "Phishing campaign abuses calendar invitations to harvest credentials",
    "New Linux kernel privilege escalation flaw disclosed by researchers",
    "Banking trojan resurfaces targeting mobile users in Latin America",
    "Zero trust adoption survey finds budgets rising among mid-market firms",
    "Botnet operators shift to residential proxies to evade blocklists",
    "Vulnerability in industrial controller allows unauthenticated reset",
    "Infostealer logs traded on forums fuel account takeover at scale",
]


def _with_background(docs):
    return docs + BACKGROUND


def test_multi_vendor_coverage_of_one_incident_clusters_together():
    docs = [
        "LockBit ransomware cripples Acme Hospital, encrypting patient records "
        "after exploiting an unpatched Citrix appliance",
        "Acme Hospital confirms LockBit intrusion: Citrix appliance exploited, "
        "patient records encrypted across the network",
        "Analysis of the LockBit attack on Acme Hospital and the Citrix "
        "appliance used for initial access to encrypt patient records",
    ]
    labels = cluster_documents(_with_background(docs))
    assert len(set(labels[:3])) == 1, "three reports on one incident are one campaign"


def test_unrelated_reports_stay_in_separate_campaigns():
    docs = [
        "LockBit ransomware cripples Acme Hospital, encrypting patient records "
        "after exploiting an unpatched Citrix appliance",
        "Quarterly cloud revenue grows as the vendor expands its datacentre "
        "footprint across three new regions in Europe",
    ]
    labels = cluster_documents(docs)
    assert len(set(labels)) == 2


def test_boilerplate_reports_merge_which_is_the_headline_limitation():
    """Two leak-site write-ups sharing a template merge, though the actor and
    victim differ. Same root cause as the recurring-series case: bag-of-words
    cannot separate "same template, different entities" from "same campaign".

    This one matters more, because merging two real incidents would mislead an
    analyst rather than merely look untidy. Squaring the idf to let rare entity
    tokens dominate was tried and measured worse — it also split genuine
    multi-vendor coverage. Pinned here so the limitation is visible in the test
    suite instead of being discovered in the UI."""
    docs = [
        "Akira ransomware attack hits Northwind Manufacturing, victim data "
        "leaked on the group's site after negotiations failed",
        "Qilin ransomware attack hits Southridge Logistics, victim data leaked "
        "on the group's site after negotiations failed",
    ]
    labels = cluster_documents(_with_background(docs))
    assert labels[0] == labels[1], "documents current behaviour; not an endorsement"


def test_short_documents_get_their_own_cluster_rather_than_a_junk_bucket():
    docs = ["LockBit hits Acme Hospital with Citrix exploit", "n/a", ""]
    labels = cluster_documents(docs)
    assert len(set(labels)) == 3


def test_single_link_is_transitive_through_a_bridge():
    """A and C join via B — vendors covering one incident from different angles."""
    docs = [
        "LockBit deployed against Acme Hospital via a Citrix appliance flaw",
        "Acme Hospital Citrix appliance flaw exploited; Conti-style playbook "
        "with LockBit encryptor observed by responders",
        "Conti-style playbook with responders observing the encryptor at Acme "
        "Hospital during the Citrix appliance compromise",
    ]
    labels = cluster_documents(_with_background(docs))
    assert len(set(labels[:3])) == 1


def test_recurring_series_are_a_known_limitation_not_a_silent_one():
    """Instalments of one column share a template, and lexical similarity
    cannot tell that from a campaign. Measured on the live corpus (nine
    editions of one monthly column merged). Pinned so the behaviour is visible
    rather than a surprise; fixing it needs embeddings or a cadence signal."""
    docs = [
        "This month in security with the analyst - July 2026 edition roundup",
        "This month in security with the analyst - June 2026 edition roundup",
    ]
    labels = cluster_documents(_with_background(docs))
    assert labels[0] == labels[1], "documents this behaviour; not an endorsement"


def test_empty_corpus_is_a_no_op():
    assert cluster_documents([]) == []


def test_threshold_is_honoured():
    docs = [
        "LockBit ransomware attack on Acme Hospital",
        "Akira ransomware attack on Northwind Logistics",
    ]
    assert len(set(cluster_documents(docs, threshold=0.99))) == 2
    assert len(set(cluster_documents(docs, threshold=0.0))) == 1


def test_cluster_articles_returns_largest_campaign_first():
    articles = [
        _Article("LockBit hits Acme Hospital via Citrix appliance exploit"),
        _Article("Acme Hospital LockBit intrusion through the Citrix appliance"),
        _Article("Cloud revenue expands across three new European datacentre regions"),
    ]
    clusters, backend = cluster_articles(articles, backend="tfidf")
    assert backend == "tfidf"
    assert len(clusters) == 2
    assert len(clusters[0]) == 2, "largest campaign leads"
    assert len(clusters[1]) == 1


def test_default_threshold_is_documented_and_sane():
    assert 0.0 < DEFAULT_THRESHOLD < 1.0
