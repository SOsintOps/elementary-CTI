# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes, Elementary
"""Campaign clustering over the ingested article corpus (Phase 2).

Why this exists: aggregating the reports that describe *one* campaign before
extraction measurably improves downstream TTP extraction, which is why the
research doc treats clustering as a Phase 2 output rather than a nice-to-have.

Two deliberate constraints:

1. **Nothing is persisted.** `articles` has no campaign column, and adding one
   is an L2 migration needing human approval. Clusters are therefore computed
   on demand. At corpus sizes in the low thousands this is cheap, and it keeps
   the threshold tunable without a data rewrite while the value is still being
   proven.
2. **Two vectorisers, chosen by measurement.** TF-IDF was the shipped baseline
   and remains the fallback. Local embeddings landed once they were measured
   against it on our own corpus rather than adopted on recommendation: on the
   metric this feature exists for — different outlets covering one incident —
   they find three genuine cross-source campaigns against TF-IDF's one, at a
   tenth of the CPU cost. Numbers in `.planning/PLAN-LOCAL-AI-2026-08.md`.
   Static embeddings (model2vec, 29.5 MB), not torch.

Distinct from `dedup.simhash64`, which answers "is this the same article?".
This answers "are these different articles about the same campaign?".
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-.]{2,}")

# Deliberately small. Security prose is full of words that say nothing about
# *which* campaign a report describes, but adversary names, malware families
# and CVE ids must survive, so the list stays generic rather than domain-tuned.
_STOPWORDS = frozenset(
    [
        "the",
        "and",
        "for",
        "that",
        "with",
        "this",
        "from",
        "have",
        "has",
        "been",
        "are",
        "was",
        "were",
        "will",
        "would",
        "can",
        "could",
        "should",
        "may",
        "might",
        "not",
        "but",
        "they",
        "their",
        "there",
        "then",
        "than",
        "when",
        "what",
        "which",
        "who",
        "whom",
        "whose",
        "how",
        "why",
        "all",
        "any",
        "some",
        "each",
        "other",
        "into",
        "over",
        "under",
        "about",
        "after",
        "before",
        "during",
        "through",
        "between",
        "more",
        "most",
        "such",
        "only",
        "own",
        "same",
        "also",
        "its",
        "his",
        "her",
        "our",
        "your",
        "you",
        "our",
        "using",
        "used",
        "use",
        "new",
        "news",
        "said",
        "says",
        "according",
        "report",
        "reports",
        "reported",
        "research",
        "researchers",
        "blog",
        "post",
        "article",
        "read",
        "also",
        "however",
        "while",
        "where",
        "these",
        "those",
        "them",
        "your",
        "via",
        "out",
        "per",
        "get",
    ]
)

# Cosine similarity above which two articles are treated as the same campaign.
# Tuned against the live 330-article corpus rather than toy inputs. Sweep:
#   0.20 -> 244 clusters, 37 multi-article     0.35 -> 306 clusters, 16
#   0.30 -> 296 clusters, 17                   0.50 -> 326 clusters, 4
# At 0.35 the multi-article groups it produces are genuine: the Akira/Bumblebee
# report and its flash alert; the ChainDrop npm worm covered by two vendors;
# the Levi Strauss breach reported by two outlets.
DEFAULT_THRESHOLD = 0.35
MIN_TOKENS = 5

# KNOWN LIMITATION, measured not assumed. Lexical similarity also groups
# *recurring editorial series*, whose instalments share a template rather than
# a campaign — on the live corpus it merged nine editions of "This month in
# security", three weekly "Threat Intelligence Report" bulletins, and two
# half-yearly ESET threat reports. It also merged two unrelated ICS advisories
# ("MZ Automation lib60870" / "o6 Automation open62541") that share vendor
# boilerplate.
#
# This is inherent to bag-of-words similarity: a template *is* lexically
# repetitive. The comment above used to offer two candidate fixes — local
# embeddings, or a publication-cadence signal. A3 measured the first and it
# made the problem *worse*: a semantic model recognises a shared register even
# more confidently, merging nine editions of Check Point's weekly report where
# TF-IDF merged two. So the cadence signal is the fix, and it is implemented
# below as `series_key`, applied to whichever vectoriser is in use.
EMBEDDING_THRESHOLD = 0.85
# Cosine on dense vectors is compressed relative to sparse TF-IDF — everything
# resembles everything — so this is nowhere near DEFAULT_THRESHOLD and the two
# are not interchangeable. Chosen by inspecting cluster contents across a
# 0.50-0.90 sweep, not by matching the old cluster count.

# A series needs at least this many instalments before its shared template is
# treated as editorial cadence rather than coincidence. Two is deliberately not
# enough: the DFIR Report's flash alert about its own Akira report is
# single-source with a near-identical title, and is a *genuine* grouping that a
# looser rule would suppress.
MIN_SERIES_LENGTH = 3

_SERIES_NOISE_RE = re.compile(
    r"\b\d+\b"  # bare numbers, including years
    r"|\b\d+(?:st|nd|rd|th)\b"  # ordinals: 3rd August
    r"|\b(?:one|two|three|four|five|six|seven|eight|nine|ten)\b"
    r"|\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?"
    r"|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?"
    r"|dec(?:ember)?)\b"
    r"|\b(?:q[1-4]|week(?:ly)?|month(?:ly)?|edition|part)\b",
    re.IGNORECASE,
)
_SERIES_PUNCT_RE = re.compile(r"[^a-z ]+")


def series_key(title: str | None) -> str:
    """Reduce a headline to its template, dropping what varies per instalment.

    "3rd August - Threat Intelligence Report" and "27th July - Threat
    Intelligence Report" both collapse to "threat intelligence report", while
    two articles about different incidents keep different keys. Counts and
    plurals fold via `_singularise` so CISA's "One Known Exploited
    Vulnerability" and "Three Known Exploited Vulnerabilities" agree.
    """
    if not title:
        return ""
    stripped = _SERIES_NOISE_RE.sub(" ", title.lower())
    stripped = _SERIES_PUNCT_RE.sub(" ", stripped)
    return " ".join(_singularise(word) for word in stripped.split())


def _singularise(word: str) -> str:
    """Crude plural folding, enough to make one template match itself.

    `-ies -> -y` is not optional: CISA alternates "One Known Exploited
    Vulnerability" with "Three Known Exploited Vulnerabilities", and bare
    trailing-s stripping turns the second into "vulnerabilitie", which matches
    neither. This is not a stemmer and does not need to be one.
    """
    if len(word) > 4 and word.endswith("ies"):
        return f"{word[:-3]}y"
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def series_suppression_keys(
    sources: list[str | None], titles: list[str | None]
) -> list[str | None]:
    """Per-document key marking members of a recurring series.

    Two documents sharing a non-None key are never joined. The key combines
    source and template because a template only means "series" within one
    publisher — two outlets independently titling a story the same way is a
    signal, not noise.
    """
    grouped: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, (source, title) in enumerate(zip(sources, titles, strict=True)):
        key = series_key(title)
        if source and key:
            grouped[(source, key)].append(index)

    keys: list[str | None] = [None] * len(titles)
    for (source, key), members in grouped.items():
        if len(members) >= MIN_SERIES_LENGTH:
            for index in members:
                keys[index] = f"{source}::{key}"
    return keys


def tokenize(text: str | None) -> list[str]:
    if not text:
        return []
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _tfidf(docs: list[list[str]]) -> list[dict[str, float]]:
    """L2-normalised TF-IDF vectors, one sparse dict per document."""
    n = len(docs)
    df: Counter[str] = Counter()
    for tokens in docs:
        df.update(set(tokens))

    vectors: list[dict[str, float]] = []
    for tokens in docs:
        tf = Counter(tokens)
        vec: dict[str, float] = {}
        for term, count in tf.items():
            # Smoothed idf: a term in every document contributes ~0 rather
            # than dividing by zero.
            idf = math.log((1 + n) / (1 + df[term])) + 1.0
            # Linear idf. Squaring it was tried, to let rare entity tokens
            # dominate shared boilerplate, and measured worse: it also broke
            # genuine multi-vendor coverage of one incident, because those
            # reports differ in rare vocabulary too. Recorded so the idea is
            # not retried blind.
            vec[term] = (1.0 + math.log(count)) * idf
        norm = math.sqrt(sum(v * v for v in vec.values()))
        vectors.append({t: v / norm for t, v in vec.items()} if norm else {})
    return vectors


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    """Both vectors are already L2-normalised, so the dot product is cosine."""
    if len(a) > len(b):
        a, b = b, a
    return sum(weight * b.get(term, 0.0) for term, weight in a.items())


def _same_series(suppress_keys: list[str | None] | None, i: int, j: int) -> bool:
    """Two instalments of one publisher's recurring series never join."""
    if suppress_keys is None:
        return False
    key_i, key_j = suppress_keys[i], suppress_keys[j]
    return key_i is not None and key_i == key_j


def _renumber(parent: list[int]) -> list[int]:
    """Ids 0..k-1 in order of first appearance — stable and readable output
    rather than sparse row indices."""

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    labels: list[int] = []
    seen: dict[int, int] = {}
    for i in range(len(parent)):
        root = find(i)
        if root not in seen:
            seen[root] = len(seen)
        labels.append(seen[root])
    return labels


def cluster_dense(
    vectors: list[list[float]],
    threshold: float = EMBEDDING_THRESHOLD,
    suppress_keys: list[str | None] | None = None,
) -> list[int]:
    """Single-link agglomeration over dense embedding vectors.

    No inverted index here: every pair of dense vectors shares every dimension,
    so there is nothing to prune and the comparison is the full triangle. At a
    corpus in the low thousands that is still far cheaper than the encode it
    follows, which itself runs at ~1,400 documents a second.
    """
    from pestilentia.ai.embeddings import cosine

    count = len(vectors)
    parent = list(range(count))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(count):
        for j in range(i + 1, count):
            if _same_series(suppress_keys, i, j):
                continue
            if cosine(vectors[i], vectors[j]) >= threshold:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    return _renumber(parent)


def cluster_documents(
    texts: list[str | None],
    threshold: float = DEFAULT_THRESHOLD,
    suppress_keys: list[str | None] | None = None,
) -> list[int]:
    """Return a cluster id per input document, in input order.

    Single-link agglomeration via union-find: A and C join the same campaign if
    each is similar enough to B, which is the behaviour wanted when vendors
    cover one incident from different angles.

    Documents with too little text to judge get their own singleton cluster
    rather than being pooled into a misleading "miscellaneous" group.
    """
    docs = [tokenize(t) for t in texts]
    vectors = _tfidf(docs)

    parent = list(range(len(docs)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        if _same_series(suppress_keys, i, j):
            return
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    # Only compare documents that share at least one term — the inverted index
    # skips the overwhelming majority of pairs in a sparse corpus.
    postings: dict[str, list[int]] = defaultdict(list)
    for idx, vec in enumerate(vectors):
        if len(docs[idx]) < MIN_TOKENS:
            continue
        for term in vec:
            postings[term].append(idx)

    candidates: set[tuple[int, int]] = set()
    for holders in postings.values():
        # A term present in nearly everything generates noise, not candidates.
        if len(holders) > max(2, len(docs) // 2):
            continue
        for a_i in range(len(holders)):
            for b_i in range(a_i + 1, len(holders)):
                candidates.add((holders[a_i], holders[b_i]))

    for i, j in candidates:
        if _cosine(vectors[i], vectors[j]) >= threshold:
            union(i, j)

    # Renumber so ids are 0..k-1 in order of first appearance, which keeps the
    # output stable and readable rather than sparse row indices.
    labels: list[int] = []
    seen: dict[int, int] = {}
    for i in range(len(docs)):
        root = find(i)
        if root not in seen:
            seen[root] = len(seen)
        labels.append(seen[root])
    return labels


def article_text(article) -> str:
    """Title repeated so it outweighs an equal span of body text: a headline
    names the campaign far more reliably than a paragraph does."""
    if article.title:
        return f"{article.title} {article.title} {(article.body or '')[:4000]}"
    return article.body or ""


def select_backend(requested: str = "auto") -> str:
    """Resolve the configured backend to the one actually usable.

    `auto` prefers embeddings and silently falls back when the model was never
    fetched — a fresh clone or a stripped image should render the page with the
    baseline rather than 500. An explicit `embedding` does *not* fall back: if
    an operator asked for it, a silent downgrade would hide a broken deploy.
    """
    from pestilentia.ai.embeddings import StaticEmbedder

    if requested == "tfidf":
        return "tfidf"
    if requested == "embedding":
        return "embedding"
    return "embedding" if StaticEmbedder.is_available() else "tfidf"


def cluster_articles(
    articles: list,
    threshold: float | None = None,
    backend: str = "auto",
) -> tuple[list[list], str]:
    """Group Article rows into campaigns, largest first, with the backend used.

    Returns the backend name alongside the groups so the page can state which
    vectoriser produced the view — the two disagree, and a reader comparing
    against yesterday deserves to know which one they are looking at.
    """
    texts = [article_text(a) for a in articles]
    suppress = series_suppression_keys(
        [a.source.name if getattr(a, "source", None) else None for a in articles],
        [a.title for a in articles],
    )

    resolved = select_backend(backend)
    if resolved == "embedding":
        from pestilentia.ai.embeddings import shared_embedder

        # One process-wide embedder: the ~30 MB model loads once, not on every
        # campaigns render. Its disk cache also persists across requests, so a
        # corpus that has not changed re-clusters from cache.
        vectors = shared_embedder().encode(texts)
        labels = cluster_dense(
            vectors, threshold if threshold is not None else EMBEDDING_THRESHOLD, suppress
        )
    else:
        labels = cluster_documents(
            texts, threshold if threshold is not None else DEFAULT_THRESHOLD, suppress
        )

    groups: dict[int, list] = defaultdict(list)
    for article, label in zip(articles, labels, strict=True):
        groups[label].append(article)
    return sorted(groups.values(), key=len, reverse=True), resolved
