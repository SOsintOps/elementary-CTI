#!/usr/bin/env python
"""A3: measure embedding clustering against the TF-IDF baseline on real data.

Reads the live article corpus, runs both vectorizers through the *same*
single-link union-find at a range of thresholds, and prints throughput, memory
and cluster counts. The point is to decide whether A4 is worth doing — a
negative result is a real outcome, so this prints what it measures and draws no
conclusion of its own.

    uv run python scripts/benchmark_clustering.py                # dev SQLite
    PEST_DB_URL=postgresql://... uv run python scripts/benchmark_clustering.py

Cosine on dense embeddings is not on the same scale as on sparse TF-IDF, so the
two sweeps deliberately use different threshold ranges.
"""

from __future__ import annotations

import argparse
import resource
import time
from collections import defaultdict

from sqlalchemy import create_engine, select
from sqlalchemy.orm import joinedload, sessionmaker

from pestilentia.ai.embeddings import CachedEmbedder, StaticEmbedder, cosine
from pestilentia.ai.sources.clustering import DEFAULT_THRESHOLD, cluster_documents
from pestilentia.config import get_settings
from pestilentia.models.tables import Article

TFIDF_THRESHOLDS = (0.20, 0.30, 0.35, 0.50)
EMBEDDING_THRESHOLDS = (0.50, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90)


def peak_rss_mb() -> float:
    # ru_maxrss is kilobytes on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def load_corpus() -> list[Article]:
    engine = create_engine(get_settings().db_url)
    with sessionmaker(bind=engine)() as session:
        # Eager-load the source: the rows outlive the session here, and a lazy
        # load after it closes raises DetachedInstanceError.
        return list(
            session.scalars(
                select(Article).options(joinedload(Article.source)).order_by(Article.id)
            )
        )


def article_text(article: Article) -> str:
    """Identical preprocessing to cluster_articles, so the only variable
    between the two arms is the vectorizer."""
    if article.title:
        return f"{article.title} {article.title} {(article.body or '')[:4000]}"
    return article.body or ""


def cluster_by_vectors(vectors: list[list[float]], threshold: float) -> list[int]:
    """Single-link union-find over dense vectors — the same agglomeration the
    TF-IDF path uses. No inverted index: every pair of dense vectors shares
    every dimension, so there is nothing to prune."""
    parent = list(range(len(vectors)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(vectors)):
        for j in range(i + 1, len(vectors)):
            if cosine(vectors[i], vectors[j]) >= threshold:
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[max(ri, rj)] = min(ri, rj)

    labels: list[int] = []
    seen: dict[int, int] = {}
    for i in range(len(vectors)):
        root = find(i)
        if root not in seen:
            seen[root] = len(seen)
        labels.append(seen[root])
    return labels


def summarise(labels: list[int]) -> tuple[int, int, int]:
    groups: dict[int, int] = defaultdict(int)
    for label in labels:
        groups[label] += 1
    multi = [size for size in groups.values() if size > 1]
    return len(groups), len(multi), (max(multi) if multi else 1)


def show_multi_clusters(labels: list[int], articles: list[Article], limit: int) -> None:
    groups: dict[int, list[Article]] = defaultdict(list)
    for label, article in zip(labels, articles, strict=True):
        groups[label].append(article)
    ranked = sorted((g for g in groups.values() if len(g) > 1), key=len, reverse=True)
    for group in ranked[:limit]:
        print(f"\n  [{len(group)} articles]")
        for article in group:
            source = article.source.name if article.source else "?"
            print(f"    - ({source}) {(article.title or '')[:95]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", type=int, default=0, help="print N largest clusters")
    parser.add_argument("--at", type=float, default=None, help="threshold for --show")
    args = parser.parse_args()

    articles = load_corpus()
    texts = [article_text(a) for a in articles]
    print(f"Corpus: {len(articles)} articles, {sum(len(t) for t in texts) / 1000:.0f}k chars\n")

    print("== TF-IDF (baseline, shipped in 0.8.0) ==")
    start = time.perf_counter()
    baseline = {t: cluster_documents(list(texts), t) for t in TFIDF_THRESHOLDS}
    print(f"  vectorize+cluster all thresholds: {time.perf_counter() - start:.2f}s")
    print(f"  {'threshold':>10} {'clusters':>9} {'multi':>6} {'largest':>8}")
    for threshold, labels in baseline.items():
        total, multi, largest = summarise(labels)
        print(f"  {threshold:>10.2f} {total:>9} {multi:>6} {largest:>8}")

    print("\n== Embeddings ==")
    rss_before = peak_rss_mb()
    embedder = StaticEmbedder()
    start = time.perf_counter()
    # Touch the property to force the lazy load, so cold start is timed on
    # its own rather than folded into the first encode.
    dimensions = embedder.dimensions
    load_s = time.perf_counter() - start
    print(f"  model load (cold): {load_s:.2f}s, {dimensions} dimensions")

    start = time.perf_counter()
    vectors = embedder.encode(texts)
    encode_s = time.perf_counter() - start
    print(
        f"  encode {len(texts)} docs: {encode_s:.2f}s "
        f"({len(texts) / encode_s:.0f} docs/s), peak RSS {peak_rss_mb():.0f} MB "
        f"(+{peak_rss_mb() - rss_before:.0f} MB)"
    )

    cached = CachedEmbedder(embedder)
    start = time.perf_counter()
    cached.encode(texts)
    warm_first = time.perf_counter() - start
    start = time.perf_counter()
    cached.encode(texts)
    warm_second = time.perf_counter() - start
    print(f"  cache: fill {warm_first:.2f}s, then {warm_second:.2f}s ({cached.cache.hits} hits)")

    print(f"  {'threshold':>10} {'clusters':>9} {'multi':>6} {'largest':>8}")
    embedding_runs = {}
    for threshold in EMBEDDING_THRESHOLDS:
        labels = cluster_by_vectors(vectors, threshold)
        embedding_runs[threshold] = labels
        total, multi, largest = summarise(labels)
        print(f"  {threshold:>10.2f} {total:>9} {multi:>6} {largest:>8}")

    if args.show:
        at = args.at if args.at is not None else 0.75
        source = embedding_runs.get(at) or baseline.get(at)
        if source is None:
            print(f"\nNo run at threshold {at}; pick one from the sweeps above.")
            return 1
        print(f"\n== {args.show} largest clusters at {at} ==")
        show_multi_clusters(source, articles, args.show)

    print(f"\n(TF-IDF ships at threshold {DEFAULT_THRESHOLD})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
