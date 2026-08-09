"""A1: the embedding backend protocol, the on-disk cache, and the test stub.

These tests pin plumbing, not quality. The stub's vectors are hashes, so two
texts about the same incident are no closer than two unrelated ones — any
assertion here about clustering *quality* would be measuring the hash, and is
deliberately absent. Quality is measured against the real corpus in A3.
"""

from __future__ import annotations

import pytest

from pestilentia.ai.embeddings import (
    CachedEmbedder,
    Embedder,
    EmbeddingCache,
    StubEmbedder,
    cosine,
    l2_normalise,
    to_float32,
)


@pytest.fixture
def cache(tmp_path):
    instance = EmbeddingCache(tmp_path / "vectors.sqlite3")
    yield instance
    instance.close()


class CountingEmbedder:
    """Stub wrapper that records how many texts actually reached the backend."""

    def __init__(self, inner: Embedder) -> None:
        self.inner = inner
        self.encoded: list[str] = []

    @property
    def model_id(self) -> str:
        return self.inner.model_id

    @property
    def dimensions(self) -> int:
        return self.inner.dimensions

    def encode(self, texts):
        self.encoded.extend(texts)
        return self.inner.encode(texts)


def test_stub_satisfies_the_protocol():
    assert isinstance(StubEmbedder(), Embedder)


def test_stub_is_deterministic_across_instances():
    """Tests must not vary run to run, so the same text always maps to the
    same vector — including in a fresh process with a fresh instance."""
    assert StubEmbedder().encode(["akira ransomware"]) == StubEmbedder().encode(
        ["akira ransomware"]
    )


def test_vectors_are_unit_length_so_dot_product_is_cosine():
    (vector,) = StubEmbedder(dimensions=128).encode(["lockbit affiliate tooling"])
    assert len(vector) == 128
    assert cosine(vector, vector) == pytest.approx(1.0, abs=1e-6)


def test_dimensions_beyond_one_digest_are_supported():
    """A sha256 digest is 32 bytes; a 256-dim model needs the counter path."""
    (vector,) = StubEmbedder(dimensions=256).encode(["x"])
    assert len(vector) == 256


def test_l2_normalise_leaves_the_zero_vector_alone():
    assert l2_normalise([0.0, 0.0]) == [0.0, 0.0]


def test_cache_roundtrip_survives_reopen(tmp_path):
    """The cache is only worth having if it outlives the process."""
    path = tmp_path / "vectors.sqlite3"
    first = EmbeddingCache(path)
    first.put("stub-v1", "akira", [0.5, 0.5, 0.5, 0.5])
    first.close()

    second = EmbeddingCache(path)
    assert second.get("stub-v1", "akira") == pytest.approx([0.5, 0.5, 0.5, 0.5])
    second.close()


def test_cache_is_scoped_by_model_id(cache):
    """Changing the model must not silently mix two vector spaces."""
    cache.put("stub-v1", "akira", [1.0, 0.0])
    assert cache.get("other-model", "akira") is None


def test_cache_counts_hits_and_misses(cache):
    cache.get("stub-v1", "absent")
    cache.put("stub-v1", "present", [1.0, 0.0])
    cache.get("stub-v1", "present")
    assert (cache.hits, cache.misses) == (1, 1)


def test_unwritable_cache_degrades_instead_of_raising(tmp_path):
    """A read-only image must cost speed, not availability."""
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    disabled = EmbeddingCache(blocker / "vectors.sqlite3")
    assert disabled.enabled is False
    disabled.put("stub-v1", "akira", [1.0])
    assert disabled.get("stub-v1", "akira") is None


def test_cached_embedder_only_encodes_misses(cache):
    counting = CountingEmbedder(StubEmbedder())
    embedder = CachedEmbedder(counting, cache)

    first = embedder.encode(["akira", "lockbit"])
    second = embedder.encode(["akira", "lockbit"])

    assert first == second
    assert counting.encoded == ["akira", "lockbit"], "second call should be all hits"


def test_cached_embedder_preserves_input_order_on_partial_hits(cache):
    """The risky path: some texts hit, some miss. The reassembled batch must
    still line up with the input, or callers silently mislabel their data."""
    counting = CountingEmbedder(StubEmbedder())
    embedder = CachedEmbedder(counting, cache)

    embedder.encode(["b"])  # warm exactly one entry
    counting.encoded.clear()

    batch = ["a", "b", "c"]
    got = embedder.encode(batch)

    assert counting.encoded == ["a", "c"], "the warm entry should not be re-encoded"
    assert got == [to_float32(v) for v in StubEmbedder().encode(batch)]


def test_cache_state_cannot_change_the_result(tmp_path):
    """The property that makes the cache safe to add to clustering: a warm
    cache and a cold one return bit-identical vectors. Storage is float32, so
    fresh vectors are rounded the same way rather than returned at full
    precision — otherwise a threshold decision could depend on cache warmth."""
    path = tmp_path / "vectors.sqlite3"
    cold = EmbeddingCache(path)
    first = CachedEmbedder(StubEmbedder(), cold).encode(["akira", "lockbit"])
    cold.close()

    warm = EmbeddingCache(path)
    second = CachedEmbedder(StubEmbedder(), warm).encode(["akira", "lockbit"])
    hits = warm.hits
    warm.close()

    assert hits == 2, "the second run should have been served entirely from disk"
    assert first == second


def test_cached_embedder_exposes_the_backend_identity(cache):
    embedder = CachedEmbedder(StubEmbedder(dimensions=32), cache)
    assert embedder.model_id == "stub-v1"
    assert embedder.dimensions == 32
