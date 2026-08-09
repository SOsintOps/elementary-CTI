"""A2: the real CPU backend and its failure mode when the model is absent.

The tests that need model weights skip when they are not on disk, so CI and a
fresh clone stay at zero download. The absent-model path is the one that must
work everywhere, so it is tested unconditionally.
"""

from __future__ import annotations

import pytest

from pestilentia.ai.embeddings import (
    CachedEmbedder,
    EmbeddingCache,
    EmbeddingModelMissingError,
    StaticEmbedder,
    cosine,
)

needs_model = pytest.mark.skipif(
    not StaticEmbedder.is_available(),
    reason="embedding model not fetched; run scripts/fetch_embedding_model.py",
)


def test_missing_model_names_the_script_that_fixes_it(tmp_path):
    """Whoever hits this should be able to act on the message alone."""
    embedder = StaticEmbedder(model_dir=tmp_path / "absent")
    with pytest.raises(EmbeddingModelMissingError) as caught:
        embedder.encode(["akira"])
    assert "scripts/fetch_embedding_model.py" in str(caught.value)


def test_availability_check_does_not_load_the_model(tmp_path):
    assert StaticEmbedder.is_available(tmp_path / "absent") is False


def test_construction_never_touches_disk(tmp_path):
    """The web app imports this at startup; a box without the model must still
    boot and fall back, not crash on import."""
    StaticEmbedder(model_dir=tmp_path / "absent")  # must not raise


@needs_model
def test_encodes_unit_vectors():
    (vector,) = StaticEmbedder().encode(["Akira ransomware targets manufacturing"])
    assert len(vector) == 256
    assert cosine(vector, vector) == pytest.approx(1.0, abs=1e-5)


@needs_model
def test_empty_batch_is_not_an_error():
    assert StaticEmbedder().encode([]) == []


@needs_model
def test_semantically_related_text_scores_above_unrelated():
    """The one quality claim worth making at unit level: the model must beat
    coin-flipping on an obvious pair, or the wiring is wrong. Real quality is
    measured on the live corpus in A3, not here."""
    embedder = StaticEmbedder()
    ransomware, affiliate, cooking = embedder.encode(
        [
            "Akira ransomware encrypts VMware ESXi hosts",
            "The Akira group deployed its encryptor against ESXi servers",
            "A recipe for slow-braised beef with red wine",
        ]
    )
    assert cosine(ransomware, affiliate) > cosine(ransomware, cooking)


@needs_model
def test_cache_returns_the_same_vectors_as_a_cold_encode(tmp_path):
    """The float32 rounding property from A1, now against the real backend."""
    path = tmp_path / "vectors.sqlite3"
    texts = ["Qilin claims a healthcare victim", "BlackByte tooling analysis"]

    cold = EmbeddingCache(path)
    first = CachedEmbedder(StaticEmbedder(), cold).encode(texts)
    cold.close()

    warm = EmbeddingCache(path)
    second = CachedEmbedder(StaticEmbedder(), warm).encode(texts)
    hits = warm.hits
    warm.close()

    assert hits == 2
    assert first == second
