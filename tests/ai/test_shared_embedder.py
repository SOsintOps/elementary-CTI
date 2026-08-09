"""S4: the campaigns view must reuse one embedder, not build one per render.

Before this, every /ai/campaigns request constructed a fresh
CachedEmbedder(StaticEmbedder()), reloading the ~30 MB model from disk each
time. These tests pin the singleton and its reset hatch.
"""

from __future__ import annotations

import pestilentia.ai.embeddings as emb
from pestilentia.ai.embeddings import CachedEmbedder, reset_shared_embedder, shared_embedder


def teardown_function():
    reset_shared_embedder()


def test_the_shared_embedder_is_one_instance():
    reset_shared_embedder()
    assert shared_embedder() is shared_embedder()


def test_it_is_a_cached_embedder():
    reset_shared_embedder()
    assert isinstance(shared_embedder(), CachedEmbedder)


def test_reset_forces_a_new_instance():
    first = shared_embedder()
    reset_shared_embedder()
    assert shared_embedder() is not first


def test_constructing_the_singleton_does_not_touch_the_network_or_load_eagerly(monkeypatch):
    """The point of the singleton is to *hold* the model, but building it must
    stay lazy — importing the app at startup must not force a model load on a
    box that never fetched one."""
    loaded = []
    real_load = emb.StaticEmbedder._load

    def spy(self):
        loaded.append(True)
        return real_load(self)

    monkeypatch.setattr(emb.StaticEmbedder, "_load", spy)
    reset_shared_embedder()
    shared_embedder()  # construct only
    assert loaded == [], "the model must not load until something encodes"
