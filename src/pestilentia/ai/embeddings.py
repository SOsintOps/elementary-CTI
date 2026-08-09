# "You see, but you do not observe." — Sherlock Holmes, Elementary
"""Local text embeddings for clustering and near-duplicate detection.

Two rules shape this module. Nothing here may touch the network at request
time — the model is fetched once, out of band, and loaded from disk, because
this runs on a Pi whose DNS is intermittent and a page render must not depend
on it. And nothing here may need a schema change: embeddings are cached on
disk keyed by content hash, not stored in a column, because adding one is a
human-approved migration.

The backend is behind a protocol so the benchmark can compare implementations
without the callers knowing which one they got."""

from __future__ import annotations

import array
import hashlib
import logging
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)

# Repo root from src/pestilentia/ai/embeddings.py — the same relative position
# inside the container image.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_CACHE_PATH = _REPO_ROOT / ".embedding-cache" / "vectors.sqlite3"

# Static embeddings rather than a transformer: this runs on a Pi alongside
# Postgres and the scheduler, and a distilled lookup-and-pool model costs a
# fraction of a forward pass per document. Whether the quality holds up against
# the TF-IDF baseline is measured in A3, not assumed here.
DEFAULT_MODEL_ID = "minishlab/potion-base-8M"
DEFAULT_MODEL_DIR = _REPO_ROOT / ".embedding-model" / "potion-base-8M"


class EmbeddingModelMissingError(RuntimeError):
    """The model files are not on disk. Raised with the command that fixes it —
    an ImportError or a bare FileNotFoundError here sends whoever hits it
    reading source code instead of running one script."""


@runtime_checkable
class Embedder(Protocol):
    """A source of dense vectors for text.

    `encode` returns one L2-normalised vector per input, in input order, so
    callers can treat the dot product as cosine similarity — the same contract
    the TF-IDF path in `ai.sources.clustering` already relies on.
    """

    @property
    def model_id(self) -> str:
        """Stable identifier; part of the cache key, so changing the model
        invalidates its entries rather than silently mixing vector spaces."""

    @property
    def dimensions(self) -> int: ...

    def encode(self, texts: Sequence[str]) -> list[list[float]]: ...


def to_float32(vector: Sequence[float]) -> list[float]:
    """Round a vector through float32, the cache's storage precision.

    Applied to freshly-encoded vectors too, so a cache hit and a cache miss
    return bit-identical values. Without it the cache would be observable:
    two runs over the same corpus could land on opposite sides of a clustering
    threshold depending only on whether the cache happened to be warm.
    """
    return list(array.array("f", vector))


def l2_normalise(vector: list[float]) -> list[float]:
    norm = sum(component * component for component in vector) ** 0.5
    if norm == 0.0:
        return vector
    return [component / norm for component in vector]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Both vectors are L2-normalised, so the dot product is the cosine."""
    return sum(x * y for x, y in zip(a, b, strict=True))


class StubEmbedder:
    """Deterministic vectors derived from the text's own hash.

    Exists so the test suite never downloads a model and never varies between
    runs. The vectors carry no semantics — two texts sharing a word are no
    closer than two that don't — so tests may assert on caching, plumbing and
    determinism, but never on clustering *quality*.
    """

    def __init__(self, dimensions: int = 64, model_id: str = "stub-v1") -> None:
        self._dimensions = dimensions
        self._model_id = model_id

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._one(text) for text in texts]

    def _one(self, text: str) -> list[float]:
        # Expand the digest to the requested width by re-hashing with a
        # counter, so dimensions is free rather than capped at digest size.
        raw: list[float] = []
        counter = 0
        seed = text.encode("utf-8")
        while len(raw) < self._dimensions:
            digest = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            raw.extend(byte / 255.0 - 0.5 for byte in digest)
            counter += 1
        return l2_normalise(raw[: self._dimensions])


class StaticEmbedder:
    """model2vec static embeddings, loaded from a local directory.

    Never reaches the network: the directory is populated out of band by
    `scripts/fetch_embedding_model.py`, and at image build time by the
    Dockerfile. Loading is deferred to first use so importing this module —
    which the web app does at startup — stays cheap and cannot fail on a box
    where the model was never fetched.
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        model_id: str = DEFAULT_MODEL_ID,
    ) -> None:
        self.model_dir = Path(model_dir) if model_dir is not None else DEFAULT_MODEL_DIR
        self._model_id = model_id
        self._model = None
        self._dimensions: int | None = None

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def dimensions(self) -> int:
        if self._dimensions is None:
            self._load()
        assert self._dimensions is not None
        return self._dimensions

    @classmethod
    def is_available(cls, model_dir: Path | None = None) -> bool:
        """Cheap presence check for callers choosing a backend. Deliberately
        does not load the model — the caller is deciding, not encoding."""
        directory = Path(model_dir) if model_dir is not None else DEFAULT_MODEL_DIR
        return (directory / "model.safetensors").is_file()

    def _load(self) -> None:
        if self._model is not None:
            return
        if not self.is_available(self.model_dir):
            raise EmbeddingModelMissingError(
                f"No embedding model at {self.model_dir}. "
                "Run: uv run python scripts/fetch_embedding_model.py"
            )
        try:
            from model2vec import StaticModel
        except ImportError as exc:  # pragma: no cover - declared dependency
            raise EmbeddingModelMissingError("model2vec is not installed; run `uv sync`") from exc
        self._model = StaticModel.from_pretrained(str(self.model_dir))
        probe = self._model.encode(["dimension probe"])
        self._dimensions = int(probe.shape[-1])

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        self._load()
        assert self._model is not None
        if not texts:
            return []
        matrix = self._model.encode(list(texts))
        return [l2_normalise([float(value) for value in row]) for row in matrix]


class EmbeddingCache:
    """On-disk vector cache, keyed by `(model_id, sha256(text))`.

    SQLite from the standard library rather than a file per vector: one file to
    ship and delete, and no inode churn from a corpus of a few thousand short
    documents. Vectors are stored as raw float32 — a JSON array of 256 floats
    is roughly eight times the bytes for no benefit.

    A cache that cannot be written is not an error. The container runs as a
    non-root user and the image may be read-only; in that case this degrades to
    a no-op and the caller pays full encode cost, which is slow but correct.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_CACHE_PATH
        self.hits = 0
        self.misses = 0
        self._connection: sqlite3.Connection | None = None
        self._enabled = self._open()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _open(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.path), check_same_thread=False)
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS vectors ("
                " model_id TEXT NOT NULL,"
                " text_sha256 TEXT NOT NULL,"
                " dimensions INTEGER NOT NULL,"
                " vector BLOB NOT NULL,"
                " PRIMARY KEY (model_id, text_sha256))"
            )
            self._connection.commit()
            return True
        except (OSError, sqlite3.Error) as exc:
            log.warning("Embedding cache disabled (%s): %s", self.path, exc)
            self._connection = None
            return False

    @staticmethod
    def key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, model_id: str, text: str) -> list[float] | None:
        if not self._enabled or self._connection is None:
            self.misses += 1
            return None
        row = self._connection.execute(
            "SELECT vector FROM vectors WHERE model_id = ? AND text_sha256 = ?",
            (model_id, self.key(text)),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        buffer = array.array("f")
        buffer.frombytes(row[0])
        return list(buffer)

    def put(self, model_id: str, text: str, vector: Sequence[float]) -> None:
        if not self._enabled or self._connection is None:
            return
        blob = array.array("f", vector).tobytes()
        try:
            self._connection.execute(
                "INSERT OR REPLACE INTO vectors"
                " (model_id, text_sha256, dimensions, vector) VALUES (?, ?, ?, ?)",
                (model_id, self.key(text), len(vector), blob),
            )
            self._connection.commit()
        except sqlite3.Error as exc:  # pragma: no cover - disk full, read-only fs
            log.warning("Embedding cache write failed: %s", exc)

    def reset_counters(self) -> None:
        self.hits = 0
        self.misses = 0

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
            self._enabled = False


class CachedEmbedder:
    """Wraps an `Embedder` so repeat texts are read from disk.

    Encodes only what the cache missed, then reassembles the batch in input
    order — the caller gets the same list it would have got uncached, which
    keeps the cache invisible to `clustering` and to the tests that exercise it.
    """

    def __init__(self, backend: Embedder, cache: EmbeddingCache | None = None) -> None:
        self.backend = backend
        self.cache = cache if cache is not None else EmbeddingCache()

    @property
    def model_id(self) -> str:
        return self.backend.model_id

    @property
    def dimensions(self) -> int:
        return self.backend.dimensions

    def encode(self, texts: Sequence[str]) -> list[list[float]]:
        results: list[list[float] | None] = []
        pending_indices: list[int] = []
        pending_texts: list[str] = []

        for index, text in enumerate(texts):
            cached = self.cache.get(self.model_id, text)
            if cached is None:
                results.append(None)
                pending_indices.append(index)
                pending_texts.append(text)
            else:
                results.append(cached)

        if pending_texts:
            fresh = self.backend.encode(pending_texts)
            for index, text, vector in zip(pending_indices, pending_texts, fresh, strict=True):
                stored = to_float32(vector)
                self.cache.put(self.model_id, text, stored)
                results[index] = stored

        # Filtering out None here would silently return a shorter batch and
        # misalign every caller's texts against their vectors. A backend that
        # under-returns is a bug worth failing on, not smoothing over.
        if any(vector is None for vector in results):
            raise RuntimeError(
                f"{self.model_id} returned fewer vectors than texts "
                f"({len(pending_texts)} requested)"
            )
        return [vector for vector in results if vector is not None]


# --- Process-wide shared embedder ---
# The model file is ~30 MB and takes ~0.5 s to load. Constructing a fresh
# StaticEmbedder per request — as the campaigns view did — reloaded it every
# time and churned the allocator. `StaticEmbedder` already loads lazily and is
# stateless once loaded, and `EmbeddingCache` opens SQLite with
# `check_same_thread=False`, so one instance is safe to share across the
# threadpool FastAPI runs sync handlers in.
_shared: CachedEmbedder | None = None


def shared_embedder() -> CachedEmbedder:
    """The one embedder the app should use. Loads the model on first call,
    reuses it forever after."""
    global _shared
    if _shared is None:
        _shared = CachedEmbedder(StaticEmbedder())
    return _shared


def reset_shared_embedder() -> None:
    """Drop the singleton — for tests that need a clean slate, or a hot-reload
    of the model. Not part of the request path."""
    global _shared
    if _shared is not None:
        _shared.cache.close()
    _shared = None
