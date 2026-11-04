"""Embedding providers.

Config-selected (``hosted`` | ``local`` | ``deterministic``), default ``hosted``.
:func:`build_embedder` **fails loud**: a chosen provider that can't initialize
raises rather than silently degrading to the non-semantic
:class:`DeterministicEmbedder` (which returns plausible-looking but meaningless
retrievals). Opt into the hash embedder explicitly with
``embedder = "deterministic"`` for tests / offline dev.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
from typing import Protocol
from urllib.parse import urlsplit

from .provider_accounting import metered_call

log = logging.getLogger(__name__)


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


def _l2(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v] if n else v


class DeterministicEmbedder:
    """Dependency-free hashing embedder.

    NOT semantic -- a deterministic bag-of-hashed-tokens vector so the pipeline
    runs (and tests pass) with no API key or model download. Same text -> same
    vector; lexically-overlapping texts land near each other, which is enough to
    exercise and verify the retrieval plumbing.
    """

    def __init__(self, dim: int = 256):
        self.dim = dim

    def embedding_identity(self) -> dict:
        return {"provider": "deterministic", "model": "sha256-token-bins",
                "revision": "1", "preprocessing": "lowercase-whitespace-l2.v1"}

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for t in texts:
            v = [0.0] * self.dim
            for tok in (t or "").lower().split():
                h = int(hashlib.sha256(tok.encode("utf-8")).hexdigest(), 16)
                v[h % self.dim] += 1.0
            out.append(_l2(v))
        return out


class HostedEmbedder:
    """Voyage / OpenAI-compatible embeddings over HTTP (needs an API key).

    Voyage is Anthropic's recommended embeddings partner; any OpenAI-compatible
    ``/embeddings`` endpoint also works via ``base_url`` + ``model``. ``httpx``
    is imported lazily so the package imports clean without the ``hosted`` extra.
    """

    def __init__(self, model: str, base_url: str, api_key: str, dim: int = 1024,
                 revision: str = "provider-model-contract"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.dim = dim
        self.revision = revision
        hostname = (urlsplit(self.base_url).hostname or "hosted-embeddings").lower()
        if "voyageai" in hostname:
            self.provider = "voyage"
        elif "openai" in hostname:
            self.provider = "openai"
        else:
            self.provider = hostname[:192]

    def embedding_identity(self) -> dict:
        return {"provider": self.provider, "model": self.model, "endpoint": self.base_url,
                "revision": self.revision, "preprocessing": "text-verbatim.v1"}

    def _bounded_response(self, texts: list[str], *, timeout: float) -> dict:
        """Raw response for the core rebuild's already-reserved physical call.

        Only the bounded rebuild service calls this transport: it owns admission,
        strict usage accounting and the durable no-retry receipt. Ordinary embed
        calls continue through the standalone-compatible meter below.
        """
        import httpx

        payload = {"model": self.model, "input": texts}
        if self.provider == "voyage":
            payload["truncation"] = False
        response = httpx.post(
            f"{self.base_url}/embeddings",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json=payload, timeout=timeout,
        )
        response.raise_for_status()
        return response.json()

    def embed(self, texts: list[str]) -> list[list[float]]:
        import httpx

        def dispatch():
            response = httpx.post(
                f"{self.base_url}/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": texts},
                timeout=60,
            )
            response.raise_for_status()
            return response

        r = metered_call(
            self.provider,
            dispatch,
            service=f"embeddings:{self.model}",
        )
        # OpenAI/Voyage-compatible responses are only guaranteed addressable by
        # each item's `index`, not positional order, so reorder before zipping
        # vectors back to their input chunks (a reordered batch would otherwise
        # pair chunk text with the wrong vector and silently corrupt the index).
        data = sorted(r.json()["data"], key=lambda d: d.get("index", 0))
        vectors = [d["embedding"] for d in data]
        if len(vectors) != len(texts):
            raise ValueError(
                f"embedding API returned {len(vectors)} vectors for "
                f"{len(texts)} inputs; refusing to misalign the index"
            )
        return vectors


class CohereEmbedder:
    """Cohere embeddings.

    Cohere's ``/v2/embed`` differs from the OpenAI/Voyage shape: it takes
    ``texts`` (not ``input``), requires an ``input_type``
    (search_document / search_query), and returns embeddings nested under
    ``embeddings.float``. ``httpx`` is imported lazily. ``input_type`` defaults
    to ``search_document`` for indexing; pass ``search_query`` at query time for
    Cohere's asymmetric retrieval models.
    """

    def __init__(self, model: str, api_key: str, dim: int = 1024,
                 base_url: str = "https://api.cohere.com/v2",
                 input_type: str = "search_document", revision: str = "provider-model-contract"):
        self.model = model
        self.api_key = api_key
        self.dim = dim
        self.base_url = base_url.rstrip("/")
        self.input_type = input_type
        self.revision = revision

    def embedding_identity(self) -> dict:
        return {"provider": "cohere", "model": self.model, "endpoint": self.base_url,
                "revision": self.revision, "document_input_type": self.input_type,
                "query_input_type": "search_query", "preprocessing": "text-verbatim.v1"}

    def _bounded_response(self, texts: list[str], *, timeout: float) -> dict:
        """Return native usage under the core rebuild's prior durable admission."""
        import httpx

        response = httpx.post(
            f"{self.base_url}/embed",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "texts": texts, "input_type": self.input_type,
                  "embedding_types": ["float"], "truncate": "NONE"},
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts, input_type=self.input_type)

    def embed_query(self, texts: list[str]) -> list[list[float]]:
        """Encode queries in the paired retrieval space without mutating mode."""
        return self._embed(texts, input_type="search_query")

    def _embed(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        import httpx

        def dispatch():
            response = httpx.post(
                f"{self.base_url}/embed",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "texts": texts,
                    "input_type": input_type,
                    "embedding_types": ["float"],
                },
                timeout=60,
            )
            response.raise_for_status()
            return response

        r = metered_call(
            "cohere",
            dispatch,
            service=f"embeddings:{self.model}",
        )
        body = r.json()
        # v2 nests vectors under embeddings.float; v1 returned a flat list.
        embeddings = body.get("embeddings", body)
        vectors = embeddings["float"] if isinstance(embeddings, dict) else embeddings
        if len(vectors) != len(texts):
            raise ValueError(
                f"embedding API returned {len(vectors)} vectors for "
                f"{len(texts)} inputs; refusing to misalign the index"
            )
        return vectors


def build_embedder(cfg: dict | None = None) -> Embedder:
    """Select an embedder from config. **Fails loud.**

    A configured provider that can't initialize (``hosted`` with no API key,
    ``local`` without the extra) raises rather than silently falling back to the
    non-semantic :class:`DeterministicEmbedder` -- a silent downgrade yields
    plausible-looking but meaningless retrievals a business would unknowingly
    trust. The hash embedder must be opted into: ``embedder = "deterministic"``
    (or ``MAVERICK_EMBED_PROVIDER=deterministic``), used by tests / offline dev.
    """
    cfg = cfg or {}
    # The env var is an operator escape hatch that wins over config -- e.g. to
    # force offline/deterministic retrieval without editing config.toml.
    provider = str(
        os.environ.get("MAVERICK_EMBED_PROVIDER") or cfg.get("embedder", "hosted")
    ).lower()

    if provider == "deterministic":
        return DeterministicEmbedder(int(cfg.get("dim", 256)))

    if provider == "hosted":
        base_url = cfg.get("base_url") or "https://api.voyageai.com/v1"
        # VOYAGE_API_KEY is Voyage's credential: it is only offered to Voyage's
        # own host, never as a Bearer token to another configured endpoint. The
        # Lightwork-specific variable wins over that generic one.
        voyage = (urlsplit(base_url).hostname or "").lower() in ("voyageai.com", "api.voyageai.com")
        key = (cfg.get("api_key") or os.environ.get("MAVERICK_EMBED_API_KEY", "")
               or (os.environ.get("VOYAGE_API_KEY") if voyage else ""))
        if not key:
            raise RuntimeError(
                "knowledge: hosted embedder selected but no API key (set "
                "[knowledge] api_key, MAVERICK_EMBED_API_KEY, or VOYAGE_API_KEY for Voyage's "
                "own endpoint); or set embedder = 'deterministic' for offline/dev retrieval."
            )
        return HostedEmbedder(
            model=cfg.get("model", "voyage-3"),
            base_url=base_url,
            api_key=key,
            dim=int(cfg.get("dim", 1024)),
            revision=str(cfg.get("revision") or "provider-model-contract"),
        )

    if provider == "cohere":
        key = cfg.get("api_key") or os.environ.get("COHERE_API_KEY") \
            or os.environ.get("MAVERICK_EMBED_API_KEY", "")
        if not key:
            raise RuntimeError(
                "knowledge: cohere embedder selected but no API key (set "
                "[knowledge] api_key, COHERE_API_KEY, or MAVERICK_EMBED_API_KEY); "
                "or set embedder = 'deterministic' for offline/dev retrieval."
            )
        return CohereEmbedder(
            model=cfg.get("model", "embed-v4.0"),
            api_key=key,
            dim=int(cfg.get("dim", 1024)),
            input_type=cfg.get("input_type", "search_document"),
            revision=str(cfg.get("revision") or "provider-model-contract"),
        )

    if provider == "local":
        import importlib.util
        if importlib.util.find_spec("sentence_transformers") is None:
            raise RuntimeError(
                "knowledge: local embedder selected but sentence-transformers is "
                "not installed (the 'local' extra); or set "
                "embedder = 'deterministic' for offline/dev retrieval."
            )
        from .local_embed import LocalEmbedder  # optional 'local' extra
        return LocalEmbedder(cfg.get("model", "all-MiniLM-L6-v2"), revision=cfg.get("revision"))

    raise ValueError(
        f"knowledge: unknown embedder provider {provider!r} "
        "(expected 'hosted', 'local', or 'deterministic')."
    )
