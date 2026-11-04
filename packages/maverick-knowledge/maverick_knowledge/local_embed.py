"""Local sentence-transformers embedder (the optional ``local`` extra).

Selected by ``[knowledge] embedder = "local"``. The model is loaded lazily on
first use so importing the package stays cheap and dependency-free; the heavy
``sentence-transformers`` dependency ships in the ``local`` extra. Vectors are
L2-normalized to match the other embedders so cosine ranking is consistent.
"""
from __future__ import annotations

import re
import uuid


class LocalEmbedder:
    """Embeds with a local sentence-transformers model (default MiniLM, 384-dim)."""

    def __init__(self, model: str = "all-MiniLM-L6-v2", *, revision: str | None = None):
        self.model_name = model
        self.revision = revision
        self._instance_revision = uuid.uuid4().hex
        self._model = None
        # all-MiniLM-L6-v2 is 384-dim; refined from the model once it loads.
        self.dim = 384

    def _ensure_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            kwargs = {"revision": self.revision} if self.revision else {}
            self._model = SentenceTransformer(self.model_name, **kwargs)
            reported = self._model.get_sentence_embedding_dimension()
            if reported:
                self.dim = int(reported)
        return self._model

    def embedding_identity(self) -> dict:
        model = self._ensure_model()
        first = getattr(model, "_first_module", None)
        transformer = first() if callable(first) else None
        configuration = getattr(getattr(transformer, "auto_model", None), "config", None)
        resolved = getattr(configuration, "_commit_hash", None)
        # A branch name such as "main" is not immutable. Reuse only a resolved
        # weights commit (or an explicit commit actually passed to the loader).
        revision = next((value for value in (resolved, self.revision)
                         if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40,64}", value)), None)
        return {"provider": "sentence-transformers", "model": self.model_name,
                "revision": revision or f"instance:{self._instance_revision}",
                "preprocessing": "text-verbatim-normalized.v1"}

    def embed(self, texts: list[str]) -> list[list[float]]:
        model = self._ensure_model()
        vectors = model.encode(list(texts), normalize_embeddings=True)
        return [[float(x) for x in v] for v in vectors]
