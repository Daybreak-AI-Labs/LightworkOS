"""Persisted vector-space identity; unknown implementations never guess reuse."""
from __future__ import annotations

import hashlib
import json
import math
import uuid

IDENTITY_KEY = "embedding_identity"
FINGERPRINT_KEY = "embedding_fingerprint"


def identity(embedder) -> tuple[dict, str]:
    resolver = getattr(embedder, "embedding_identity", None)
    if callable(resolver):
        descriptor = resolver()
    else:
        revision = getattr(embedder, "_knowledge_instance_revision", None)
        if revision is None:
            revision = uuid.uuid4().hex
            try:
                embedder._knowledge_instance_revision = revision
            except AttributeError as exc:
                raise ValueError("custom embedder must provide embedding_identity()") from exc
        descriptor = {"provider": f"{type(embedder).__module__}.{type(embedder).__qualname__}",
                      "revision": f"instance:{revision}"}
    descriptor = {**descriptor, "dimension": int(embedder.dim),
                  "preprocessing": descriptor.get("preprocessing", "text-verbatim.v1")}
    serialized = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(serialized) > 8192 or descriptor["dimension"] < 1:
        raise ValueError("knowledge embedding identity is invalid")
    return descriptor, hashlib.sha256(serialized.encode()).hexdigest()


def validate_batch(vectors, count: int, dimension: int) -> None:
    if len(vectors) != count or any(
        len(vector) != dimension or not any(vector) or any(
            isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value)
            for value in vector
        ) for vector in vectors
    ):
        raise ValueError("knowledge embedding batch has invalid dimensions or values")
