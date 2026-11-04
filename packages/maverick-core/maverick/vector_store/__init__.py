"""Vector-store adapters for cross-run semantic memory.

Adapters share a minimal interface: ``add(docs)``, ``query(text)``,
``delete(ids)``, ``count()``. Each adapter is behind its own optional
extra; users install only what they need.

Currently:
  - ChromaStore (``maverick-agent[chroma]``) — local persistent
    embedding store at ~/.maverick/vector_store/ (chmod 700).
  - QdrantStore (``maverick-agent[qdrant]``) — local persistent or
    remote Qdrant cluster; uses qdrant-client's built-in fastembed.
  - WeaviateStore (``maverick-agent[weaviate]``) — embedded by default or
    a remote cluster; server-side vectorizer module.
  - PgVectorStore (``maverick-agent[postgres]``) — Postgres + the pgvector
    extension; keeps vectors in the same DB as the world model. Takes an
    injected embedder (it does not embed itself).
"""
from .chroma_store import DEFAULT_PATH, ChromaStore  # noqa: F401
from .pgvector_store import PgVectorStore  # noqa: F401
from .qdrant_store import DEFAULT_PATH as QDRANT_DEFAULT_PATH
from .qdrant_store import QdrantStore  # noqa: F401
from .weaviate_store import WeaviateStore  # noqa: F401

__all__ = ["ChromaStore", "DEFAULT_PATH", "QdrantStore", "QDRANT_DEFAULT_PATH",
           "WeaviateStore", "PgVectorStore"]
