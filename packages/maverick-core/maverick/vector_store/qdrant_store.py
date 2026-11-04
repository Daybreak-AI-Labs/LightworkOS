"""Qdrant vector store adapter.

Embedding-backed memory using Qdrant. Mirrors the Chroma adapter API
(``add(docs)``, ``query(text, top_k)``, ``delete(ids)``, ``count()``)
so callers can swap one for the other.

Defaults to local persistent mode under ``~/.maverick/qdrant/`` (chmod
700). Configurable:
  - ``MAVERICK_QDRANT_PATH`` -> local persistent path
  - ``MAVERICK_QDRANT_URL``  -> remote server URL (overrides path)
  - ``MAVERICK_QDRANT_API_KEY`` -> remote API key

Optional dep behind ``[qdrant]`` extra. Text embeddings run client-side
through FastEmbed. Older clients retain their text helpers; current clients
use native point operations while preserving the recorded embedding space.
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid as _uuid
from pathlib import Path

from ..paths import data_dir
from ._provider_accounting import BestEffortTransportError, metered_transport_call

log = logging.getLogger(__name__)


DEFAULT_PATH = data_dir("qdrant", tenant=None)


def _default_path() -> Path:
    """Resolve the default local Qdrant path for the active tenant."""
    return data_dir("qdrant")


def _active_tenant() -> str | None:
    """Tenant scope for vector ids, or ``None`` for legacy single-tenant use."""
    try:
        from ..paths import current_tenant
        return current_tenant()
    except Exception:  # pragma: no cover -- tenancy never blocks vector ops
        return None


# Stable namespace so a given logical id always maps to the same point id.
_POINT_NS = _uuid.UUID("6f9b8c1e-3a2d-5e4f-8b7a-0c1d2e3f4a5b")
# Payload key holding the logical (tenant-namespaced) id -- see _point_id.
_NSID_KEY = "__nsid__"


def _point_id(doc_id: str, tenant_id: str | None) -> str:
    """A valid Qdrant point id (UUID) derived deterministically from the logical
    (tenant-namespaced) id. Qdrant only accepts unsigned-int or UUID point ids,
    so the raw ``tenant:<t>:<doc>`` string (or an arbitrary caller id) can't be
    used directly -- it's rejected with a 400. The logical id itself is stored
    in the payload under ``_NSID_KEY`` so query()/delete() can still scope by
    tenant and recover the caller's original id."""
    return str(_uuid.uuid5(_POINT_NS, _stored_id(doc_id, tenant_id)))


def _stored_id(doc_id: str, tenant_id: str | None) -> str:
    """Namespace an id by tenant so one tenant can't read/delete another's
    vectors -- the same scheme the pgvector adapter uses for its row ids."""
    if tenant_id is None:
        return doc_id
    return f"tenant:{tenant_id}:{doc_id}"


class QdrantStore:
    """Thin wrapper over qdrant-client.

    Lazy import: qdrant-client + fastembed are heavy. We don't pay the
    cost unless a store is instantiated.
    """

    def __init__(
        self,
        collection: str = "maverick",
        path: Path | None = None,
        url: str | None = None,
        api_key: str | None = None,
        embedding_model: str | None = None,
    ):
        try:
            from qdrant_client import QdrantClient  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "qdrant-client not installed. Run: python -m pip install -e './packages/maverick-core[qdrant]'"
            ) from e
        from qdrant_client import QdrantClient

        from ..env_setting import env_or_config

        url = url or env_or_config("MAVERICK_QDRANT_URL", "memory", "qdrant_url")
        api_key = api_key or env_or_config("MAVERICK_QDRANT_API_KEY", "memory", "qdrant_api_key")
        self._remote = bool(url)

        if url:
            # Qdrant's default compatibility check may contact the server while
            # the client is constructed. Keep that physical call behind the
            # same fail-closed admission boundary as every explicit method.
            self._client = metered_transport_call(
                "qdrant",
                lambda: QdrantClient(url=url, api_key=api_key),
                category="retrieval",
            )
        else:
            store_path = Path(path or os.environ.get("MAVERICK_QDRANT_PATH") or _default_path())
            store_path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(store_path, 0o700)
            except OSError:
                pass
            self._client = QdrantClient(path=str(store_path))

        self._collection = collection
        self._embedding_model = embedding_model
        self._legacy_text = all(callable(getattr(self._client, name, None)) for name in ("add", "query"))
        self._text_bridge = None
        if embedding_model and self._legacy_text:
            # An explicit model failure must never silently switch vector space.
            try:
                self._client.set_model(embedding_model)
            except Exception:
                try:
                    self._client.close()
                except Exception:
                    log.warning("qdrant: client cleanup failed after rejected text model")
                raise
        location = url or str(store_path.resolve())
        self.recall_identity = hashlib.sha256(f"{location}:{collection}".encode()).hexdigest()
        self.requires_precomputed_embeddings = True
        self.supports_atomic_recall = all(callable(getattr(self._client, name, None)) for name in (
            "upsert", "query_points", "collection_exists", "get_collection",
        ))

    def _text(self):
        if self._text_bridge is None:
            from .qdrant_text import TextBridge
            self._text_bridge = TextBridge(self)
        return self._text_bridge

    def upsert_one(self, document: str, *, id: str, metadata: dict,
                   embedding: list[float] | None = None) -> None:
        """Atomic single-point replacement with an explicitly prepared vector.

        Unlike upload helpers this issues no automatic write retries. Transport
        errors after commit have an unknown outcome; the recall layer records
        that uncertainty and falls back until explicitly re-indexed.
        """
        from qdrant_client.models import Distance, PointStruct, VectorParams

        from ..skill.embeddings import validate_vectors

        vector = validate_vectors([embedding], 1)[0]
        tenant_id = _active_tenant()
        payload = {**metadata, _NSID_KEY: _stored_id(id, tenant_id), "document": document,
                   "__recall_tenant__": tenant_id or ""}
        point = PointStruct(id=_point_id(id, tenant_id), vector=vector, payload=payload)
        exists = metered_transport_call(
            "qdrant", lambda: self._client.collection_exists(self._collection),
            hosted=self._remote, category="retrieval",
        )
        if not exists:
            metered_transport_call(
                "qdrant", lambda: self._client.create_collection(
                    self._collection, vectors_config=VectorParams(size=len(vector), distance=Distance.COSINE)),
                hosted=self._remote, category="storage",
            )
        else:
            info = metered_transport_call(
                "qdrant", lambda: self._client.get_collection(self._collection),
                hosted=self._remote, category="retrieval",
            )
            params = info.config.params.vectors
            if (not isinstance(params, VectorParams) or params.size != len(vector)
                    or params.distance != Distance.COSINE):
                raise ValueError("recall vector space does not match the existing collection")
        metered_transport_call(
            "qdrant", lambda: self._client.upsert(self._collection, points=[point], wait=True),
            hosted=self._remote, category="storage",
        )

    def add(
        self,
        documents: list[str],
        *,
        ids: list[str] | None = None,
        metadatas: list[dict] | None = None,
    ) -> None:
        """Index a batch of documents. ids auto-generated if not provided.

        Requires fastembed for the default embedder. Errors propagate so
        the caller can surface a helpful install hint.
        """
        if not documents:
            return
        import uuid as _uuid
        if ids is None:
            ids = [str(_uuid.uuid4()) for _ in documents]
        # Fail fast with a clear message rather than a backend-internal
        # error deep in the upsert when the parallel arrays don't line up.
        if len(ids) != len(documents):
            raise ValueError(
                f"ids length {len(ids)} != documents length {len(documents)}"
            )
        if metadatas is not None and len(metadatas) != len(documents):
            raise ValueError(
                f"metadatas length {len(metadatas)} != documents length {len(documents)}"
            )
        tenant_id = _active_tenant()
        # Point ids are deterministic UUIDs (Qdrant rejects arbitrary strings);
        # the logical tenant-namespaced id rides in the payload so query()/delete()
        # can scope by tenant and recover the caller's original id.
        metas: list[dict] = []
        for i in range(len(documents)):
            m = dict(metadatas[i]) if metadatas else {}
            m[_NSID_KEY] = _stored_id(ids[i], tenant_id)
            metas.append(m)
        if not self._legacy_text:
            return self._text().add(documents, [_point_id(i, tenant_id) for i in ids], metas)
        metered_transport_call(
            "qdrant",
            lambda: self._client.add(
                collection_name=self._collection,
                documents=documents,
                ids=[_point_id(i, tenant_id) for i in ids],
                metadata=metas,
            ),
            hosted=self._remote,
            category="storage",
        )

    def query(self, text: str | None = None, *, top_k: int = 5,
              embedding: list[float] | None = None) -> list[dict]:
        """Top-k similarity search. Returns list of
        {id, document, score, distance, metadata}.

        Results come back highest-similarity-first from Qdrant. ``score``
        is the raw similarity from the collection's metric; ``distance``
        is ``1 - score`` for "lower = closer" parity with the Chroma
        adapter. NOTE: ``1 - score`` only orders correctly for the
        default cosine (0..1) metric; for a DOT/EUCLID collection, sort
        by raw ``score`` (already similarity-ordered by the backend)
        rather than ``distance``.
        """
        if embedding is not None:
            return self._query_vector(embedding, top_k=top_k)
        if not text:
            return []
        tenant_id = _active_tenant()
        if not self._legacy_text:
            return self._text().query(text, tenant_id=tenant_id, top_k=top_k)
        want = max(1, min(top_k, 100))
        prefix = f"tenant:{tenant_id}:" if tenant_id is not None else None
        # The similarity search spans the whole collection, but writes are
        # namespaced by `_stored_id` (the same isolation boundary delete() uses).
        # Without scoping the read, query() returned OTHER tenants' vectors.
        # Over-fetch and drop hits outside this tenant's prefix; strip the prefix
        # so the caller gets back its original doc id. (Best-effort top_k: a tenant
        # whose vectors are sparse among many may get < top_k -- a server-side
        # payload filter would be exact, but this matches the id-namespacing design.)
        fetch = want if prefix is None else min(100, want * 10)
        results = metered_transport_call(
            "qdrant",
            lambda: self._client.query(
                collection_name=self._collection,
                query_text=text,
                limit=fetch,
            ),
            hosted=self._remote,
            category="retrieval",
        )
        out: list[dict] = []
        for r in results:
            meta = dict(getattr(r, "metadata", None) or {})
            # The caller's id lives in the payload (point ids are opaque UUIDs);
            # fall back to the point id for legacy rows written before that.
            nsid = str(meta.pop(_NSID_KEY, None) or getattr(r, "id", ""))
            if prefix is not None:
                if not nsid.startswith(prefix):
                    continue
                rid = nsid[len(prefix):]
            else:
                rid = nsid
            score = getattr(r, "score", None)
            score_f = float(score) if isinstance(score, (int, float)) else None
            distance = (1.0 - score_f) if score_f is not None else None
            out.append({
                "id": rid,
                "document": getattr(r, "document", "") or "",
                "score": score_f,
                "distance": distance,
                "metadata": meta or None,
            })
            if len(out) >= want:
                break
        return out

    def _query_vector(self, embedding: list[float], *, top_k: int) -> list[dict]:
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        from ..skill.embeddings import validate_vectors

        vector = validate_vectors([embedding], 1)[0]
        tenant_id = _active_tenant()
        # A dedicated payload field permits exact server-side tenant filtering;
        # logical id prefix filtering cannot express an exact indexed predicate.
        scope = tenant_id or ""
        result = metered_transport_call(
            "qdrant", lambda: self._client.query_points(
                self._collection, query=vector, limit=max(1, min(top_k, 100)),
                query_filter=Filter(must=[FieldCondition(key="__recall_tenant__", match=MatchValue(value=scope))]),
                with_payload=True,
            ), hosted=self._remote, category="retrieval",
        )
        prefix = f"tenant:{tenant_id}:" if tenant_id is not None else ""
        out = []
        for point in result.points:
            payload = dict(point.payload or {})
            nsid = str(payload.pop(_NSID_KEY, ""))
            if payload.pop("__recall_tenant__", None) != scope or not nsid.startswith(prefix):
                continue
            out.append({"id": nsid[len(prefix):], "document": payload.pop("document", ""),
                        "distance": 1.0 - float(point.score), "metadata": payload})
        return out

    def delete(self, ids: list[str]) -> None:
        if not ids:
            return
        from qdrant_client.models import PointIdsList
        tenant_id = _active_tenant()
        metered_transport_call(
            "qdrant",
            lambda: self._client.delete(
                collection_name=self._collection,
                points_selector=PointIdsList(
                    points=[_point_id(i, tenant_id) for i in ids]
                ),
            ),
            hosted=self._remote,
            category="update",
        )

    def count(self) -> int:
        def dispatch():
            try:
                return self._client.count(
                    collection_name=self._collection,
                    exact=True,
                )
            except Exception as exc:
                raise BestEffortTransportError("qdrant count failed") from exc

        try:
            res = metered_transport_call(
                "qdrant",
                dispatch,
                hosted=self._remote,
                category="retrieval",
            )
            return int(getattr(res, "count", 0))
        except BestEffortTransportError as exc:
            # Log so a backend outage isn't silently reported as an empty store.
            log.warning("qdrant: count failed (%s); reporting 0", exc.__cause__)
            return 0

    def reset(self) -> None:
        """Clear the collection. Tests use this; runtime
        users should prefer ``delete(ids)``.

        Current clients clear points while retaining schema and model identity.
        Legacy clients recreate after the drop so a query before the next add doesn't
        hit a missing collection. ``client.add`` auto-creates with the
        fastembed vector params, so recreate with the same params; if the
        client can't supply them (older versions / no model loaded) we leave
        the next ``add`` to lazily recreate."""
        if not self._legacy_text:
            return self._text().reset()
        def dispatch() -> None:
            first_error: Exception | None = None
            try:
                self._client.delete_collection(self._collection)
            except Exception as exc:
                first_error = exc
            try:
                self._client.create_collection(
                    collection_name=self._collection,
                    vectors_config=self._client.get_fastembed_vector_params(),
                )
            except Exception as exc:  # next add() recreates lazily
                first_error = first_error or exc
            if first_error is not None:
                raise BestEffortTransportError("qdrant reset failed") from first_error

        try:
            metered_transport_call(
                "qdrant",
                dispatch,
                hosted=self._remote,
                category="update",
            )
        except BestEffortTransportError as exc:
            log.debug("qdrant: reset failed: %s", exc.__cause__)


__all__ = ["QdrantStore", "DEFAULT_PATH"]
