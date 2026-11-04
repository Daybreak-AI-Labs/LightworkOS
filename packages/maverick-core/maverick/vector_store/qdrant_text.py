"""Compatibility for Qdrant clients that removed the implicit text helpers.

Existing collections retain their named vector space. Only a genuinely new
collection without an explicit model uses FastEmbed's current default.
"""
from __future__ import annotations

from ..connector_attempts import current_invocation
from ._provider_accounting import metered_transport_call


def _field(model: str) -> str:
    # This is the official legacy Qdrant FastEmbed vector-name convention.
    return "fast-" + model.split("/")[-1].lower()


class TextBridge:
    def __init__(self, store):
        self.store = store
        self.encoder = None
        self.model = None

    def call(self, callback, category="retrieval"):
        invocation = current_invocation()
        invocation.check()
        result = metered_transport_call("qdrant", callback, hosted=self.store._remote, category=category)
        invocation.check()
        return result

    def info(self):
        client, collection = self.store._client, self.store._collection
        if not self.call(lambda: client.collection_exists(collection)):
            return None
        return self.call(lambda: client.get_collection(collection))

    def space(self, info, invocation):
        invocation.check()
        from fastembed import TextEmbedding
        from qdrant_client.models import Distance, VectorParams

        models = TextEmbedding.list_supported_models()
        selected = self.store._embedding_model or self.model
        recorded = (getattr(info.config, "metadata", None) or {}).get("lightwork_text_embedding") if info else None
        if recorded is not None:
            if not isinstance(recorded, dict) or not isinstance(recorded.get("model"), str):
                raise ValueError("The Qdrant collection's recorded embedding identity is invalid")
            if selected is not None and selected != recorded["model"]:
                raise ValueError("The selected model does not match the recorded Qdrant embedding identity")
            selected = recorded["model"]
        if selected is None and info is not None:
            vectors = info.config.params.vectors
            if not isinstance(vectors, dict) or len(vectors) != 1:
                raise ValueError("Choose an explicit matching embedding model for this existing Qdrant collection")
            field = next(iter(vectors))
            candidates = {row["model"] for row in models if _field(row["model"]) == field}
            if len(candidates) != 1:
                raise ValueError("The existing Qdrant vector space has no unique supported model; choose its original model")
            selected = candidates.pop()
        candidate = None
        if selected is None:
            # Do not introduce an application model default. This branch is
            # reachable only for a collection with no prior vectors/schema.
            invocation.check()
            candidate = TextEmbedding()
            invocation.check()
            selected = candidate.model_name
        candidates = [row for row in models if row["model"] == selected]
        if len(candidates) != 1:
            raise ValueError("The selected Qdrant text embedding model is not supported by FastEmbed")
        dimension = candidates[0]["dim"]
        field = _field(selected)
        params = VectorParams(size=dimension, distance=Distance.COSINE)
        if recorded is not None and recorded != self.identity(selected, field, dimension):
            raise ValueError("The recorded Qdrant embedding identity does not match its supported vector space")
        if info is not None:
            vectors = info.config.params.vectors
            existing = vectors.get(field) if isinstance(vectors, dict) else None
            if existing is None or existing.size != dimension or existing.distance != Distance.COSINE:
                raise ValueError("The embedding model does not match the existing Qdrant vector space; use its original model or rebuild explicitly")
        if candidate is None and (self.encoder is None or self.model != selected):
            invocation.check()
            candidate = TextEmbedding(model_name=selected)
            invocation.check()
        # A cancelled or rejected construction must never publish an encoder
        # without its validated identity for a later invocation to reuse.
        invocation.check()
        if candidate is not None:
            self.encoder, self.model = candidate, selected
        return field, params

    def encode(self, inputs, *, query, dimension, invocation):
        from ..skill.embeddings import validate_vectors

        vectors = []
        for offset in range(0, len(inputs), 16):
            invocation.check()
            batch = inputs[offset:offset + 16]
            generated = iter(self.encoder.query_embed(batch[0]) if query else self.encoder.passage_embed(batch))
            raw = []
            try:
                while True:
                    invocation.check()
                    try:
                        value = next(generated)
                    except StopIteration:
                        break
                    invocation.check()
                    if len(raw) >= len(batch):
                        raise ValueError("embedding batch does not match its inputs")
                    raw.append(value.tolist() if hasattr(value, "tolist") else value)
            finally:
                close = getattr(generated, "close", None)
                if callable(close):
                    close()
            invocation.check()
            vectors.extend(validate_vectors(raw, len(batch), dimension))
        return vectors

    @staticmethod
    def identity(model, field, dimension):
        return {"model": model, "field": field, "dimension": dimension, "distance": "Cosine"}

    def add(self, documents, point_ids, metadatas):
        from qdrant_client.models import PointStruct

        invocation = current_invocation()
        invocation.check()
        info = self.info()
        field, params = self.space(info, invocation)
        vectors = self.encode(documents, query=False, dimension=params.size, invocation=invocation)
        points = [PointStruct(id=point_id, vector={field: vector},
                              payload={"document": document, **metadata})
                  for point_id, vector, metadata, document in
                  zip(point_ids, vectors, metadatas, documents, strict=True)]
        # Embedding/preparation failures cannot delete or partially replace the
        # old records. Recheck the persisted schema before the single upsert.
        latest = self.info()
        if latest is None:
            if info is not None:
                raise ValueError("The Qdrant collection changed while preparing text; review before retrying")
            self.call(lambda: self.store._client.create_collection(
                self.store._collection, vectors_config={field: params},
                metadata={"lightwork_text_embedding": self.identity(self.model, field, params.size)}), "storage")
        else:
            self.space(latest, invocation)
        self.call(lambda: self.store._client.upsert(
            self.store._collection, points=points, wait=True), "storage")

    def query(self, text, *, tenant_id, top_k):
        invocation = current_invocation()
        invocation.check()
        info = self.info()
        if info is None:
            return []
        field, params = self.space(info, invocation)
        vector = self.encode([text], query=True, dimension=params.size, invocation=invocation)[0]
        want = max(1, min(top_k, 100))
        prefix = f"tenant:{tenant_id}:" if tenant_id is not None else None
        # Older text records have no __recall_tenant__ field. Retain the bounded
        # legacy search and mandatory logical-ID check for those records.
        result = self.call(lambda: self.store._client.query_points(
            self.store._collection, query=vector, using=field,
            limit=min(100, want * 10) if prefix else want, with_payload=True))
        out = []
        for point in result.points:
            payload = dict(point.payload or {})
            nsid = str(payload.pop("__nsid__", "") or point.id)
            if prefix is not None and not nsid.startswith(prefix):
                continue
            if prefix is None and nsid.startswith("tenant:"):
                continue
            document = payload.get("document", "")
            score = float(point.score)
            out.append({"id": nsid[len(prefix):] if prefix else nsid,
                        "document": document, "score": score,
                        "distance": 1.0 - score, "metadata": payload or None})
            if len(out) >= want:
                break
        return out

    def reset(self):
        from qdrant_client.models import Filter, FilterSelector

        if self.info() is None:
            return
        # Clear through the supported point API, retaining the entire schema
        # and model identity. Local Qdrant's delete/recreate can silently retain
        # its SQLite file when Windows still holds it open; never rely on that
        # filesystem deletion for a successful reset.
        self.call(lambda: self.store._client.delete(
            self.store._collection, points_selector=FilterSelector(filter=Filter()), wait=True), "update")
