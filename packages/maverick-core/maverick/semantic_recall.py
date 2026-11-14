"""Semantic cross-run recall over the vector_store adapters.

`recall_past_goals` (tools/recall.py) does a linear scan + on-demand
fastembed/jaccard re-rank: fine for small histories, but O(n) per query
and embeds every candidate every time. This module routes recall through a
persistent vector store (Chroma / Qdrant) when the operator configures one,
so similarity search is indexed and incremental — the "how well" companion
to the auto-recall wiring (the "when").

Design:
  * Fully opt-in. With no ``[memory] backend`` configured (the default),
    every entry point is a no-op and callers fall back to the existing
    lexical/embedding recall. The kernel never *requires* a vector store.
  * Fail-open. A missing optional dep (chromadb/qdrant-client), a backend
    error, or a malformed config degrades to "no semantic backend" — never
    an exception into the run.
  * Dependency-injectable. ``build_store`` is the single construction
    point; tests pass a fake store with the same ``add``/``query``
    interface, so the wiring is exercised without the heavy extras.

Document id convention: ``goal:<id>``. Replacements use a native single-record
upsert; adapters without that contract explicitly fall back to lexical recall.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def backend_name() -> str | None:
    """Configured vector-store backend, or None when semantic recall is off.

    Resolved from ``MAVERICK_VECTOR_STORE`` (env wins) or ``[memory]
    backend`` in config. Recognised: ``chroma``, ``qdrant``, ``weaviate``,
    ``pgvector``. Anything else (including unset / "none") disables the
    semantic path.
    """
    env = os.environ.get("MAVERICK_VECTOR_STORE")
    if env is not None:
        name = env.strip().lower()
    else:
        try:
            from .config import load_config
            name = str(load_config().get("memory", {}).get("backend", "")).strip().lower()
        except Exception:  # pragma: no cover -- config never blocks a run
            name = ""
    return name if name in ("chroma", "qdrant", "weaviate", "pgvector") else None


def _tenant_ns() -> str | None:
    """Backend-safe active-tenant namespace, or None for single-tenant use.

    The namespace is intentionally collision-resistant: a readable sanitized
    prefix is only a hint, and a SHA-256 suffix covers the raw tenant id. This
    keeps external vector-store collection names tenant-isolated even when
    tenant ids differ only by punctuation or after truncation.
    """
    try:
        from .paths import current_tenant
        t = current_tenant()
    except Exception:  # pragma: no cover -- tenancy never blocks a run
        return None
    if not t:
        return None
    import hashlib
    import re

    raw = str(t)
    safe = re.sub(r"[^0-9A-Za-z]", "_", raw).strip("_") or "tenant"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{safe[:32]}_{digest}"


def _sealed_recall() -> bool:
    """True when the vector store must hold **sealed** documents -- i.e. at-rest
    encryption is on.

    The backends embed the document they store, so a sealed document can't be
    embedded by the backend. In sealed mode we therefore embed the *plaintext*
    client-side (the local all-MiniLM model, same one pgvector/skills use) and
    hand the backend a precomputed vector + the sealed document, and we use a
    separate collection (``_s`` suffix) so sealed vectors never mix with legacy
    plaintext-embedded ones. Off -> behaviour is byte-for-byte unchanged.
    """
    try:
        from .crypto_at_rest import at_rest_enabled
        return bool(at_rest_enabled())
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _embed_texts(texts: list[str]) -> list[list[float]] | None:
    """Local embedding via the shared skill embedder (fastembed all-MiniLM), or
    None when no local embedder is available."""
    from .skill import embeddings as skill_embeddings
    return skill_embeddings.embed(texts)


_sealed_warned: set[str] = set()


def _warn_sealed_backend_unsupported(backend: str) -> None:
    """Warn once per backend that sealed semantic recall isn't wired for it."""
    if backend in _sealed_warned:
        return
    _sealed_warned.add(backend)
    log.warning(
        "semantic recall is disabled for the %r vector backend under at-rest "
        "encryption (sealing its stored documents is not implemented yet); "
        "falling back to lexical recall over the sealed world DB. Use the "
        "'chroma' or 'pgvector' backend for sealed semantic recall.", backend,
    )


def build_store(backend: str | None = None) -> Any | None:
    """Construct the configured vector store, or None if unavailable.

    Never raises: a missing extra or a backend error returns None so the
    caller falls back to lexical/embedding recall.

    Multi-tenant isolation: the SHARED external backends (chroma/qdrant/weaviate)
    run similarity SEARCH across every row in a collection -- id-namespacing
    isolates get/delete-by-id but NOT search -- so one tenant's recall would
    surface another tenant's goals. Give each tenant its OWN collection (the
    standard vector-DB multi-tenancy pattern; a wrong name errors loudly rather
    than leaking). No-op single-tenant. pgvector already scopes by a tenant_id
    column, so it keeps the shared collection.

    Under at-rest encryption (:func:`_sealed_recall`) the collection gets a
    ``_s`` suffix so the sealed, client-embedded vectors live apart from any
    legacy plaintext-embedded data.
    """
    backend = backend or backend_name()
    if backend is None:
        return None
    sealed = _sealed_recall()
    # Sealing the stored document requires a client-side precomputed embedding
    # (the backend can't embed sealed text). That path is implemented for the
    # backends whose vector space matches the local embedder -- chroma and
    # pgvector (both all-MiniLM-L6-v2). For qdrant/weaviate it is not wired yet,
    # so rather than leak plaintext to them we disable the semantic path under
    # at-rest and fall back to lexical recall over the sealed world DB.
    if sealed and backend in ("qdrant", "weaviate"):
        _warn_sealed_backend_unsupported(backend)
        return None
    ns = _tenant_ns()
    sfx = "_s" if sealed else ""
    try:
        if backend == "chroma":
            from .vector_store import ChromaStore
            return ChromaStore(collection=(f"t_{ns}__goals" if ns else "goals") + sfx)
        if backend == "qdrant":
            from .vector_store import QdrantStore
            # Explicit local vectors must not mix with legacy named-vector spaces.
            return QdrantStore(collection=(f"t_{ns}__goals" if ns else "goals") + "_v2" + sfx)
        if backend == "weaviate":
            from .vector_store import WeaviateStore
            # Weaviate class names must start with an uppercase letter.
            return WeaviateStore(collection=(f"T_{ns}__Goals" if ns else "Goals") + sfx)
        if backend == "pgvector":
            # pgvector does not embed; inject the local fastembed embedder
            # (the same one skills use). No embedder -> fail-open to lexical.
            from .skill import embeddings as skill_embeddings
            from .vector_store import PgVectorStore

            def _embed(texts):
                vecs = skill_embeddings.embed(list(texts))
                if vecs is None:
                    raise RuntimeError(
                        "pgvector recall needs a local embedder (install fastembed)")
                return vecs

            return PgVectorStore(collection="goals" + sfx, embedder=_embed)
    except Exception as e:  # pragma: no cover -- optional dep / backend down
        log.debug("semantic recall backend %s unavailable: %s", backend, e)
    return None


def _goal_text(goal) -> str:
    return f"{getattr(goal, 'title', '') or ''}\n\n{getattr(goal, 'description', '') or ''}".strip()


_PROCESS_STATE = uuid.uuid4().hex


def _state_dir(store: Any) -> Path:
    from .paths import data_dir

    identity = getattr(store, "recall_identity", None) or f"{_PROCESS_STATE}:{id(store)}"
    key = hashlib.sha256(f"{type(store).__module__}.{type(store).__name__}:{identity}:{_sealed_recall()}".encode()).hexdigest()
    return data_dir("semantic_recall_state") / key


def index_status(*, store: Any | None = None) -> str:
    """Local lifecycle state, not a claim that every world goal was indexed.

    Pending markers survive crashes/unknown transport outcomes. Only an explicit
    successful retry of that goal clears its marker; another goal cannot do so.
    """
    store = store if store is not None else build_store()
    if store is None:
        return "unavailable" if backend_name() else "disabled"
    if (not callable(getattr(store, "upsert_one", None))
            or not getattr(store, "supports_atomic_recall", True)):
        return "unsupported"
    try:
        state = _state_dir(store)
        if next(state.glob("*.pending"), None) is not None:
            return "rebuild_required"
        return "ready" if (state / "revision").is_file() else "absent"
    except Exception:
        return "unavailable"


def index_goal(goal, *, store: Any | None = None) -> bool:
    """Upsert one goal into the vector store. Returns True if indexed.

    No-op (returns False) when no backend is configured/available. Metadata is
    limited to non-sensitive routing keys (``goal_id``/``status``); the sensitive
    ``title``/``result`` are NOT duplicated here -- callers hydrate them from the
    sealed world DB by ``goal_id``.

    The document is the goal's title+description. Under at-rest encryption it is
    **sealed** before storage (embedded client-side from the plaintext first, so
    similarity search is preserved); with at-rest off it is stored plaintext as
    before. If at-rest is on but no local embedder is available, indexing is
    skipped (returns False) rather than shipping plaintext to the store -- the
    caller falls back to lexical recall over the sealed world DB. Never raises.
    """
    try:
        from .file_lock import atomic_write_text, cross_process_lock
        from .pilot_learning import excluded
        from .skill.embeddings import validate_vectors

        gid = getattr(goal, "id", None)
        if isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0 or excluded(gid):
            return False
        store = store if store is not None else build_store()
        if (store is None or not callable(getattr(store, "upsert_one", None))
                or not getattr(store, "supports_atomic_recall", True)):
            return False
        text = _goal_text(goal)
        state = _state_dir(store)
        with cross_process_lock(state / "write", strict=True):
            if (state / f"{gid}.removed").exists():
                return False
            pending = state / f"{gid}.pending"
            atomic_write_text(pending, "rebuild_required")
            if not text or len(text) > 65536:
                # Deterministic: a retry can never index this text. Drop any
                # earlier record of the goal so the index is consistent again,
                # instead of leaving a marker that disables recall for good.
                store.delete([f"goal:{gid}"])
                atomic_write_text(state / "revision", uuid.uuid4().hex)
                pending.unlink()
                return False
            document, vector = text, None
            if _sealed_recall() or getattr(store, "requires_precomputed_embeddings", False):
                vector = validate_vectors(_embed_texts([text]), 1)[0]
            if _sealed_recall():
                from .crypto_at_rest import seal_to_str
                document = seal_to_str(text)
            # Authority can change during preparation. Recheck before publishing
            # and before releasing search results, without caching decisions.
            if excluded(gid):
                return False
            store.upsert_one(document, id=f"goal:{gid}",
                             metadata={"goal_id": gid, "status": getattr(goal, "status", None)},
                             embedding=vector)
            if excluded(gid):
                store.delete([f"goal:{gid}"])
                return False
            atomic_write_text(state / "revision", uuid.uuid4().hex)
            pending.unlink()
            return True
    except Exception as e:  # pragma: no cover -- backend write error
        log.debug("semantic index of goal failed: %s", e)
        return False


def remove_goal(goal_id: int, *, store: Any | None = None) -> bool:
    """Explicit semantic removal; late indexing cannot resurrect this goal ID.

    This removes only the derived semantic record, not the canonical world goal.
    A persisted tombstone shares the index publication fence. Failed deletion is
    incomplete, remains invisible to search, and may be explicitly retried.
    """
    try:
        from .file_lock import atomic_write_text, cross_process_lock

        if isinstance(goal_id, bool) or not isinstance(goal_id, int) or goal_id <= 0:
            return False
        store = store if store is not None else build_store()
        if store is None or not callable(getattr(store, "delete", None)):
            return False
        state = _state_dir(store)
        with cross_process_lock(state / "write", strict=True):
            atomic_write_text(state / f"{goal_id}.removed", "removed")
            pending = state / f"{goal_id}.pending"
            atomic_write_text(pending, "rebuild_required")
            store.delete([f"goal:{goal_id}"])
            atomic_write_text(state / "revision", uuid.uuid4().hex)
            pending.unlink()
            return True
    except Exception as exc:
        log.debug("semantic removal failed: %s", exc)
        return False


def search(
    query: str,
    *,
    k: int = 5,
    store: Any | None = None,
    exclude_goal_id: int | None = None,
) -> list[tuple[float, dict]] | None:
    """Semantic top-k over indexed goals.

    Returns a list of ``(score, metadata)`` where score is a similarity in
    [0, 1] (``1 - distance``, clamped) and metadata carries only routing keys
    (goal_id / status); hydrate title/result from the world DB by goal_id (the
    vector store keeps no plaintext copy). Returns ``None`` when no backend is
    configured/available, so
    the caller knows to fall back to lexical/embedding recall (an empty list
    means "backend present, no matches"). Never raises.
    """
    if not query or len(query) > 65536 or isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        return None
    store = store if store is not None else build_store()
    if store is None:
        return None
    try:
        if index_status(store=store) != "ready":
            return None
        state = _state_dir(store)
        revision = (state / "revision").read_text()
        k = min(k, 99)
        # Over-fetch so we can drop the current goal then trim to k. Under at-rest
        # the stored documents are sealed, so the query is embedded client-side
        # (same model the index used) and searched by vector; otherwise the
        # backend embeds the query text as before.
        if _sealed_recall() or getattr(store, "requires_precomputed_embeddings", False):
            from .skill.embeddings import validate_vectors
            qv = validate_vectors(_embed_texts([query]), 1)
            hits = store.query(top_k=k + 1, embedding=qv[0])
        else:
            hits = store.query(query, top_k=k + 1)
    except Exception as e:  # pragma: no cover -- backend query error
        log.debug("semantic search failed: %s", e)
        return None
    from .pilot_learning import excluded

    out: list[tuple[float, dict]] = []
    for h in hits or []:
        if not isinstance(h, dict):
            return None
        meta = h.get("metadata") or {}
        if not isinstance(meta, dict):
            return None
        gid = meta.get("goal_id")
        if isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0:
            return None
        if exclude_goal_id is not None and gid == exclude_goal_id:
            continue
        if excluded(gid) or (state / f"{gid}.removed").exists():
            continue
        dist = h.get("distance")
        # Chroma returns L2/cosine distance; map to a [0,1] similarity.
        if dist is None:
            score = 0.0
        else:
            try:
                distance = float(dist)
                if not math.isfinite(distance):
                    return None
                score = max(0.0, min(1.0, 1.0 - distance))
            except (TypeError, ValueError):
                score = 0.0
        out.append((score, {"goal_id": gid, "status": meta.get("status")}))
        if len(out) >= k:
            break
    try:
        if index_status(store=store) != "ready" or (state / "revision").read_text() != revision:
            return None
        return [(score, meta) for score, meta in out
                if not excluded(meta["goal_id"]) and not (state / f"{meta['goal_id']}.removed").exists()]
    except Exception:
        return None


__all__ = ["backend_name", "build_store", "index_goal", "index_status", "remove_goal", "search"]
