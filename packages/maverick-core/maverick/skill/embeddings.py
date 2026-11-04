"""Embedding-based skill retrieval (optional, falls back to lexical).

Uses fastembed (ONNX) when installed; cached embeddings live in
``~/.maverick/skill_embeddings.json`` keyed by canonical text and model identity.

Falls back gracefully to ``skills._relevant_skills_lexical`` when
fastembed isn't installed or any error occurs at retrieval time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from ..paths import data_dir

log = logging.getLogger(__name__)

CACHE_PATH = data_dir("skill_embeddings.json")
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
_CACHE_SCHEMA = "lightwork.retrieval-embeddings.v2"
_PREPROCESSING = "skill-name-triggers-first-line.v1"
_MAX_ENTRIES = 2048
_MAX_TEXT = 8192
_MAX_DIM = 4096
_MAX_CACHE_BYTES = 16 * 1024 * 1024
_BATCH_SIZE = 64
_PROCESS_REVISION = uuid.uuid4().hex
_PROCESS_CACHES: OrderedDict[str, dict] = OrderedDict()
_MAX_PROCESS_CACHES = 4


def _cache_path():
    """Resolve the cache path at CALL time so it follows the ACTIVE tenant.

    ``CACHE_PATH`` is computed once at import and snapshots whichever tenant was
    active then; in a long-lived multi-tenant process (the dashboard) every
    later load/save would hit that frozen path, so tenant B reads/writes tenant
    A's vector cache -- and since the cache is keyed by skill *name* and learned
    skills are tenant-scoped, a same-named skill could be served another
    tenant's vector. The sibling ``stats._resolve`` already re-reads the tenant
    per call for exactly this reason; mirror it. The module-attr stays the
    fallback so the single-tenant layout and tests monkeypatching ``CACHE_PATH``
    keep working.
    """
    from ..paths import current_tenant
    if current_tenant():
        return data_dir("skill_embeddings.json")
    return CACHE_PATH

_model = None  # lazy singleton
_model_name = None
_model_lock = threading.RLock()  # also fences identity against concurrent embedding
_identity_model = None
_identity_revision = uuid.uuid4().hex


def _have_fastembed() -> bool:
    try:
        import fastembed  # noqa: F401
        return True
    except ImportError:
        return False


def _get_model():
    global _model, _model_name
    if _model is not None and _model_name in (None, MODEL_NAME):
        _model_name = MODEL_NAME
        return _model
    # Double-checked lock: without it, concurrent first calls (FastAPI
    # threadpool) each construct a TextEmbedding -- an expensive ONNX model
    # load -- and clobber _model.
    with _model_lock:
        if _model is not None and _model_name == MODEL_NAME:
            return _model
        try:
            from fastembed import TextEmbedding
        except ImportError:
            return None
        try:
            _model = TextEmbedding(model_name=MODEL_NAME)
            _model_name = MODEL_NAME
            return _model
        except Exception as e:  # pragma: no cover
            log.error("failed to load embedding model: %s", e)
            return None


def embed(texts: list[str]) -> list[list[float]] | None:
    try:
        with _model_lock:
            model = _get_model()
            if model is None or not texts:
                return None
            return validate_vectors([list(map(float, v)) for v in model.embed(texts)], len(texts))
    except Exception as e:  # pragma: no cover
        log.error("embedding call failed: %s", e)
        return None


def embedding_identity() -> dict[str, str]:
    """Identity of the actual loaded local model, without a guessed revision.

    Fastembed's name alone does not attest a weights revision. Unless a loader
    supplies ``cache_revision``, scope reuse to this loaded instance and process.
    A restart/reload then rebuilds safely instead of claiming unchanged weights.
    No hosted embedder is silently substituted on this optional local path.
    """
    global _identity_model, _identity_revision
    with _model_lock:
        model = _get_model()
        if model is not _identity_model:
            _identity_model = model
            _identity_revision = uuid.uuid4().hex
        try:
            provider_version = version("fastembed")
        except PackageNotFoundError:
            provider_version = "unavailable"
        revision = getattr(model, "cache_revision", None)
        return {
            "provider": "fastembed", "provider_version": provider_version,
            "model": MODEL_NAME,
            "revision": str(revision) if revision else f"process:{_PROCESS_REVISION}:instance:{_identity_revision}",
            "preprocessing": _PREPROCESSING,
        }


def validate_vectors(vectors, count: int, dimension: int | None = None) -> list[list[float]]:
    """Reject partial, non-finite, mixed-space and unusable embedding batches."""
    if not isinstance(vectors, list | tuple) or len(vectors) != count:
        raise ValueError("embedding batch does not match its inputs")
    result = []
    for vector in vectors:
        if not isinstance(vector, list | tuple) or not 1 <= len(vector) <= _MAX_DIM:
            raise ValueError("embedding dimension is invalid")
        if dimension is None:
            dimension = len(vector)
        if len(vector) != dimension or any(
            isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value)
            for value in vector
        ):
            raise ValueError("embedding values or dimensions are invalid")
        values = [float(value) for value in vector]
        if not any(values):
            raise ValueError("embedding vector has no direction")
        result.append(values)
    return result


@dataclass
class CachedEmbedding:
    name: str
    text: str
    mtime: float
    vector: list[float]
    content_sha256: str = ""


def _load_cache(*, path: Path | None = None, identity: Mapping | None = None,
                dimension: int | None = None) -> dict[str, CachedEmbedding]:
    path = path or _cache_path()
    if not path.exists():
        return {}
    try:
        with path.open("rb") as source:
            payload = source.read(_MAX_CACHE_BYTES + 1)
        if len(payload) > _MAX_CACHE_BYTES:
            return {}
        raw = json.loads(payload)
        if (not isinstance(raw, dict) or raw.get("schema") != _CACHE_SCHEMA
            or raw.get("identity") != (identity or embedding_identity())
            or not isinstance(raw.get("entries"), dict)
            or len(raw["entries"]) > _MAX_ENTRIES):
            return {}
    except (ValueError, OSError, UnicodeError, RecursionError):
        return {}
    out: dict[str, CachedEmbedding] = {}
    for name, entry in raw["entries"].items():
        try:
            if (not isinstance(name, str) or not name or len(name) > 512
                or not isinstance(entry, dict) or not isinstance(entry.get("text"), str)
                or len(entry["text"]) > _MAX_TEXT
                or entry.get("content_sha256") != _text_digest(entry["text"])
                or isinstance(entry.get("mtime"), bool)
                or not isinstance(entry.get("mtime"), int | float)
                or not math.isfinite(entry["mtime"])):
                continue
            vector = validate_vectors([entry["vector"]], 1, dimension)[0]
            if entry.get("dimension") != len(vector):
                continue
            if dimension is None:
                dimension = len(vector)
            out[name] = CachedEmbedding(name, entry["text"], float(entry["mtime"]),
                                        vector, entry["content_sha256"])
        except (ValueError, TypeError, KeyError):
            continue
    return out


def _save_cache(cache: dict[str, CachedEmbedding], *, path: Path | None = None,
                identity: Mapping | None = None) -> None:
    path = path or _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    from ..file_lock import atomic_write_text
    atomic_write_text(path, _cache_payload(cache, identity))


def _cache_payload(cache: dict[str, CachedEmbedding], identity: Mapping | None) -> str:
    entries = {
        name: {"text": e.text, "mtime": e.mtime, "vector": e.vector,
               "content_sha256": _text_digest(e.text), "dimension": len(e.vector)}
        for name, e in cache.items()
    }
    # Atomic write (temp + os.replace) so a crash mid-write or a concurrent
    # writer can't leave a truncated/corrupt cache -- the same pattern the
    # sibling skill.stats module uses.
    payload = json.dumps({"schema": _CACHE_SCHEMA,
                          "identity": dict(identity or embedding_identity()), "entries": entries},
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(entries) > _MAX_ENTRIES or len(payload.encode()) > _MAX_CACHE_BYTES:
        raise ValueError("embedding cache exceeds its storage boundary")
    return payload


def _text_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def cached_corpus_vectors(texts: Mapping[str, str], *, namespace: str = "skills",
                          mtimes: Mapping[str, float] | None = None,
                          dimension: int | None = None,
                          identity: Mapping | None = None) -> dict[str, CachedEmbedding] | None:
    """Cache an exact corpus snapshot; incomplete refreshes fall back as a whole."""
    if namespace not in {"skills", "capabilities"}:
        raise ValueError("unsupported embedding cache namespace")
    if len(texts) > _MAX_ENTRIES or any(
        not isinstance(key, str) or not key or len(key) > 512
        or not isinstance(text, str) or len(text) > _MAX_TEXT for key, text in texts.items()
    ):
        return None
    from ..file_lock import cross_process_lock

    selected_identity = dict(identity or embedding_identity())
    cache_identity = {**selected_identity, "corpus": namespace,
                      "projection": (_PREPROCESSING if namespace == "skills"
                                     else "catalog-name-summary.v1")}
    path = _cache_path() if namespace == "skills" else data_dir("capability_embeddings.json")
    # Unattested weights are deliberately process scoped. They must not evict
    # another worker's warm corpus from a shared on-disk cache on every request.
    process_local = str(selected_identity.get("revision", "")).startswith("process:")
    cache_key = json.dumps([str(path.resolve()), cache_identity, dimension], sort_keys=True)
    lock = _model_lock if process_local else cross_process_lock(path, strict=True)
    with lock:
        previous = (deepcopy(_PROCESS_CACHES.get(cache_key, {})) if process_local
                    else _load_cache(path=path, identity=cache_identity, dimension=dimension))
        cache = {
            name: entry for name, entry in previous.items()
            if name in texts and entry.content_sha256 == _text_digest(texts[name])
        }
        missing = [name for name in texts if name not in cache]
        if cache and dimension is None:
            dimension = len(next(iter(cache.values())).vector)
        for start in range(0, len(missing), _BATCH_SIZE):
            batch = missing[start:start + _BATCH_SIZE]
            try:
                vectors = validate_vectors(embed([texts[name] for name in batch]), len(batch), dimension)
            except (ValueError, TypeError):
                return None
            if vectors and dimension is None:
                dimension = len(vectors[0])
            for name, vector in zip(batch, vectors, strict=True):
                cache[name] = CachedEmbedding(name, texts[name], (mtimes or {}).get(name, 0.0),
                                             vector, _text_digest(texts[name]))
        if embedding_identity() != selected_identity:
            return None
        # This path also persists deletions when there were no embedding misses.
        if process_local:
            if cache != previous or set(previous) != set(texts):
                _cache_payload(cache, cache_identity)  # enforce the same byte boundary in memory
            _PROCESS_CACHES[cache_key] = deepcopy(cache)
            _PROCESS_CACHES.move_to_end(cache_key)
            while len(_PROCESS_CACHES) > _MAX_PROCESS_CACHES:
                _PROCESS_CACHES.popitem(last=False)
        elif cache != previous or set(previous) != set(texts):
            _save_cache(cache, path=path, identity=cache_identity)
        return cache


def _skill_to_embed_text(skill) -> str:
    triggers = " | ".join(skill.triggers) if skill.triggers else ""
    first_line = (skill.body or "").splitlines()[0] if skill.body else ""
    return f"{skill.name}: {triggers}\n{first_line}".strip()


def build_or_update_cache(skills: list, *, dimension: int | None = None,
                          identity: Mapping | None = None) -> dict[str, CachedEmbedding]:
    texts = {}
    mtimes = {}
    for s in skills:
        try:
            mtime = s.path.stat().st_mtime
        except (OSError, AttributeError):
            mtime = 0.0
        if s.name in texts:
            return {}  # ambiguous names must not choose an arbitrary vector
        texts[s.name] = _skill_to_embed_text(s)
        mtimes[s.name] = mtime
    return cached_corpus_vectors(texts, mtimes=mtimes, dimension=dimension, identity=identity) or {}


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    try:
        a, b = validate_vectors([a, b], 2)
    except (ValueError, TypeError):
        return 0.0
    # Scaling prevents finite but large provider values from overflowing norms.
    scale_a, scale_b = max(map(abs, a)), max(map(abs, b))
    a = [value / scale_a for value in a]
    b = [value / scale_b for value in b]
    dot = math.fsum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(math.fsum(x * x for x in a))
    nb = math.sqrt(math.fsum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def relevant_skills_embed(
    goal: str, all_skills: list, max_n: int = 3, threshold: float = 0.35,
) -> list | None:
    if not _have_fastembed():
        return None
    if not all_skills:
        return []

    if not isinstance(goal, str) or len(goal) > _MAX_TEXT:
        return None
    identity = embedding_identity()
    try:
        goal_vec = validate_vectors(embed([goal]), 1)[0]
        cache = build_or_update_cache(all_skills, dimension=len(goal_vec), identity=identity)
    except Exception:
        return None
    if len(cache) != len(all_skills) or embedding_identity() != identity:
        return None

    by_name = {s.name: s for s in all_skills}
    # Fold each skill's past-run track record into the ranking BEFORE the
    # top-N cut (see skills._decay_weights / skill_stats), so a skill that
    # rides along with failures yields rank. Threshold still gates on raw
    # relevance — decay only re-orders skills that already cleared it, never
    # pulls in an irrelevant one. Neutral 1.0 when stats are unavailable.
    from ..skills import _decay_weights
    weights = _decay_weights(list(by_name))
    scored: list[tuple[float, object]] = []
    for name, entry in cache.items():
        if name not in by_name:
            continue
        score = _cosine(goal_vec, entry.vector)
        if score >= threshold:
            scored.append((score * weights.get(name, 1.0), by_name[name]))
    # Deterministic tie-break by name, like the BM25 path (skill_search.py): a
    # bare score sort leaves equal-scored skills in cache-insertion order, which
    # shifts across cache rebuilds and can flip which skills land inside max_n.
    scored.sort(key=lambda x: (-x[0], x[1].name))
    return [s for _, s in scored[:max_n]]
